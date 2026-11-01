"""A weakness in a helper the handler calls is on the route; one nothing calls is not."""

from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.callgraph import CallGraph
from breachgraph.graph.model import Confidence as PathConfidence
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from tests.test_entry_points import write

K8S = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: shop/api:1
          volumeMounts:
            - {name: creds, mountPath: /etc/creds}
      volumes:
        - name: creds
          secret: {secretName: prod-db-password}
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: LoadBalancer
  selector: {app: api}
  ports: [{port: 80}]
"""


JEWEL = Config.model_validate({"attack_graph": {"crown_jewels": [{"match": "prod-db", "value": 9}]}})


def deployed(root: Path) -> None:
    write(root, "k8s/api.yaml", K8S)
    write(root, "api/Dockerfile", "FROM python:3.12\n")


def cmd_injection(path: str, line: int) -> Finding:
    return Finding(
        tool="semgrep",
        rule_id="command-injection",
        title="Command injection",
        severity=Severity.HIGH,
        category=Category.SAST,
        confidence=Confidence.HIGH,
        cwe=["CWE-78"],
        location=Location(path=path, start_line=line),
        fingerprint=f"{path}:{line}",
    )


def route_weak(res, label: str):  # type: ignore[no-untyped-def]
    nodes = [n for n in res.graph.nodes.values() if n.id.startswith("route:") and n.name == label]
    assert nodes, [n.name for n in res.graph.nodes.values() if n.id.startswith("route:")]
    return [w for n in nodes for w in n.weaknesses]


PY_HANDLER = """from flask import Flask, request
from api.services.runner import execute

app = Flask(__name__)

@app.get("/run")
def run_it():
    return execute(request.args["c"])

@app.get("/health")
def health():
    return "ok"
"""
PY_SERVICE = """import subprocess
from .shell import spawn

def execute(cmd):
    return spawn(cmd)

def never_called(cmd):
    return subprocess.run(cmd, shell=True)
"""
PY_SHELL = """import subprocess

def spawn(cmd):
    return subprocess.run(cmd, shell=True)
"""


def python_app(root: Path) -> None:
    deployed(root)
    write(root, "api/app.py", PY_HANDLER)
    write(root, "api/services/runner.py", PY_SERVICE)
    write(root, "api/services/shell.py", PY_SHELL)


def test_weakness_two_calls_away_makes_a_path(tmp_path: Path) -> None:
    python_app(tmp_path)
    res = build_attack_graph(tmp_path, [cmd_injection("api/services/shell.py", 4)], JEWEL)
    [weak] = route_weak(res, "GET /run")
    assert weak.confidence is PathConfidence.MEDIUM
    assert weak.evidence.detail == "command-injection, reached from the handler by run_it -> execute -> spawn"
    assert route_weak(res, "GET /health") == []  # the other route doesn't reach it
    [path] = [p for p in res.paths if "prod-db-password" in p.target.name]
    assert path.confidence is PathConfidence.MEDIUM


def test_a_function_nothing_calls_is_not_on_a_route(tmp_path: Path) -> None:
    python_app(tmp_path)
    res = build_attack_graph(tmp_path, [cmd_injection("api/services/runner.py", 8)], Config())
    assert route_weak(res, "GET /run") == []


def test_a_weakness_in_the_handler_stays_high_confidence(tmp_path: Path) -> None:
    python_app(tmp_path)
    res = build_attack_graph(tmp_path, [cmd_injection("api/app.py", 8)], Config())
    [weak] = route_weak(res, "GET /run")
    assert weak.confidence is PathConfidence.HIGH


def test_a_same_named_function_in_an_unrelated_file_is_not_followed(tmp_path: Path) -> None:
    python_app(tmp_path)
    write(tmp_path, "api/other/jobs.py", "import os\n\ndef spawn(c):\n    os.system(c)\n")
    res = build_attack_graph(tmp_path, [cmd_injection("api/other/jobs.py", 4)], Config())
    assert route_weak(res, "GET /run") == []


def test_tests_are_not_linked(tmp_path: Path) -> None:
    python_app(tmp_path)
    write(tmp_path, "api/services/shell_test.py", "def spawn(c):\n    pass\n")
    graph = CallGraph(tmp_path, [])
    assert graph.chain_to("api/app.py", 6, 8, "api/services/shell.py", 4) == ["execute", "spawn"]


def test_a_route_registered_inside_a_function_does_not_inherit_its_calls(tmp_path: Path) -> None:
    deployed(tmp_path)
    write(
        tmp_path,
        "api/server.js",
        """const bad = require('./bad')
const metrics = require('./metrics')

function start(app) {
  bad.danger()
  app.get('/metrics', metrics.serve)
}
""",
    )
    write(tmp_path, "api/bad.js", "exports.danger = function danger(x) {\n  eval(x)\n}\n")
    write(tmp_path, "api/metrics.js", "exports.serve = function serve(req, res) {\n  res.end(1)\n}\n")
    res = build_attack_graph(tmp_path, [cmd_injection("api/bad.js", 2)], Config())
    assert route_weak(res, "GET /metrics") == []


JS = {
    "api/routes/run.ts": """import { Router } from 'express'
import * as controller from '../controllers/run'

const router = Router()
router.post('/run', controller.handle)
export default router
""",
    "api/controllers/run.ts": """import { spawnIt } from '@/lib/shell'

export const handle = async (req, res) => {
  res.json(await spawnIt(req.body.cmd))
}
""",
    "api/lib/shell.ts": """import { exec } from 'child_process'

export function spawnIt(cmd: string) {
  return exec(cmd)
}
""",
}
GO = {
    "api/main.go": """package main

import (
	"github.com/gin-gonic/gin"
	"example.com/shop/api/internal/runner"
)

func main() {
	r := gin.Default()
	r.GET("/run", func(c *gin.Context) {
		runner.Execute(c.Query("c"))
	})
}
""",
    "api/internal/runner/run.go": """package runner

import "os/exec"

func Execute(cmd string) {
	spawn(cmd)
}

func spawn(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}
""",
}
JAVA = {
    "api/src/main/java/shop/web/RunController.java": """package shop.web;

import org.springframework.web.bind.annotation.*;
import shop.core.Runner;

@RestController
public class RunController {
    private final Runner runner = new Runner();

    @GetMapping("/run")
    public String run(@RequestParam String c) {
        return runner.execute(c);
    }
}
""",
    "api/src/main/java/shop/core/Runner.java": """package shop.core;

public class Runner {
    public String execute(String c) {
        return spawn(c);
    }

    private String spawn(String c) {
        return Runtime.getRuntime().exec(c).toString();
    }
}
""",
}


@pytest.mark.parametrize(
    ("files", "sink", "line", "label", "chain_end"),
    [
        (JS, "api/lib/shell.ts", 4, "POST /run", "spawnIt"),
        (GO, "api/internal/runner/run.go", 10, "GET /run", "spawn"),
        (JAVA, "api/src/main/java/shop/core/Runner.java", 9, "GET /run", "spawn"),
    ],
)
def test_other_languages(
    tmp_path: Path, files: dict[str, str], sink: str, line: int, label: str, chain_end: str
) -> None:
    deployed(tmp_path)
    for rel, text in files.items():
        write(tmp_path, rel, text)
    res = build_attack_graph(tmp_path, [cmd_injection(sink, line)], JEWEL)
    [weak] = route_weak(res, label)
    assert (weak.evidence.detail or "").endswith(chain_end)
    assert any("prod-db-password" in p.target.name for p in res.paths)


CAPTCHA = """exports.captcha = function captcha() {
  const first = Math.floor(Math.random() * 10)
  const second = 4
  const expression = first.toString() + '+' + second.toString()
  return eval(expression)
}
"""


@pytest.mark.parametrize(
    ("code", "line", "constant"),
    [
        (CAPTCHA, 5, True),
        ("function f(cmd) {\n  return eval(cmd)\n}\n", 2, False),  # a parameter
        ("function f(cmd) {\n  const c = 'x' + cmd\n  return eval(c)\n}\n", 3, False),  # through a local
        ("function f() {\n  return eval(req.body.code)\n}\n", 2, False),  # the request
        ("function f() {\n  return eval(SETTING)\n}\n", 2, True),  # a Capitalized constant
        ("function f() {\n  return eval(setting)\n}\n", 2, False),  # a variable defined elsewhere
        ("const x = 1\nmodule.exports = eval(x)\n", 2, False),  # no enclosing function: no opinion
    ],
)
def test_constant_input(tmp_path: Path, code: str, line: int, constant: bool) -> None:
    write(tmp_path, "a.js", code)
    assert CallGraph(tmp_path, []).constant_input("a.js", line, "detect-eval") is constant


def test_a_rule_that_traced_the_data_is_trusted(tmp_path: Path) -> None:
    write(tmp_path, "a.js", CAPTCHA)
    assert not CallGraph(tmp_path, []).constant_input("a.js", 5, "express-tainted-eval")


def test_a_constant_sink_is_reported_without_gating(tmp_path: Path) -> None:
    deployed(tmp_path)
    write(tmp_path, "api/server.js", "const c = require('./captcha')\napp.get('/captcha', c.captcha)\n")
    write(tmp_path, "api/captcha.js", CAPTCHA)
    res = build_attack_graph(tmp_path, [cmd_injection("api/captcha.js", 5)], JEWEL)
    [weak] = route_weak(res, "GET /captcha")
    assert weak.confidence is PathConfidence.LOW
    assert {p.confidence for p in res.paths} == {PathConfidence.LOW}
