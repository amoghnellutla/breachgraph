"""Implicit crown jewels for application repositories: the database the code talks to."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from tests.test_entry_points import write
from tests.test_graph_paths import finding

FLASK = """from flask import Flask, request
from sqlalchemy import text, create_engine

app = Flask(__name__)
db = create_engine("postgresql://localhost/app")

@app.route("/search")
def search():
    q = request.args["q"]
    return str(db.execute(text("SELECT * FROM items WHERE name = '" + q + "'")).all())
"""
SQLI = finding("app.py", 10, "CWE-89", "SQL injection", "sqli")


def paths(tmp: Path, findings=()) -> list[list[str]]:  # type: ignore[no-untyped-def]
    return [p.nodes for p in build_attack_graph(tmp, list(findings), Config()).paths]


def test_route_injection_reaches_the_application_database(tmp_path: Path) -> None:
    write(tmp_path, "app.py", FLASK)
    graph = build_attack_graph(tmp_path, [SQLI], Config()).graph
    db = graph.nodes["app:database:sqlalchemy"]
    assert db.attrs["implicit"] and db.evidence[0].path == "app.py"
    found = paths(tmp_path, [SQLI])
    assert found and found[0][0] == "internet" and found[0][-1] == "app:database:sqlalchemy"
    assert "app:application" in found[0]
    assert paths(tmp_path) == []  # no weakness, no path


def test_connection_setting_alone_is_evidence(tmp_path: Path) -> None:
    write(tmp_path, "app.py", FLASK.replace("from sqlalchemy import text, create_engine\n", ""))
    write(tmp_path, ".env.example", "DATABASE_URL=postgres://localhost/app\n")
    graph = build_attack_graph(tmp_path, [], Config()).graph
    assert any(n.id.startswith("app:database:") for n in graph.nodes.values())


def test_infrastructure_database_is_not_shadowed(tmp_path: Path) -> None:
    write(tmp_path, "app.py", FLASK)
    write(tmp_path, "main.tf", 'resource "aws_db_instance" "main" {\n  engine = "postgres"\n}\n')
    graph = build_attack_graph(tmp_path, [], Config()).graph
    assert not any(n.id.startswith("app:database:") for n in graph.nodes.values())


COMPOSE = """services:
  proxy:
    image: nginx:1.27-alpine
    ports: ["80:80"]
    depends_on: [web]
  web:
    build: ./web
    expose: ["3000"]
  worker:
    build: ./worker
"""
WEB = """const express = require("express");
const { Sequelize } = require("sequelize");
const app = express();
const handler = require("./search");
app.get("/search", handler);
"""


def test_compose_service_behind_a_proxy_is_exposed(tmp_path: Path) -> None:
    write(tmp_path, "docker-compose.yml", COMPOSE)
    write(tmp_path, "web/Dockerfile", "FROM node\n")
    write(tmp_path, "web/server.js", WEB)
    write(tmp_path, "web/search.js", "module.exports = (req, res) => db.query(req.query.q);\n")
    write(tmp_path, "worker/Dockerfile", "FROM node\n")
    sqli = finding("web/search.js", 1, "CWE-89", "SQL injection", "sqli")
    found = paths(tmp_path, [sqli])
    assert ["internet", "compose:service:web", "app:database:sequelize"] in found
    graph = build_attack_graph(tmp_path, [sqli], Config()).graph
    exposed = {e.dst for e in graph.edges if e.src == "internet"}
    assert "compose:service:web" in exposed and "compose:service:worker" not in exposed


def test_ci_config_and_samples_do_not_arm_the_service(tmp_path: Path) -> None:
    """A workflow injection is not code execution in the app; a test snippet is weaker evidence."""
    write(tmp_path, "docker-compose.yml", "services:\n  web:\n    build: .\n    ports: ['8080:80']\n")
    write(tmp_path, "Dockerfile", "FROM node\n")
    write(tmp_path, "server.js", WEB)
    write(tmp_path, ".github/workflows/ci.yml", "on: push\njobs: {}\n")
    gha = finding(".github/workflows/ci.yml", 1, "CWE-78", "Workflow injection", "gha")
    assert paths(tmp_path, [gha]) == []
    fixture = finding("test/fixtures/q.js", 1, "CWE-89", "SQL injection in a fixture", "fx")
    assert paths(tmp_path, [fixture]) == []
    snippet = finding("static/snippets/q.js", 1, "CWE-89", "SQL injection in a snippet", "sn")
    real = finding("lib/db.js", 3, "CWE-89", "SQL injection", "real")
    res = build_attack_graph(tmp_path, [snippet, real], Config())
    assert res.paths[0].steps[-1].weakness_title == "SQL injection"
