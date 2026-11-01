"""Routes behind a login are labelled and rank lower; they are never dropped."""

from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.sources.auth import annotate
from breachgraph.graph.sources.routes import routes_in_file
from tests.test_callgraph import JEWEL, cmd_injection, deployed
from tests.test_entry_points import write


def guards(tmp: Path, name: str, code: str) -> dict[str, str]:
    path = write_file(tmp, name, code)
    routes = routes_in_file(path, name)
    annotate(routes, code)
    return {r.path: r.auth for r in routes}


def write_file(tmp: Path, name: str, code: str) -> Path:
    write(tmp, name, code)
    return tmp / name


FLASK = """from flask import Flask
from flask_login import login_required
app = Flask(__name__)

@app.get("/open")
def open_route():
    return "login_required is only a word here"

@app.get("/account")
@login_required
def account():
    return "x"
"""
FASTAPI = """from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/open")
def open_route(q: str):
    return q

@router.get("/me")
def me(user=Depends(get_current_user)):
    return user
"""
EXPRESS = """const router = require('express').Router()
router.get('/auth/login', (req, res) => res.end())
router.get('/me', requireAuth, (req, res) => res.end())
router.get('/you', auth, handler)
router.get('/inline', (req, res) => { isAuthenticated(req); res.end() })
"""
EXPRESS_USE = """const app = express()
app.get('/before', handler)
app.use(passport.authenticate('jwt'))
app.get('/after', handler)
app.use('/api/users/:id', security.isAuthorized())
app.get('/api/users/7', handler)
"""
NEST = """@UseGuards(JwtAuthGuard)
@Controller('cats')
export class CatsController {
  @Get('all')
  all() { return [] }
}
"""
SPRING = """import org.springframework.web.bind.annotation.*;

@RestController
public class C {
    @GetMapping("/open")
    public String open() { return ""; }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String admin() { return ""; }

    @PreAuthorize("permitAll()")
    @GetMapping("/public")
    public String pub() { return ""; }
}
"""
GIN = """package main

func main() {
	r := gin.Default()
	r.GET("/open", h)
	admin := r.Group("/admin", AuthRequired())
	admin.GET("/users", h)
	api := r.Group("/api")
	api.Use(JWTAuthMiddleware())
	api.GET("/me", h)
}
"""


@pytest.mark.parametrize(
    ("name", "code", "expected"),
    [
        ("a.py", FLASK, {"/open": "", "/account": "login_required"}),
        ("b.py", FASTAPI, {"/open": "", "/me": "get_current_user"}),
        ("c.js", EXPRESS, {"/auth/login": "", "/me": "requireAuth", "/you": "auth", "/inline": ""}),
        (
            "d.js",
            EXPRESS_USE,
            {"/before": "", "/after": "authenticate", "/api/users/7": "authenticate"},
        ),
        ("e.ts", NEST, {"/cats/all": "UseGuards"}),
        ("F.java", SPRING, {"/open": "", "/admin": "PreAuthorize", "/public": ""}),
        ("g.go", GIN, {"/open": "", "/users": "AuthRequired", "/me": "JWTAuth"}),
    ],
)
def test_guards_by_framework(tmp_path: Path, name: str, code: str, expected: dict[str, str]) -> None:
    found = guards(tmp_path, name, code)
    for route, guard in expected.items():
        if route in found:
            assert found[route].lower().startswith(guard.lower()), route
    assert set(found) & set(expected)


APP = """from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.get("/open")
def open_route():
    return subprocess.run(request.args["c"], shell=True)

@app.get("/me")
@login_required
def me():
    return subprocess.run(request.args["c"], shell=True)
"""


def test_a_guarded_path_is_labelled_and_ranks_below_an_open_one(tmp_path: Path) -> None:
    deployed(tmp_path)
    write(tmp_path, "api/app.py", APP)
    findings = [cmd_injection("api/app.py", 7), cmd_injection("api/app.py", 12)]
    res = build_attack_graph(tmp_path, findings, JEWEL)
    by_login = {p.needs_login: p for p in res.paths}
    assert set(by_login) == {"", "login_required"}
    assert by_login["login_required"].score < by_login[""].score
    assert res.paths[0].needs_login == ""


def test_an_auth_bypass_on_the_route_removes_the_label(tmp_path: Path) -> None:
    deployed(tmp_path)
    write(tmp_path, "api/app.py", APP)
    bypass = cmd_injection("api/app.py", 11)
    bypass.cwe = ["CWE-287"]
    bypass.fingerprint = "bypass"
    res = build_attack_graph(tmp_path, [cmd_injection("api/app.py", 12), bypass], JEWEL)
    assert res.paths
    assert all(p.needs_login == "" for p in res.paths)


def test_a_config_without_findings_has_no_paths(tmp_path: Path) -> None:
    deployed(tmp_path)
    write(tmp_path, "api/app.py", APP)
    assert not build_attack_graph(tmp_path, [], Config()).paths
