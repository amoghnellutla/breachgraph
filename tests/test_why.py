"""`why` names the step that decides whether a finding is on an attack path."""

import json
from pathlib import Path

from typer.testing import CliRunner

from breachgraph.cli import app
from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.why import explain
from breachgraph.models import Category, Package, ScanResult, Status
from tests.test_callgraph import JEWEL, cmd_injection, deployed, python_app
from tests.test_entry_points import write

runner = CliRunner()


def why(root: Path, finding, config: Config = JEWEL) -> str:  # type: ignore[no-untyped-def]
    return " ".join(explain(finding, build_attack_graph(root, [finding], config)))


def test_on_a_path(tmp_path: Path) -> None:
    python_app(tmp_path)
    assert why(tmp_path, cmd_injection("api/services/shell.py", 4)).startswith("On 1 attack path(s)")


def test_suppressed(tmp_path: Path) -> None:
    deployed(tmp_path)
    f = cmd_injection("api/x.py", 1)
    f.status = Status.SUPPRESSED
    assert "suppressed" in why(tmp_path, f)


def test_a_kind_that_opens_nothing(tmp_path: Path) -> None:
    f = cmd_injection("a.py", 1)
    f.cwe = ["CWE-327"]
    f.rule_id = "weak-hash"
    assert "doesn't give an attacker a step" in why(tmp_path, f)


def test_an_unused_dependency(tmp_path: Path) -> None:
    f = cmd_injection("requirements.txt", 1)
    f.category = Category.SCA
    f.package = Package(name="x", reachability="unused")
    assert "imports this package" in why(tmp_path, f)


def test_test_code(tmp_path: Path) -> None:
    assert "test or example code" in why(tmp_path, cmd_injection("tests/a.py", 1))


def test_code_nothing_deploys(tmp_path: Path) -> None:
    write(tmp_path, "tools/a.py", "x = 1\n")
    assert "no deployed service" in why(tmp_path, cmd_injection("tools/a.py", 1))


def test_a_private_service(tmp_path: Path) -> None:
    python_app(tmp_path)
    text = (
        (tmp_path / "k8s/api.yaml")
        .read_text(encoding="utf-8")
        .replace("type: LoadBalancer", "type: ClusterIP")
    )
    write(tmp_path, "k8s/api.yaml", text)
    assert "isn't reachable from the internet" in why(tmp_path, cmd_injection("api/services/shell.py", 4))


def test_no_route_reaches_it(tmp_path: Path) -> None:
    python_app(tmp_path)
    assert "none of them was followed" in why(tmp_path, cmd_injection("api/services/runner.py", 8))


def test_nothing_valuable_beyond_it(tmp_path: Path) -> None:
    python_app(tmp_path)
    assert "doesn't lead to a high-value asset" in why(
        tmp_path, cmd_injection("api/services/shell.py", 4), Config()
    )


def test_the_command(tmp_path: Path) -> None:
    python_app(tmp_path)
    f = cmd_injection("api/services/shell.py", 4)
    report = tmp_path / "r.json"
    report.write_text(
        ScanResult(breachgraph_version="1", target=".", findings=[f]).model_dump_json(), "utf-8"
    )
    res = runner.invoke(app, ["why", "api/services/shell.py:4", str(tmp_path), "-r", str(report)])
    assert res.exit_code == 0 and "Command injection" in res.output
    res = runner.invoke(app, ["why", "api/nothing.py", str(tmp_path), "-r", str(report)])
    assert res.exit_code == 1 and json.dumps("x")
