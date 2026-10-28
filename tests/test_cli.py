"""End-to-end CLI tests using --import, so they run without scanners installed."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from breachgraph.cli import app
from tests.conftest import FIXTURES

DEMO = Path(__file__).parent.parent / "examples" / "vulnerable-app"
PLATFORM_DIR = Path(__file__).parent.parent / "examples" / "vulnerable-platform"
runner = CliRunner()


def imports() -> list[str]:
    args: list[str] = []
    for tool, fixture in [
        ("semgrep", "semgrep.json"),
        ("gitleaks", "gitleaks.json"),
        ("trivy", "trivy.json"),
        ("checkov", "checkov.json"),
    ]:
        args += ["--import", f"{tool}={FIXTURES / fixture}"]
    return args


def scan(tmp_path: Path, *extra: str):  # type: ignore[no-untyped-def]
    return runner.invoke(
        app,
        [
            "scan",
            str(DEMO),
            "-o",
            str(tmp_path / "out"),
            "--offline",
            "--skip",
            "zizmor",
            "--skip",
            "cicd",
            *imports(),
            *extra,
        ],
    )


def test_scan_fails_gate_and_writes_reports(tmp_path: Path) -> None:
    res = scan(tmp_path, "-f", "json,sarif,html,md,junit")
    assert res.exit_code == 1, res.output
    out = tmp_path / "out"
    for name in [
        "breachgraph.json",
        "breachgraph.sarif",
        "breachgraph.html",
        "breachgraph.md",
        "breachgraph-junit.xml",
    ]:
        assert (out / name).is_file(), name
    data = json.loads((out / "breachgraph.json").read_text(encoding="utf-8"))
    assert not data["gate"]["passed"]
    assert {t["status"] for t in data["tools"]} == {"imported"}


def test_no_fail_and_fail_on_none(tmp_path: Path) -> None:
    assert scan(tmp_path, "--no-fail").exit_code == 0


def test_baseline_roundtrip(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    res = scan(tmp_path, "--write-baseline", str(baseline))
    assert res.exit_code == 0, res.output
    assert json.loads(baseline.read_text(encoding="utf-8"))["findings"]
    res = scan(tmp_path, "--baseline", str(baseline))
    assert res.exit_code == 0, res.output  # everything is accepted -> nothing new
    data = json.loads((tmp_path / "out" / "breachgraph.json").read_text(encoding="utf-8"))
    assert data["baseline_used"]
    assert {f["status"] for f in data["findings"]} == {"baseline"}


def test_bad_config_exits_2(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.yml"
    cfg.write_text("fail_on: {priority: P9}\n", encoding="utf-8")
    assert scan(tmp_path, "-c", str(cfg)).exit_code == 2


def test_unknown_scanner_exits_2(tmp_path: Path) -> None:
    assert scan(tmp_path, "--only", "nessus").exit_code == 2


def test_report_rerender(tmp_path: Path) -> None:
    scan(tmp_path, "-f", "json")
    res = runner.invoke(
        app,
        [
            "report",
            str(tmp_path / "out" / "breachgraph.json"),
            "-o",
            str(tmp_path / "re"),
            "-f",
            "html",
        ],
    )
    assert res.exit_code == 0, res.output
    assert (tmp_path / "re" / "breachgraph.html").is_file()


def test_init(tmp_path: Path) -> None:
    res = runner.invoke(app, ["init", str(tmp_path)])
    assert res.exit_code == 0
    assert (tmp_path / ".breachgraph.yml").is_file()
    assert (tmp_path / ".github" / "workflows" / "breachgraph.yml").is_file()
    from breachgraph.config import load_config

    load_config(tmp_path / ".breachgraph.yml")  # the starter config must be valid
    assert "What breachgraph sees here" in res.output and "0 HTTP routes" in res.output
    assert (
        "persist-credentials: false" in (tmp_path / ".github" / "workflows" / "breachgraph.yml").read_text()
    )


def test_init_describes_the_repository(tmp_path: Path) -> None:
    shutil.copytree(Path(__file__).parent.parent / "examples" / "vulnerable-platform", tmp_path / "repo")
    (tmp_path / "repo" / ".breachgraph.yml").unlink(missing_ok=True)
    res = runner.invoke(app, ["init", str(tmp_path / "repo"), "--no-workflow"])
    assert res.exit_code == 0
    assert "3 HTTP routes" in res.output and "S3 bucket shop-customer-data-prod" in res.output
    assert "add 'cluster' to attack_graph.entry_points" in res.output


def test_init_points_at_per_environment_helm_values(tmp_path: Path) -> None:
    chart = tmp_path / "deploy" / "shop"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: shop\nversion: 0.1.0\n", encoding="utf-8")
    for name in ("values.yaml", "values-prod.yaml", "values.schema.json"):
        (chart / name).write_text("{}\n", encoding="utf-8")
    res = runner.invoke(app, ["init", str(tmp_path), "--no-workflow"], terminal_width=300)
    assert res.exit_code == 0
    assert "set attack_graph.helm_values: {deploy/shop: [deploy/shop/values-prod.yaml]}" in res.output


def test_version() -> None:
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0 and "breachgraph" in res.output


def test_report_rejects_foreign_json(tmp_path: Path) -> None:
    bad = tmp_path / "x.json"
    bad.write_text('{"hello": 1}', encoding="utf-8")
    res = runner.invoke(app, ["report", str(bad), "-o", str(tmp_path / "o")])
    assert res.exit_code == 2


PLATFORM = Path(__file__).parent.parent / "examples" / "vulnerable-platform"


def test_graph_command_infra_only(tmp_path: Path) -> None:
    res = runner.invoke(app, ["graph", str(PLATFORM)])
    assert res.exit_code == 0  # no code vuln -> no path to S3


def test_graph_command_with_findings(tmp_path: Path) -> None:
    from breachgraph.models import Category, Confidence, Finding, Location, ScanResult, Severity

    fj = tmp_path / "f.json"
    r = ScanResult(
        breachgraph_version="t",
        target=".",
        findings=[
            Finding(
                tool="semgrep",
                rule_id="cmdi",
                title="Command injection",
                severity=Severity.HIGH,
                category=Category.SAST,
                confidence=Confidence.HIGH,
                cwe=["CWE-78"],
                location=Location(path="services/api/app.py", start_line=30),
                fingerprint="c1",
            ),
        ],
    )
    fj.write_text(r.model_dump_json(), encoding="utf-8")
    out = tmp_path / "graph.json"
    res = runner.invoke(app, ["graph", str(PLATFORM), "--findings", str(fj), "-o", str(out)])
    assert res.exit_code == 1  # gating attack path found
    assert out.is_file()
    assert "customer-data" in out.read_text(encoding="utf-8")


def test_console_output_escapes_untrusted_text(capsys: pytest.CaptureFixture[str]) -> None:
    from breachgraph.cli import _print_summary
    from breachgraph.models import (
        AIInsight,
        AIVerdict,
        Category,
        Finding,
        Location,
        ScanResult,
        Severity,
    )

    f = Finding(
        tool="semgrep",
        rule_id="r",
        title="Route [/admin] [bold]x",
        severity=Severity.HIGH,
        category=Category.SAST,
        location=Location(path="a[/b].py", start_line=1),
        ai=AIInsight(verdict=AIVerdict.NEEDS_REVIEW, summary="s", reasoning="r", remediation="f"),
    )
    result = ScanResult(breachgraph_version="t", target=".", findings=[f], warnings=["model said [/x]"])
    _print_summary(result)  # Rich would raise MarkupError on "[/admin]" if it were not escaped
    out = capsys.readouterr().err
    assert "[/admin]" in out and "needs review" in out and "[/x]" in out


def test_unwritable_output_fails_fast(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(DEMO), "-o", str(blocker / "out"), "--offline"])
    assert res.exit_code == 2 and "cannot write reports" in res.output
    assert "scanning" not in res.output  # failed before any scanner ran


def test_graph_without_findings_is_not_reassuring() -> None:
    res = runner.invoke(app, ["graph", str(PLATFORM_DIR)])
    assert "No attack path found, but the result is incomplete" in res.output
    assert "Infrastructure only" in res.output and "breachgraph scan" in res.output
    assert "[green]No attack path" not in res.output


def test_fix_scans_first_when_there_is_no_report(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(PLATFORM_DIR, repo)
    shutil.rmtree(repo / "breachgraph-report", ignore_errors=True)
    res = runner.invoke(app, ["fix", str(repo), "--offline"])
    assert res.exit_code == 0, res.output
    assert "No report yet, so scanning first" in res.output
    assert (repo / "breachgraph-report" / "breachgraph.json").is_file()


def test_missing_scanners_get_one_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))  # no scanner binaries
    res = runner.invoke(app, ["scan", str(PLATFORM_DIR), "-o", str(tmp_path / "o"), "--offline", "--no-fail"])
    assert res.exit_code == 0
    assert "scanner(s) not installed" in res.output and "ghcr.io/amoghnellutla/breachgraph" in res.output
