"""End-to-end CLI tests using --import, so they run without scanners installed."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from breachgraph.cli import app
from tests.conftest import FIXTURES

DEMO = Path(__file__).parent.parent / "examples" / "vulnerable-app"
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
            "zap",
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
