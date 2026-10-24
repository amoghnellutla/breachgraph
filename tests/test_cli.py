"""End-to-end CLI tests using --import, so they run without scanners installed."""

import json
from pathlib import Path

from typer.testing import CliRunner

from tests.conftest import FIXTURES
from triagegate.cli import app

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
        "triagegate.json",
        "triagegate.sarif",
        "triagegate.html",
        "triagegate.md",
        "triagegate-junit.xml",
    ]:
        assert (out / name).is_file(), name
    data = json.loads((out / "triagegate.json").read_text(encoding="utf-8"))
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
    data = json.loads((tmp_path / "out" / "triagegate.json").read_text(encoding="utf-8"))
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
            str(tmp_path / "out" / "triagegate.json"),
            "-o",
            str(tmp_path / "re"),
            "-f",
            "html",
        ],
    )
    assert res.exit_code == 0, res.output
    assert (tmp_path / "re" / "triagegate.html").is_file()


def test_init(tmp_path: Path) -> None:
    res = runner.invoke(app, ["init", str(tmp_path)])
    assert res.exit_code == 0
    assert (tmp_path / ".triagegate.yml").is_file()
    assert (tmp_path / ".github" / "workflows" / "triagegate.yml").is_file()
    from triagegate.config import load_config

    load_config(tmp_path / ".triagegate.yml")  # the starter config must be valid


def test_version() -> None:
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0 and "triagegate" in res.output


def test_report_rejects_foreign_json(tmp_path: Path) -> None:
    bad = tmp_path / "x.json"
    bad.write_text('{"hello": 1}', encoding="utf-8")
    res = runner.invoke(app, ["report", str(bad), "-o", str(tmp_path / "o")])
    assert res.exit_code == 2
