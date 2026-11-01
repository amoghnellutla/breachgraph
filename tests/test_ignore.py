"""`breachgraph ignore`: one command, a reason, an expiry, and the config's comments intact."""

from datetime import date
from pathlib import Path

import yaml
from typer.testing import CliRunner

from breachgraph.cli import app
from breachgraph.config import Suppression, load_config
from breachgraph.models import ScanResult
from breachgraph.policy import add_suppression
from tests.test_callgraph import cmd_injection

runner = CliRunner()
ENTRY = Suppression(fingerprint="abc", reason="Parser isn't reachable: see SEC-1", expires=date(2027, 1, 1))


def entries(text: str) -> list[dict[str, object]]:
    return yaml.safe_load(text)["suppressions"]


def test_a_new_section_keeps_what_is_there() -> None:
    text = add_suppression("version: 1\n# keep me\nfail_on:\n  priority: P1\n", ENTRY)
    assert "# keep me" in text and entries(text)[0]["fingerprint"] == "abc"


def test_it_joins_an_existing_list() -> None:
    old = "version: 1\nsuppressions:  # accepted risks\n  - vuln: CVE-1\n    reason: x\n    expires: 2027-02-02\nfail_on:\n  priority: P1\n"
    text = add_suppression(old, ENTRY)
    assert [e.get("fingerprint") or e.get("vuln") for e in entries(text)] == ["abc", "CVE-1"]
    assert yaml.safe_load(text)["fail_on"] == {"priority": "P1"}


def test_an_empty_list_is_filled() -> None:
    assert len(entries(add_suppression("version: 1\nsuppressions: []\n", ENTRY))) == 1


def test_no_config_yet() -> None:
    assert yaml.safe_load(add_suppression("", ENTRY))["version"] == 1


def repo(tmp: Path) -> Path:
    report = tmp / "r.json"
    findings = [cmd_injection("a.py", 1), cmd_injection("a.py", 2)]
    report.write_text(
        ScanResult(breachgraph_version="1", target=".", findings=findings).model_dump_json(), "utf-8"
    )
    return report


def test_the_command(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "ignore",
            "a.py:1",
            str(tmp_path),
            "--reason",
            "only runs in CI",
            "-r",
            str(repo(tmp_path)),
            "--days",
            "30",
        ],
    )
    assert res.exit_code == 0, res.output
    [s] = load_config(tmp_path / ".breachgraph.yml").suppressions
    assert s.fingerprint == "a.py:1" and s.reason == "only runs in CI" and s.expires


def test_a_reason_is_required(tmp_path: Path) -> None:
    res = runner.invoke(app, ["ignore", "a.py:1", str(tmp_path), "--reason", "  ", "-r", str(repo(tmp_path))])
    assert res.exit_code == 2 and not (tmp_path / ".breachgraph.yml").exists()


def test_several_matches_are_refused(tmp_path: Path) -> None:
    res = runner.invoke(app, ["ignore", "a.py", str(tmp_path), "--reason", "x", "-r", str(repo(tmp_path))])
    assert res.exit_code == 1 and "2 findings match" in res.output
