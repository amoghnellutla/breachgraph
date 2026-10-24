from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from breachgraph.models import Category, Finding, Location, Package, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def make_finding(**kw: Any) -> Finding:
    loc = kw.pop("location", None) or Location(
        path=kw.pop("path", "app.py"),
        start_line=kw.pop("line", 10),
        end_line=kw.pop("end_line", None),
        snippet=kw.pop("snippet", "do_something(user_input)"),
        in_repo=kw.pop("in_repo", True),
    )
    defaults: dict[str, Any] = {
        "tool": "semgrep",
        "rule_id": "rule.one",
        "title": "Something bad",
        "severity": Severity.HIGH,
        "category": Category.SAST,
        "location": loc,
    }
    defaults.update(kw)
    return Finding(**defaults)


def make_vuln(cve: str = "CVE-2021-44228", pkg: str = "log4j-core", **kw: Any) -> Finding:
    return make_finding(
        tool=kw.pop("tool", "trivy"),
        rule_id=cve,
        title=f"{cve} in {pkg}",
        category=Category.SCA,
        vuln_ids=[cve],
        package=Package(name=pkg, version="2.14.1", fixed_version="2.15.0"),
        path=kw.pop("path", "pom.xml"),
        line=None,
        snippet=None,
        **kw,
    )


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BREACHGRAPH_CACHE_DIR", str(tmp_path / "cache"))
    for var in ("GITHUB_ACTIONS", "GITHUB_TOKEN", "GITHUB_STEP_SUMMARY", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(var, raising=False)
