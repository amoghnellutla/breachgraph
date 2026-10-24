"""Import-level reachability: which dependency CVEs the code actually uses."""

from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.graph.sources.common import SourceContext
from breachgraph.models import Category, Finding, Location, Package, Reachability, Severity
from breachgraph.reachability import annotate_reachability
from breachgraph.reachability.imports import collect_imports

PLATFORM = Path(__file__).parent.parent / "examples" / "vulnerable-platform"


def dep(name: str, ecosystem: str = "pip", path: str = "services/api/requirements.txt") -> Finding:
    return Finding(
        tool="trivy",
        rule_id=f"CVE-{name}",
        title=f"{name} CVE",
        severity=Severity.HIGH,
        category=Category.SCA,
        location=Location(path=path),
        vuln_ids=[f"CVE-{name}"],
        package=Package(name=name, version="1.0", ecosystem=ecosystem),
    )


def reach(findings: list[Finding], target: Path = PLATFORM) -> dict[str, str]:
    annotate_reachability(target, findings, Config())
    return {f.package.name: f.package.reachability.value for f in findings if f.package}


def test_imported_package_is_entrypoint_reachable() -> None:
    # app.py imports flask and requests, and defines routes -> reachable from an entry point.
    r = reach([dep("flask"), dep("requests")])
    assert r == {"flask": "entrypoint", "requests": "entrypoint"}


def test_transitive_unused_package() -> None:
    r = reach([dep("jinja2"), dep("PyYAML")])
    assert r == {"jinja2": "unused", "PyYAML": "unused"}


def test_pypi_import_alias() -> None:
    # PyYAML -> import yaml. Create a file that imports yaml (not reachable from a route).
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "util.py").write_text("import yaml\n", encoding="utf-8")
        r = reach([dep("PyYAML")], target=root)
    assert r == {"PyYAML": "direct"}  # used, but no route traces to it


def test_unknown_ecosystem() -> None:
    r = reach([dep("some-gem", ecosystem="gem")])
    assert r == {"some-gem": "unknown"}


def test_no_source_files_is_unknown(tmp_path: Path) -> None:
    (tmp_path / "data.txt").write_text("nothing", encoding="utf-8")
    r = reach([dep("flask")], target=tmp_path)
    assert r == {"flask": "unknown"}


def test_go_module_path_matching(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\nimport "github.com/gin-gonic/gin"\nfunc main() { gin.Default() }\n',
        encoding="utf-8",
    )
    r = reach([dep("github.com/gin-gonic/gin", ecosystem="gomod")], target=tmp_path)
    assert r["github.com/gin-gonic/gin"] == "direct"


def test_java_group_id_matching(tmp_path: Path) -> None:
    (tmp_path / "A.java").write_text(
        "import com.fasterxml.jackson.databind.ObjectMapper;\nclass A {}\n", encoding="utf-8"
    )
    r = reach([dep("com.fasterxml.jackson.core:jackson-databind", ecosystem="pom")], target=tmp_path)
    assert r["com.fasterxml.jackson.core:jackson-databind"] == "direct"


def test_collect_imports_python(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import os\nfrom flask import Flask\nfrom .helper import foo\n", encoding="utf-8"
    )
    idx = collect_imports(SourceContext(root=tmp_path, exclude=[]))
    fi = idx.files["a.py"]
    assert "flask" in fi.externals and "os" in fi.externals
    assert any("helper" in loc for loc in fi.local)


def test_no_deps_returns_empty() -> None:
    assert annotate_reachability(PLATFORM, [], Config()) == {}


@pytest.mark.parametrize("eco", ["npm", "yarn"])
def test_npm_package(tmp_path: Path, eco: str) -> None:
    (tmp_path / "app.js").write_text("const express = require('express');\n", encoding="utf-8")
    r = reach([dep("express", ecosystem=eco)], target=tmp_path)
    assert r["express"] == "direct"


def test_unused_kev_cve_does_not_gate() -> None:
    from breachgraph.models import ScanResult
    from breachgraph.policy import evaluate_gate

    f = dep("jinja2")
    f.enrichment.kev = True
    f.package.reachability = Reachability.UNUSED
    result = ScanResult(breachgraph_version="t", target=".", findings=[f])
    # Default gate_on_unused=false: a KEV CVE in an unused package does not fail the gate.
    assert evaluate_gate(result, Config()).passed
    cfg = Config.model_validate({"reachability": {"gate_on_unused": True}})
    assert not evaluate_gate(result, cfg).passed


def test_pipeline_deprioritizes_unused_dep() -> None:

    from breachgraph.models import ToolRun, ToolStatus
    from breachgraph.pipeline import ScanOptions, process

    used, unused = dep("flask"), dep("jinja2")
    for f in (used, unused):
        f.cvss = 9.8
    res = process(
        [used, unused],
        [ToolRun(name="trivy", status=ToolStatus.IMPORTED, findings=2)],
        Config(),
        PLATFORM,
        ScanOptions(offline=True),
    )
    by_name = {f.package.name: f for f in res.findings if f.package}
    assert by_name["jinja2"].package.reachability is Reachability.UNUSED
    assert by_name["jinja2"].risk_score < by_name["flask"].risk_score
    assert any("not imported" in r for r in by_name["jinja2"].score_reasons)
