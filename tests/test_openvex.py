"""OpenVEX from reachability, and the dependency graph that makes "not affected" claims safe."""

import json

import jsonschema

from breachgraph.config import Config
from breachgraph.models import Package, Reachability, ScanResult
from breachgraph.reporters import openvex
from breachgraph.scanners import IMPORTERS
from breachgraph.scanners.base import ScanContext
from tests.conftest import FIXTURES
from tests.test_reachability import dep

SCHEMA = json.loads((FIXTURES / "openvex-schema.json").read_text(encoding="utf-8"))


def doc(*packages: tuple[str, Reachability | None], not_affected: bool = True) -> dict:  # type: ignore[type-arg]
    findings = []
    for name, reach in packages:
        f = dep(name)
        f.vuln_ids = [f"CVE-2024-{abs(hash(name)) % 10000:04d}", f"GHSA-{name}"]
        f.package = Package(
            name=name, version="1.0", ecosystem="pip", reachability=reach, fixed_version="2.0"
        )
        findings.append(f)
    result = ScanResult(breachgraph_version="0.2.0", target="/repo/shop", findings=findings)
    result.metadata["vex"] = {
        "author": "sec@example.com",
        "product": "pkg:github/acme/shop",
        "not_affected": not_affected,
    }
    return openvex.build(result)


def status(d: dict, name: str) -> dict:  # type: ignore[type-arg]
    return next(s for s in d["statements"] if f"/{name}@" in s["products"][0]["subcomponents"][0]["@id"])


def test_document_is_valid_openvex() -> None:
    d = doc(
        ("yaml-lib", Reachability.UNUSED), ("flask", Reachability.ENTRYPOINT), ("odd", Reachability.UNKNOWN)
    )
    jsonschema.validate(d, SCHEMA)
    assert d["@context"] == "https://openvex.dev/ns/v0.2.0" and d["author"] == "sec@example.com"


def test_statuses_follow_reachability() -> None:
    d = doc(("yaml-lib", Reachability.UNUSED), ("flask", Reachability.ENTRYPOINT), ("odd", None))
    unused, used, unknown = status(d, "yaml-lib"), status(d, "flask"), status(d, "odd")
    assert unused["status"] == "not_affected"
    assert unused["justification"] == "vulnerable_code_not_in_execute_path" and unused["impact_statement"]
    assert used["status"] == "affected" and "Upgrade flask to 2.0" in used["action_statement"]
    assert unknown["status"] == "under_investigation"
    assert used["products"][0]["@id"] == "pkg:github/acme/shop"
    assert used["vulnerability"]["aliases"] == ["GHSA-flask"]


def test_not_affected_can_be_disabled() -> None:
    d = doc(("yaml-lib", Reachability.UNUSED), not_affected=False)
    assert status(d, "yaml-lib")["status"] == "under_investigation"
    jsonschema.validate(d, SCHEMA)


def test_purl_from_trivy_and_fallback() -> None:
    f = dep("PyYAML")
    assert openvex.purl(f) == "pkg:pypi/pyyaml@1.0"
    assert f.package is not None
    f.package.purl = "pkg:pypi/pyyaml@1.0?extra=1"
    assert openvex.purl(f) == "pkg:pypi/pyyaml@1.0?extra=1"
    m = dep("org.apache.logging.log4j:log4j-core", ecosystem="pom")
    assert openvex.purl(m) == "pkg:maven/org.apache.logging.log4j/log4j-core@1.0"


def test_pipeline_writes_vex_settings() -> None:
    from breachgraph.models import ToolRun, ToolStatus
    from breachgraph.pipeline import ScanOptions, process
    from tests.test_reachability import PLATFORM

    res = process(
        [dep("flask")],
        [ToolRun(name="trivy", status=ToolStatus.IMPORTED)],
        Config(),
        PLATFORM,
        ScanOptions(offline=True),
    )
    d = openvex.build(res)
    jsonschema.validate(d, SCHEMA)
    # A plain requirements file has no root component: the package itself is the product.
    assert d["statements"][0]["products"] == [{"@id": "pkg:pypi/flask@1.0"}]


def test_root_component_scopes_the_statement() -> None:
    f = dep("jackson-core", ecosystem="pom")
    assert f.package is not None
    f.package.root_purl = "pkg:maven/acme/shop@1.0"
    result = ScanResult(breachgraph_version="0.2.0", target="/repo", findings=[f])
    products = openvex.build(result)["statements"][0]["products"]
    assert products == [
        {"@id": "pkg:maven/acme/shop@1.0", "subcomponents": [{"@id": "pkg:maven/jackson-core@1.0"}]}
    ]


def test_trivy_dependency_graph_from_lockfile_data(tmp_path) -> None:  # type: ignore[no-untyped-def]
    ctx = ScanContext(target=tmp_path, work_dir=tmp_path, config=Config())
    raw = json.loads((FIXTURES / "trivy.json").read_text(encoding="utf-8"))
    findings = IMPORTERS["trivy"].parse(raw, ctx)
    core = next(f for f in findings if f.package and f.package.name.endswith("jackson-core"))
    assert core.package is not None and core.package.dependency_graph
    assert core.package.dependents == [
        "com.fasterxml.jackson.core:jackson-databind"
    ]  # the project root excluded
    log4j = next(f for f in findings if f.rule_id == "CVE-2021-44228")
    assert (
        log4j.package is not None
        and log4j.package.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    )
    pip = [f for f in findings if f.location.path == "requirements.txt" and f.package]
    assert pip and not any(f.package.dependency_graph for f in pip if f.package)  # flat requirements file
