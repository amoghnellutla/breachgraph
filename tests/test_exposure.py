"""One bug away: what a single new weakness at an exposed entry would reach, and nothing more."""

from pathlib import Path

from breachgraph.compare import compare
from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.summary import summarize
from breachgraph.models import AttackGraphSummary, ExposureView, ScanResult
from breachgraph.reporters.markdown import render
from tests.test_callgraph import JEWEL, K8S, cmd_injection, deployed
from tests.test_entry_points import write

PLATFORM = Path(__file__).parent.parent / "examples" / "vulnerable-platform"


def exposures(res):  # type: ignore[no-untyped-def]
    return {(x.entry.name, x.target.name) for x in res.exposures}


def test_a_public_service_with_no_findings_is_one_bug_from_what_it_mounts(tmp_path: Path) -> None:
    deployed(tmp_path)
    res = build_attack_graph(tmp_path, [], JEWEL)
    assert not res.paths
    [x] = res.exposures
    assert "prod-db-password" in x.target.name and x.needs


def test_a_private_service_is_not_exposed(tmp_path: Path) -> None:
    write(tmp_path, "k8s/api.yaml", K8S.replace("type: LoadBalancer", "type: ClusterIP"))
    write(tmp_path, "api/Dockerfile", "FROM python:3.12\n")
    assert build_attack_graph(tmp_path, [], JEWEL).exposures == []


def test_a_real_path_is_not_repeated_as_advice(tmp_path: Path) -> None:
    deployed(tmp_path)
    write(
        tmp_path,
        "api/app.py",
        'from flask import Flask\napp = Flask(__name__)\n\n@app.get("/x")\ndef x():\n    pass\n',
    )
    res = build_attack_graph(tmp_path, [cmd_injection("api/app.py", 6)], JEWEL)
    assert res.paths and res.exposures == []


def test_two_imagined_bugs_are_never_assumed() -> None:
    """The demo's bucket sits behind the SSRF route. With no findings, every step past the entry
    must already be possible for it to be one bug away."""
    res = build_attack_graph(PLATFORM, [], Config())
    assert not [p for p in res.paths if "customer-data" in p.target.name]
    for x in res.exposures:
        crossings = [e for e in x.steps if e.requires]
        assert all(e.src == x.steps[0].src or e.src in {s.dst for s in x.steps} for e in crossings)
        hypothetical = [
            e
            for e in crossings
            if not res.graph.nodes[e.src].has(set(e.requires))
            and e.src != x.entry.id
            and res.graph.nodes[e.src].kind.value != "route"
        ]
        assert not hypothetical, x


def test_advice_never_gates(tmp_path: Path) -> None:
    deployed(tmp_path)
    res = build_attack_graph(tmp_path, [], JEWEL)
    summary = summarize(res, [], JEWEL.attack_graph, baseline_used=False)
    assert summary.exposures and not summary.gating_paths


def view(ident: str) -> ExposureView:
    return ExposureView(
        id=ident,
        entry="api",
        target="customer-bucket",
        target_kind="datastore",
        needs=["code_execution"],
        via=["role app"],
        harden="limit role app",
    )


def report(exposures: list[ExposureView] | None) -> ScanResult:
    return ScanResult(
        breachgraph_version="1", target=".", attack_graph=AttackGraphSummary(exposures=exposures)
    )


def test_a_change_that_widens_reach_is_called_out() -> None:
    head = report([view("old"), view("added")])
    head.comparison = compare(head, report([view("old")]))
    assert head.comparison.wider_exposures == ["added"]
    assert "This change widens what one bug could reach (1)" in render(head)


def test_a_base_from_an_older_version_says_nothing() -> None:
    head = report([view("added")])
    assert compare(head, report(None)).wider_exposures == []
