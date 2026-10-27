"""The interactive attack-graph explorer in the HTML report: data export and injection safety."""

import json
import re

from breachgraph.models import (
    AttackGraphSummary,
    AttackPathView,
    AttackStep,
    GraphEdgeView,
    GraphExport,
    GraphNodeView,
    ScanResult,
)
from breachgraph.reporters import html
from tests.test_pipeline_attackgraph import CMDI, SSRF, run


def embedded(page: str) -> dict:  # type: ignore[type-arg]
    m = re.search(r'<script type="application/json" id="bg-data">(.*?)</script>', page, re.S)
    assert m, "explorer data missing"
    return json.loads(m.group(1))


def test_graph_export_covers_every_path() -> None:
    res = run([SSRF, CMDI])
    ag = res.attack_graph
    assert ag is not None and ag.graph is not None
    ids = {n.id for n in ag.graph.nodes}
    for p in ag.paths:
        assert set(p.node_ids) <= ids
    pairs = {(e.src, e.dst) for e in ag.graph.edges}
    for p in ag.paths:
        assert all((a, b) in pairs for a, b in zip(p.node_ids, p.node_ids[1:], strict=False))
    route = next(n for n in ag.graph.nodes if n.kind == "route" and n.weaknesses)
    assert route.weaknesses[0].fingerprint and route.weaknesses[0].location


def test_report_embeds_explorer_data() -> None:
    page = html.render(run([SSRF, CMDI]))
    data = embedded(page)
    assert len(data["paths"]) == 2 and data["fixes"]
    assert all(p["nodes"][0] == "internet" for p in data["paths"])
    assert 'id="explorer"' in page and "Paths as text" in page


def test_hostile_names_cannot_escape_the_data_block() -> None:
    evil = '</script><img src=x onerror=alert(1)>"&'
    graph = GraphExport(
        nodes=[
            GraphNodeView(id="internet", name="Internet", kind="internet"),
            GraphNodeView(id="x", name=evil, kind="datastore", value=9),
        ],
        edges=[GraphEdgeView(src="internet", dst="x", kind="can_access", note=evil)],
    )
    path = AttackPathView(
        id="p",
        node_ids=["internet", "x"],
        target=evil,
        target_kind="datastore",
        score=1,
        confidence="high",
        length=1,
        steps=[AttackStep(src="Internet", dst=evil, dst_kind="datastore", kind="can_access")],
    )
    result = ScanResult(breachgraph_version="t", target="/r")
    result.attack_graph = AttackGraphSummary(paths=[path], graph=graph)
    page = html.render(result)
    block = re.search(r'id="bg-data">(.*?)</script>', page, re.S)
    assert block is not None
    assert "<" not in block.group(1) and ">" not in block.group(1)  # can't close or open tags
    assert embedded(page)["nodes"][1]["name"] == evil  # the data itself is intact
    assert "<img src=x" not in page  # and nowhere else is it rendered as HTML
    assert "innerHTML" not in page  # the explorer only ever uses textContent
