"""Many paths of one kind read as one entry, and a limit can't hide what blocks a merge."""

from breachgraph.graph.model import (
    INTERNET_ID,
    Confidence,
    Edge,
    EdgeKind,
    Evidence,
    Graph,
    Node,
    NodeKind,
    Weakness,
    WeaknessClass,
    internet,
)
from breachgraph.graph.paths import find_paths
from breachgraph.graph.summary import group_id, known_as
from breachgraph.models import AttackGraphSummary, AttackPathView, AttackStep


def weapon(name: str, sure: Confidence = Confidence.HIGH, title: str = "SQL") -> Weakness:
    return Weakness(
        cls=WeaknessClass.CODE_EXECUTION,
        confidence=sure,
        fingerprint=name,
        title=title,
        evidence=Evidence(path=f"{name}.py", line=1),
    )


def graph(*weapons: Weakness) -> Graph:
    g = Graph()
    g.add_node(internet())
    g.add_node(Node(id="jewel", kind=NodeKind.DATASTORE, name="db", value=9))
    for i, w in enumerate(weapons):
        node = g.add_node(Node(id=f"w{i}", kind=NodeKind.WORKLOAD, name=f"w{i}", weaknesses=[w]))
        g.add_edge(Edge(src=INTERNET_ID, dst=node.id, kind=EdgeKind.EXPOSES))
        g.add_edge(
            Edge(src=node.id, dst="jewel", kind=EdgeKind.CONNECTS_TO, requires=[WeaknessClass.CODE_EXECUTION])
        )
    return g


def test_a_limit_keeps_the_path_that_blocks_over_stronger_scoring_leads() -> None:
    leads = [weapon(f"lead{i}", Confidence.LOW) for i in range(3)]
    g = graph(*leads, weapon("sure", title="real"))
    for edge in g.edges:  # less direct, so it scores below every lead
        if edge.src == "w3":
            edge.confidence = Confidence.MEDIUM
    ranked = find_paths(g, max_paths=None)
    assert ranked[0].confidence is Confidence.MEDIUM
    assert ranked[0].score < ranked[1].score
    assert [p.confidence for p in find_paths(g, max_paths=1)] == [Confidence.MEDIUM]
    assert len(find_paths(g, max_paths=None)) == 4


def test_same_flaw_and_asset_share_a_group_and_a_different_flaw_does_not() -> None:
    a, b, c = find_paths(graph(weapon("a"), weapon("b"), weapon("c", title="other")))
    by_title = {p.steps[-1].weakness_title: group_id(p) for p in (a, b, c)}
    assert len(by_title) == 2
    assert len({group_id(a), group_id(b), group_id(c)}) == 2


def view(group: str, gating: bool = False) -> AttackPathView:
    step = AttackStep(src="a", dst="b", dst_kind="workload", kind="exposes")
    return AttackPathView(
        id=f"{group}{gating}", group=group, target="t", target_kind="k", score=1, confidence="low",
        length=1, gating=gating, steps=[step],
    )  # fmt: skip


def test_a_blocking_path_leads_its_group() -> None:
    summary = AttackGraphSummary(paths=[view("x"), view("y"), view("x", gating=True)])
    assert [[p.gating for p in g] for g in summary.grouped()] == [[True, False], [False]]


def test_older_reports_have_no_groups_so_nothing_merges() -> None:
    assert len(AttackGraphSummary(paths=[view(""), view("")]).grouped()) == 2


def incident_graph(via: WeaknessClass, target: NodeKind) -> Graph:
    g = Graph()
    g.add_node(internet())
    g.add_node(Node(id="w", kind=NodeKind.WORKLOAD, name="web", weaknesses=[]))
    g.add_node(Node(id="r", kind=NodeKind.IDENTITY, name="role"))
    g.add_node(Node(id="d", kind=target, name="data", value=9))
    g.nodes["w"].weaknesses.append(
        Weakness(cls=via, title="t", evidence=Evidence(path="a.py", line=1), fingerprint="f")
    )
    g.add_edge(Edge(src=INTERNET_ID, dst="w", kind=EdgeKind.EXPOSES))
    g.add_edge(Edge(src="w", dst="r", kind=EdgeKind.USES_IDENTITY, requires=[via]))
    g.add_edge(Edge(src="r", dst="d", kind=EdgeKind.CAN_ACCESS))
    return g


def test_a_path_with_a_known_shape_says_so_and_others_do_not() -> None:
    ssrf = incident_graph(WeaknessClass.SSRF, NodeKind.DATASTORE)
    assert "Capital One" in known_as(find_paths(ssrf)[0], ssrf)
    rce = incident_graph(WeaknessClass.CODE_EXECUTION, NodeKind.DATASTORE)
    assert known_as(find_paths(rce)[0], rce) == ""
    secret = incident_graph(WeaknessClass.SSRF, NodeKind.SECRET)
    assert known_as(find_paths(secret)[0], secret) == ""
