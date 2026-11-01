"""`--from` and `--to`: an answer that needs no second imagined bug."""

import pytest

from breachgraph.graph.model import (
    CONTROL,
    INTERNET_ID,
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
from breachgraph.graph.query import answer, matching, reach_from, reach_to


def graph() -> Graph:
    """Internet -> web, web needs a weapon to reach its role, the role reads the bucket."""
    g = Graph()
    g.add_node(internet())
    g.add_node(Node(id="web", kind=NodeKind.WORKLOAD, name="web"))
    g.add_node(Node(id="role", kind=NodeKind.IDENTITY, name="web role"))
    g.add_node(Node(id="bucket", kind=NodeKind.DATASTORE, name="customer data", value=9))
    g.add_node(Node(id="key", kind=NodeKind.SECRET, name="payment key", value=8))
    g.add_edge(Edge(src=INTERNET_ID, dst="web", kind=EdgeKind.EXPOSES))
    g.add_edge(Edge(src="web", dst="role", kind=EdgeKind.USES_IDENTITY, requires=CONTROL))
    g.add_edge(Edge(src="role", dst="bucket", kind=EdgeKind.CAN_ACCESS))
    g.add_edge(Edge(src="bucket", dst="key", kind=EdgeKind.MOUNTS, requires=CONTROL))
    return g


def weapon(g: Graph) -> None:
    g.nodes["web"].weaknesses.append(
        Weakness(cls=WeaknessClass.CODE_EXECUTION, title="rce", evidence=Evidence(path="a.py"))
    )


def test_a_lost_node_gives_what_it_holds_and_nothing_needing_another_bug() -> None:
    g = graph()
    assert [n.id for n, _r in reach_from(g, g.nodes["web"])] == ["bucket"]  # not the key behind a second bug


def test_the_first_step_is_assumed_and_later_ones_are_not() -> None:
    g = graph()
    assert reach_from(g, g.nodes["role"])[0][0].id == "bucket"
    assert reach_from(g, g.nodes["bucket"])[0][0].id == "key"


def test_to_says_when_nothing_reaches_it_today() -> None:
    g = graph()
    today, sources = reach_to(g, g.nodes["bucket"])
    assert today == []
    assert {n.id for n in sources} == {"web", "role"}


def test_to_gives_the_route_when_there_is_one() -> None:
    g = graph()
    weapon(g)
    today, _sources = reach_to(g, g.nodes["bucket"])
    assert [e.dst for e in today] == ["web", "role", "bucket"]


def test_the_closest_name_wins() -> None:
    g = graph()
    g.add_node(Node(id="w2", kind=NodeKind.WORKLOAD, name="web frontend"))
    assert matching(g, "WEB")[0].id == "web"


def test_an_unknown_name_says_so() -> None:
    with pytest.raises(ValueError, match="nothing in the graph"):
        answer(graph(), "nope", None)


def test_the_answer_for_an_assistant() -> None:
    out = answer(graph(), "web role", "customer data")
    assert out["falls_with_it"] == [{"asset": "customer data", "route": "web role -> customer data"}]
    assert out["reachable_from_the_internet_today"] is None
