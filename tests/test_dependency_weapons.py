"""A dependency CVE is a way in only if its flaw gives control of what runs it."""

import pytest

from breachgraph.graph.correlate import CodeUnit, attach, code_units
from breachgraph.graph.model import Confidence, Evidence, Graph, Node, NodeKind, WeaknessClass
from breachgraph.models import Category, Finding
from tests.conftest import make_finding


def exploited(cwe: list[str]) -> Finding:
    f = make_finding(path="package-lock.json")
    f.category = Category.SCA
    f.cwe = cwe
    f.enrichment.kev = True
    return f


def workload(path: str = "deploy/app.yaml") -> Node:
    return Node(id="w", kind=NodeKind.WORKLOAD, name="w", evidence=[Evidence(path=path)])


@pytest.mark.parametrize(
    ("cwe", "sure"),
    [
        (["CWE-502"], Confidence.HIGH),  # deserialization runs code
        (["CWE-787"], Confidence.HIGH),  # so can memory corruption
        ([], Confidence.HIGH),  # nothing says it doesn't
        (["CWE-918", "CWE-289"], Confidence.LOW),  # a proxy bypass
        (["CWE-22"], Confidence.LOW),  # a cookie path bug
        (["CWE-863"], Confidence.LOW),  # an authorization bypass in a daemon the code only calls
    ],
)
def test_exploited_is_not_the_same_as_control(cwe: list[str], sure: Confidence) -> None:
    graph = Graph()
    node = graph.add_node(workload())
    attach(graph, [exploited(cwe)], [], [CodeUnit("", ["w"], Confidence.HIGH)])
    assert [(w.cls, w.confidence) for w in node.weaknesses] == [(WeaknessClass.VULNERABLE_DEPENDENCY, sure)]


def test_an_example_workload_does_not_inherit_the_only_dockerfile() -> None:
    graph = Graph()
    graph.add_node(workload("terraform/examples/three-nodes/main.tf"))
    assert code_units(graph, [""], "repo") == []
    other = Graph()
    other.add_node(workload())
    assert [u.workloads for u in code_units(other, [""], "repo")] == [["w"]]


def test_model_output_at_a_sink_is_a_lead_until_outsiders_text_is_shown_to_reach_it() -> None:
    f = make_finding(path="app.py", rule_id="breachgraph.python.model-output-execution")
    f.cwe = ["CWE-94"]
    graph = Graph()
    node = graph.add_node(workload())
    attach(graph, [f], [], [CodeUnit("", ["w"], Confidence.HIGH)])
    assert [w.confidence for w in node.weaknesses] == [Confidence.LOW]
