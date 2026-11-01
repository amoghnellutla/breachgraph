"""Whoever controls a workload has the open service beside it, and only within what the network allows."""

from pathlib import Path

import yaml

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.correlate import CodeUnit, attach
from breachgraph.graph.model import Confidence, EdgeKind, Graph, WeaknessClass
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.kubernetes import KubernetesSource
from breachgraph.graph.sources.peers import reach_from_peers
from breachgraph.graph.sources.routes import Route


def deployment(name: str, image: str, namespace: str = "default") -> dict:  # type: ignore[type-arg]
    labels = {"app": name}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {"containers": [{"name": "c", "image": image}]},
            },
        },
    }


DENY = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "deny", "namespace": "default"},
    "spec": {"podSelector": {"matchLabels": {"app": "search"}}, "policyTypes": ["Ingress"], "ingress": []},
}
SEARCH = "k8s:workload:default/search"
WEB = "k8s:workload:default/web"
JEWEL = f"service:{SEARCH}"


def load(tmp: Path, *docs: dict) -> Graph:  # type: ignore[type-arg]
    (tmp / "all.yaml").write_text(yaml.safe_dump_all(docs), encoding="utf-8")
    g = Graph()
    KubernetesSource().collect(SourceContext(root=tmp, exclude=[]), g)
    reach_from_peers(g)
    return g


def edge(g: Graph, src: str, dst: str):  # type: ignore[no-untyped-def]
    return next((e for e in g.edges if e.src == src and e.dst == dst), None)


def test_a_neighbour_needs_control_to_use_it(tmp_path: Path) -> None:
    g = load(tmp_path, deployment("web", "app:1"), deployment("search", "elasticsearch:7.17.0"))
    step = edge(g, WEB, JEWEL)
    assert step and step.kind is EdgeKind.CONNECTS_TO and step.requires


def test_a_network_policy_cuts_it(tmp_path: Path) -> None:
    g = load(tmp_path, deployment("web", "app:1"), deployment("search", "elasticsearch:7.17.0"), DENY)
    assert not edge(g, WEB, JEWEL)


def test_a_secured_service_has_nothing_to_reach(tmp_path: Path) -> None:
    g = load(tmp_path, deployment("web", "app:1"), deployment("search", "elasticsearch:8.13.0"))
    assert not edge(g, WEB, JEWEL)


def ssrf_reaches(image: str, root: Path) -> bool:
    root.mkdir()
    g = load(root, deployment("web", "app:1"), deployment("search", image))
    route = Route(
        method="GET", path="/f", file="a.py", start_line=1, end_line=2, handler="f", framework="flask"
    )
    attach(g, [], [route], [CodeUnit("", [WEB], Confidence.HIGH)])
    return any(e.dst == JEWEL and WeaknessClass.SSRF in e.requires for e in g.edges)


def test_ssrf_reaches_what_speaks_http_and_not_redis(tmp_path: Path) -> None:
    assert ssrf_reaches("elasticsearch:7.17.0", tmp_path / "a")
    assert not ssrf_reaches("redis:7", tmp_path / "b")


def test_it_reaches_a_full_build_without_inventing_a_path(tmp_path: Path) -> None:
    (tmp_path / "all.yaml").write_text(
        yaml.safe_dump_all([deployment("web", "app:1"), deployment("search", "elasticsearch:7.17.0")]),
        encoding="utf-8",
    )
    assert build_attack_graph(tmp_path, [], Config()).paths == []
