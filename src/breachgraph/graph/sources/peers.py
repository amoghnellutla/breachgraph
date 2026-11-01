"""Who else reaches an open service: its neighbours, within what the network allows."""

from __future__ import annotations

from breachgraph.graph.model import CONTROL, Confidence, Edge, EdgeKind, Graph, Node, NodeKind
from breachgraph.graph.sources.kubernetes import admits


def _beside(peer: Node, service: Node) -> bool:
    """Whether `peer` can open a connection to `service`."""
    if peer.attrs.get("platform") != service.attrs.get("platform"):
        return False
    if service.attrs.get("platform") == "compose":
        return bool(peer.evidence and service.evidence) and peer.evidence[0].path == service.evidence[0].path
    ingress = service.attrs.get("ingress")
    if isinstance(ingress, dict):
        return admits(ingress, peer.attrs, str(service.attrs.get("namespace")))
    return service.attrs.get("platform") == "kubernetes"  # no policy selects it: any pod connects


def reach_from_peers(graph: Graph) -> None:
    """An open service doesn't ask who is connecting, so whoever controls a neighbour has it too."""
    workloads = list(graph.of_kind(NodeKind.WORKLOAD))
    for service in workloads:
        jewel = graph.nodes.get(f"service:{service.id}")
        if jewel is None:
            continue
        for peer in workloads:
            if peer.id != service.id and _beside(peer, service):
                graph.add_edge(
                    Edge(
                        src=peer.id,
                        dst=jewel.id,
                        kind=EdgeKind.CONNECTS_TO,
                        requires=CONTROL,
                        confidence=Confidence.MEDIUM,
                        evidence=jewel.evidence,
                        note=f"{service.name} is on the same network and doesn't ask who is connecting",
                    )
                )
