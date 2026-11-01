"""Questions for the day something goes wrong: this leaked, what now? What can reach that?

Both start from the graph as it stands. `--from` assumes one node is already lost, and every step
after it must be possible today, so the answer never rests on a second imagined bug.
"""

from __future__ import annotations

from collections import deque

from breachgraph.graph.model import INTERNET_ID, Edge, Graph, Node


def matching(graph: Graph, text: str) -> list[Node]:
    """Nodes whose name or id contains `text`, closest first."""
    needle = text.lower()
    hits = [n for n in graph.nodes.values() if needle in f"{n.name} {n.id}".lower()]
    return sorted(hits, key=lambda n: (n.name.lower() != needle, len(n.name)))


def _routes(graph: Graph, start: str, waive_first: bool) -> dict[str, list[Edge]]:
    """The shortest route to every node reachable from `start`, through crown jewels too."""
    adj = graph.out_edges()
    found: dict[str, list[Edge]] = {start: []}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        node = graph.nodes[current]
        for edge in adj.get(current, []):
            if edge.dst in found:
                continue
            given = waive_first and current == start
            if edge.requires and not given and not node.has(set(edge.requires)):
                continue
            found[edge.dst] = [*found[current], edge]
            queue.append(edge.dst)
    return found


def reach_from(graph: Graph, start: Node, crown_value: int = 7) -> list[tuple[Node, list[Edge]]]:
    """What falls if `start` is lost, most valuable first."""
    routes = _routes(graph, start.id, waive_first=True)
    lost = [(graph.nodes[n], r) for n, r in routes.items() if n != start.id]
    return sorted(
        [(n, r) for n, r in lost if n.value >= crown_value],
        key=lambda x: (-x[0].value, len(x[1])),
    )


def reach_to(graph: Graph, target: Node) -> tuple[list[Edge], list[Node]]:
    """The route an outsider has today, if any, and every node that could get there if it fell."""
    today = (
        _routes(graph, INTERNET_ID, waive_first=False).get(target.id, [])
        if INTERNET_ID in graph.nodes
        else []
    )
    sources: dict[str, list[str]] = {}
    for edge in graph.edges:
        sources.setdefault(edge.dst, []).append(edge.src)
    seen = {target.id}
    queue = deque([target.id])
    while queue:
        for src in sources.get(queue.popleft(), []):
            if src not in seen and src != INTERNET_ID:
                seen.add(src)
                queue.append(src)
    return today, [graph.nodes[n] for n in sorted(seen - {target.id})]


def describe(graph: Graph, route: list[Edge]) -> str:
    return " -> ".join([graph.nodes[route[0].src].name, *(graph.nodes[e.dst].name for e in route)])


def answer(graph: Graph, start: str | None, target: str | None, crown_value: int = 7) -> dict[str, object]:
    """Both questions in a shape a person or an assistant can use."""
    out: dict[str, object] = {}
    if start:
        hits = matching(graph, start)
        if not hits:
            raise ValueError(f"nothing in the graph matches {start!r}")
        out["from"] = hits[0].name
        out["falls_with_it"] = [
            {"asset": n.name, "route": describe(graph, r)} for n, r in reach_from(graph, hits[0], crown_value)
        ]
    if target:
        hits = matching(graph, target)
        if not hits:
            raise ValueError(f"nothing in the graph matches {target!r}")
        today, sources = reach_to(graph, hits[0])
        out["to"] = hits[0].name
        out["reachable_from_the_internet_today"] = describe(graph, today) if today else None
        out["reachable_if_these_fall"] = [n.name for n in sources]
    return out
