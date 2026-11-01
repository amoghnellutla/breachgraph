"""One bug away: what a single new weakness at each exposed entry would reach.

Attack paths need a weakness that exists today, which is the right bar for failing a build, and
most healthy repositories have none. The risk they do carry is structural: a public service whose
role can read the customer bucket is one bug from a breach, and no scanner finding says so.

So for each entry an outsider can reach with no weakness at all, assume one bug there, and only
there. Every later step must be possible already, so a result never rests on two imagined bugs.
These are hardening advice: they are never attack paths and never gate a merge.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass

from breachgraph.graph.model import (
    INTERNET_ID,
    Confidence,
    Edge,
    EdgeKind,
    Graph,
    Node,
    NodeKind,
    WeaknessClass,
)
from breachgraph.graph.paths import AttackPath

MAX_EXPOSURES = 20


@dataclass
class Exposure:
    entry: Node
    target: Node
    steps: list[Edge]
    needs: list[WeaknessClass]  # what kind of bug at the entry would do it

    @property
    def id(self) -> str:
        return hashlib.sha256(f"{self.entry.id}|{self.target.id}".encode()).hexdigest()[:16]

    @property
    def via(self) -> list[str]:
        return [e.dst for e in self.steps[:-1]]


def _exposed(graph: Graph, adj: dict[str, list[Edge]]) -> set[str]:
    """Nodes an outsider reaches with no weakness, over edges that aren't doubtful."""
    seen = {INTERNET_ID}
    queue = deque(seen)
    while queue:
        for e in adj.get(queue.popleft(), []):
            if e.dst not in seen and not e.requires and e.confidence is not Confidence.LOW:
                seen.add(e.dst)
                queue.append(e.dst)
    return seen


def _reach(
    graph: Graph, adj: dict[str, list[Edge]], entry: str, crown_value: int
) -> dict[str, tuple[list[Edge], list[WeaknessClass]]]:
    """Crown jewels reachable from an entry, assuming one bug on the entry or a route it serves."""
    assumed = {entry} | {e.dst for e in adj.get(entry, []) if e.kind is EdgeKind.SERVES}
    found: dict[str, tuple[list[Edge], list[WeaknessClass]]] = {}
    seen = set(assumed)
    queue: deque[tuple[str, list[Edge], list[WeaknessClass]]] = deque((n, [], []) for n in sorted(assumed))
    while queue:
        node_id, steps, needs = queue.popleft()
        node = graph.nodes[node_id]
        for e in adj.get(node_id, []):
            if e.dst in seen:
                continue
            first = needs
            if e.requires and not node.has(set(e.requires)):
                if node_id not in assumed or needs:
                    continue  # a second imagined bug
                first = list(e.requires)
            elif e.requires and not needs and node_id in assumed:
                first = list(e.requires)
            seen.add(e.dst)
            path = [*steps, e]
            if graph.nodes[e.dst].value >= crown_value:
                if first:  # with no bug needed at all this is an attack path, not advice
                    found.setdefault(e.dst, (path, first))
                continue
            queue.append((e.dst, path, first))
    return found


def one_bug_away(graph: Graph, crown_value: int, paths: list[AttackPath]) -> list[Exposure]:
    if INTERNET_ID not in graph.nodes:
        return []
    adj = graph.out_edges()
    exposed = _exposed(graph, adj)
    real = {p.target.id for p in paths}  # already a real path: the path says it better
    out: list[Exposure] = []
    for nid in sorted(exposed):
        node = graph.nodes[nid]
        if node.kind is not NodeKind.WORKLOAD:
            continue
        for target, (steps, needs) in _reach(graph, adj, nid, crown_value).items():
            if target not in real:
                out.append(Exposure(node, graph.nodes[target], steps, needs))
    out.sort(key=lambda x: (-x.target.value, len(x.steps), x.entry.name, x.target.name))
    return out[:MAX_EXPOSURES]
