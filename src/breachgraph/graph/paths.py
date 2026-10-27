"""Find and rank attack paths from the internet to high-value assets.

A path is a walk from the Internet node to a "crown jewel" (a node whose value >= threshold).
An edge marked ``requires`` can be crossed only if the current node carries a weakness of one of
the required classes; that weakness is what makes the step an attack step. The path's confidence
is the weakest edge on it, and its score combines the target's value with how easy the path is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from breachgraph.graph.model import (
    INTERNET_ID,
    Confidence,
    Edge,
    Graph,
    Node,
    WeaknessClass,
)

_CONF_WEIGHT = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.3}
_CONF_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
# How hard each attacker action is (1 = trivial). Used to rank, and to pick the cheapest fix.
_STEP_COST = {
    WeaknessClass.CREDENTIAL_EXPOSURE: 1.0,
    WeaknessClass.VULNERABLE_DEPENDENCY: 2.0,
    WeaknessClass.CODE_EXECUTION: 2.0,
    WeaknessClass.SSRF: 2.5,
    WeaknessClass.INJECTION_DATA: 2.5,
    WeaknessClass.FILE_READ: 2.5,
    WeaknessClass.AUTH_BYPASS: 2.0,
    WeaknessClass.CONTAINER_ESCAPE: 2.0,
    WeaknessClass.METADATA_REACHABLE: 1.0,
}


@dataclass
class Step:
    edge: Edge
    via: WeaknessClass | None  # the weakness used to cross, if any
    weakness_title: str | None


@dataclass
class AttackPath:
    steps: list[Step]
    target: Node
    score: float = 0.0
    confidence: Confidence = Confidence.HIGH
    weaknesses: list[str] = field(default_factory=list)  # fingerprints of findings on the path

    @property
    def nodes(self) -> list[str]:
        return [self.steps[0].edge.src, *[s.edge.dst for s in self.steps]]

    @property
    def length(self) -> int:
        return len(self.steps)


def _target_value(node: Node) -> int:
    return node.value


def find_paths(
    graph: Graph, crown_value: int = 7, max_depth: int = 12, max_paths: int = 40
) -> list[AttackPath]:
    if INTERNET_ID not in graph.nodes:
        return []
    adj = graph.out_edges()
    targets = {n.id for n in graph.nodes.values() if n.value >= crown_value}
    if not targets:
        return []

    # Enumerate paths to crown jewels (bounded DFS), keeping the best path per distinct set of
    # weapons used. Different entry weaknesses (e.g. SSRF vs command injection) therefore surface
    # as separate attack vectors, since fixing one does not fix the other. A global step budget
    # guarantees termination on dense graphs.
    best_by_vector: dict[frozenset[str], AttackPath] = {}
    budget = 200_000
    stack: list[tuple[list[str], list[Step]]] = [([INTERNET_ID], [])]
    while stack and budget > 0:
        node_ids, steps = stack.pop()
        budget -= 1
        current = node_ids[-1]
        if current in targets and steps:
            path = _make_path(graph, steps)
            _score(path)
            vector = _vector(graph, path) or frozenset({current})
            prev = best_by_vector.get(vector)
            if prev is None or path.score > prev.score:
                best_by_vector[vector] = path
            continue
        if len(steps) >= max_depth:
            continue
        node = graph.nodes[current]
        for edge in adj.get(current, []):
            if edge.dst in node_ids:  # no cycles
                continue
            via, title = _crossing(node, edge)
            if edge.requires and via is None:
                continue
            stack.append(([*node_ids, edge.dst], [*steps, Step(edge, via, title)]))

    found = sorted(best_by_vector.values(), key=lambda p: (-p.score, p.length))
    return found[:max_paths]


def _vector(graph: Graph, path: AttackPath) -> frozenset[str]:
    """The weapons a path uses: scanner findings by fingerprint, and weaknesses the graph itself
    derived (a committed password, a privileged pod) by where they are and what they are, so a
    path that needs one never collides with a path that needs nothing."""
    derived = {
        f"{s.edge.src}|{s.via}"
        for s in path.steps
        if s.via and not any(w.fingerprint for w in graph.nodes[s.edge.src].has({s.via}))
    }
    return frozenset(path.weaknesses) | derived


def _crossing(node: Node, edge: Edge) -> tuple[WeaknessClass | None, str | None]:
    if not edge.requires:
        return None, None
    matches = node.has(set(edge.requires))
    if not matches:
        return None, None
    w = matches[0]
    return w.cls, w.title


def _make_path(graph: Graph, steps: list[Step]) -> AttackPath:
    target = graph.nodes[steps[-1].edge.dst]
    weaknesses: list[str] = []
    for s in steps:
        if s.via:
            for w in graph.nodes[s.edge.src].has({s.via}):
                if w.fingerprint and w.fingerprint not in weaknesses:
                    weaknesses.append(w.fingerprint)
    return AttackPath(steps=steps, target=target, weaknesses=weaknesses)


def _score(path: AttackPath) -> None:
    confs = [s.edge.confidence for s in path.steps]
    path.confidence = min(confs, key=lambda c: _CONF_RANK[c])
    reachability = 1.0
    for c in confs:
        reachability *= _CONF_WEIGHT[c]
    effort = sum(_STEP_COST.get(s.via, 0.5) for s in path.steps if s.via) or 1.0
    # Value dominates; longer, harder, lower-confidence paths score lower.
    path.score = round(path.target.value * (10 / (effort + 3)) * (0.4 + 0.6 * reachability), 2)


@dataclass
class ChokePoint:
    fingerprint: str | None
    title: str
    weakness: WeaknessClass
    paths_cut: int
    evidence_path: str | None
    evidence_line: int | None


def choke_points(graph: Graph, paths: list[AttackPath]) -> list[ChokePoint]:
    """Weaknesses that, if removed, break the most paths: the best fixes to recommend first."""
    by_weakness: dict[tuple[WeaknessClass, str], ChokePoint] = {}
    counts: dict[tuple[WeaknessClass, str], int] = {}
    for path in paths:
        on_path: set[tuple[WeaknessClass, str]] = set()
        for s in path.steps:
            if not s.via:
                continue
            src = graph.nodes[s.edge.src]
            for w in src.has({s.via}):
                key = (w.cls, w.fingerprint or w.title)
                on_path.add(key)
                if key not in by_weakness:
                    by_weakness[key] = ChokePoint(
                        fingerprint=w.fingerprint,
                        title=w.title,
                        weakness=w.cls,
                        paths_cut=0,
                        evidence_path=w.evidence.path,
                        evidence_line=w.evidence.line,
                    )
        for key in on_path:
            counts[key] = counts.get(key, 0) + 1
    result = []
    for key, cp in by_weakness.items():
        cp.paths_cut = counts[key]
        result.append(cp)
    result.sort(key=lambda c: (-c.paths_cut, _STEP_COST.get(c.weakness, 5)))
    return result
