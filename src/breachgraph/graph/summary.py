"""Convert the attack-graph engine output into the serializable summary reporters consume."""

from __future__ import annotations

import hashlib

from breachgraph.config import AttackGraph as AttackGraphConfig
from breachgraph.graph import AttackGraphResult
from breachgraph.graph.model import Confidence
from breachgraph.graph.paths import AttackPath
from breachgraph.models import (
    AttackGraphSummary,
    AttackPathView,
    AttackStep,
    ChokePointView,
    Finding,
    GraphEdgeView,
    GraphExport,
    GraphNodeView,
    GraphWeakness,
    Status,
)

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def path_id(path: AttackPath) -> str:
    """Stable identity of a path: where it starts, what it reaches, and the findings it needs.

    Node ids are resource names and finding fingerprints are content-based, so the id survives
    unrelated edits and reruns. A path that needs no finding (e.g. a publicly assumable role) is
    identified by its full route instead."""
    nodes = path.nodes
    parts = [nodes[0], path.target.id, *sorted(path.weaknesses)] if path.weaknesses else nodes
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def summarize(
    result: AttackGraphResult,
    findings: list[Finding],
    config: AttackGraphConfig,
    baseline_used: bool,
    baseline_paths: set[str] | None = None,
) -> AttackGraphSummary:
    node_name = {nid: n.name for nid, n in result.graph.nodes.items()}
    node_kind = {nid: n.kind.value for nid, n in result.graph.nodes.items()}
    status_by_fp = {f.fingerprint: f.status for f in findings}
    new_fps = {f.fingerprint for f in findings if f.status is Status.NEW}
    min_rank = _CONF_RANK[config.min_confidence]

    views: list[AttackPathView] = []
    for p in result.paths:
        pid = path_id(p)
        if baseline_paths is not None:
            is_new = pid not in baseline_paths
        else:
            # Without recorded paths: new if any weapon on it is a new finding, or no baseline.
            is_new = (not baseline_used) or any(fp in new_fps for fp in p.weaknesses) or not p.weaknesses
        gating = (
            config.fail_on_new_path
            and _CONF_RANK[p.confidence.value] >= min_rank
            and (is_new or not baseline_used)
        )
        views.append(
            AttackPathView(
                id=pid,
                node_ids=p.nodes,
                target=p.target.name,
                target_kind=p.target.kind.value,
                score=p.score,
                confidence=p.confidence.value,
                length=p.length,
                is_new=is_new,
                gating=gating,
                steps=[_step(p, i, node_name, node_kind) for i in range(len(p.steps))],
                weaknesses=[fp for fp in p.weaknesses if status_by_fp.get(fp) is not Status.SUPPRESSED],
            )
        )

    chokes = [
        ChokePointView(
            title=c.title,
            weakness=c.weakness.value,
            paths_cut=c.paths_cut,
            fingerprint=c.fingerprint,
            path=c.evidence_path,
            line=c.evidence_line,
        )
        for c in result.choke_points
    ]
    return AttackGraphSummary(
        enabled=True,
        paths=views,
        choke_points=chokes,
        skipped=result.skipped,
        stats=result.stats,
        graph=export_graph(result, views),
    )


MAX_EXPORT_NODES = 400


def export_graph(result: AttackGraphResult, views: list[AttackPathView]) -> GraphExport:
    """Nodes and edges that the reported paths use (the explorer draws exactly these)."""
    g = result.graph
    wanted: list[str] = []
    for v in views:
        wanted += [n for n in v.node_ids if n not in wanted]
    truncated = len(wanted) > MAX_EXPORT_NODES
    keep = set(wanted[:MAX_EXPORT_NODES])
    nodes = [
        GraphNodeView(
            id=nid,
            name=g.nodes[nid].name,
            kind=g.nodes[nid].kind.value,
            value=g.nodes[nid].value,
            evidence=[e.label() for e in g.nodes[nid].evidence[:3]],
            weaknesses=[
                GraphWeakness(
                    title=w.title,
                    cls=w.cls.value,
                    fingerprint=w.fingerprint,
                    location=w.evidence.label() if w.evidence else None,
                )
                for w in g.nodes[nid].weaknesses[:10]
            ],
        )
        for nid in wanted[:MAX_EXPORT_NODES]
        if nid in g.nodes
    ]
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    edges: list[GraphEdgeView] = []
    for path in result.paths:
        for s in path.steps:
            e = s.edge
            key = (e.src, e.dst, e.kind.value, tuple(sorted(r.value for r in e.requires)))
            if key in seen or e.src not in keep or e.dst not in keep:
                continue
            seen.add(key)
            edges.append(
                GraphEdgeView(
                    src=e.src,
                    dst=e.dst,
                    kind=e.kind.value,
                    requires=[r.value for r in e.requires],
                    confidence=e.confidence.value,
                    note=e.note,
                    evidence=e.evidence[0].label() if e.evidence else None,
                )
            )
    return GraphExport(nodes=nodes, edges=edges, truncated=truncated)


def _step(path: AttackPath, i: int, names: dict[str, str], kinds: dict[str, str]) -> AttackStep:
    s = path.steps[i]
    ev = s.edge.evidence[0] if s.edge.evidence else None
    return AttackStep(
        src=names.get(s.edge.src, s.edge.src),
        dst=names.get(s.edge.dst, s.edge.dst),
        dst_kind=kinds.get(s.edge.dst, ""),
        kind=s.edge.kind.value,
        via=s.via.value if s.via else None,
        weakness_title=s.weakness_title,
        note=s.edge.note,
        confidence=s.edge.confidence.value if isinstance(s.edge.confidence, Confidence) else "high",
        evidence_path=ev.path if ev else None,
        evidence_line=ev.line if ev else None,
    )
