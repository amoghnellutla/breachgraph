"""`breachgraph why file:line`: why a finding is, or isn't, part of an attack path.

Triage turns on this question and the reports only imply the answer. This walks the checks the
graph applies, in order, and stops at the first one that explains the result, so the answer names
the missing step rather than a score.
"""

from __future__ import annotations

from breachgraph.graph import AttackGraphResult
from breachgraph.graph.correlate import weakness_class
from breachgraph.graph.exposure import _exposed
from breachgraph.graph.model import Confidence, Graph, Node, NodeKind, WeaknessClass, not_run
from breachgraph.models import Category, Finding, Reachability, Status

_LOW = (
    "This is low confidence, so it doesn't gate: the service has known routes and none of them was "
    "followed to this code, or the value it uses is built from constants."
)


def _route(path_nodes: list[str], graph: Graph) -> str:
    return " -> ".join(graph.nodes[n].name for n in path_nodes)


def _unclassified(f: Finding) -> str:
    if f.category in (Category.SCA, Category.CONTAINER):
        if f.package and f.package.reachability is Reachability.UNUSED:
            return "Nothing in the code imports this package, so it can't be used as a way in."
        return (
            "A dependency CVE opens a path only with signs of real exploitation (in CISA KEV, or EPSS at "
            "least 0.1 with CVSS at least 7), and this one has none."
        )
    return "This kind of finding doesn't give an attacker a step (no code execution, injection, SSRF, ...)."


def _holder(nodes: list[Node], fps: set[str]) -> tuple[Node, Confidence, str]:
    """The node carrying the weakness that says the most: routes first, then the surest."""
    best = sorted(
        ((n, w) for n in nodes for w in n.weaknesses if w.fingerprint in fps),
        key=lambda x: (x[0].kind is not NodeKind.ROUTE, x[1].confidence is Confidence.LOW),
    )
    node, weak = best[0]
    return node, weak.confidence, weak.evidence.detail


def explain(f: Finding, ag: AttackGraphResult) -> list[str]:
    """Plain sentences, the verdict first."""
    fps = set(f.fingerprints or [f.fingerprint])
    on_paths = [p for p in ag.paths if fps & set(p.weaknesses)]
    if on_paths:
        out = [f"On {len(on_paths)} attack path(s):"]
        out += [f"  {_route(p.nodes, ag.graph)} ({p.confidence.value} confidence)" for p in on_paths[:5]]
        if login := next((p.needs_login for p in on_paths if p.needs_login), ""):
            out.append(f"The route is behind `{login}`, so an attacker needs an account first.")
        if all(p.confidence is Confidence.LOW for p in on_paths):
            out.append(_LOW)
        return out
    if f.status is Status.SUPPRESSED:
        return ["Not on a path: this finding is suppressed in your policy."]
    cls: WeaknessClass | None = weakness_class(f)
    if cls is None:
        return [f"Not on a path. {_unclassified(f)}"]
    if not_run(f.location.path):
        return ["Not on a path: this is test or example code, which the service doesn't run."]
    nodes = [n for n in ag.graph.nodes.values() if any(w.fingerprint in fps for w in n.weaknesses)]
    if not nodes:
        return [
            f"Not on a path: it's a {cls.value.replace('_', ' ')} weakness, but no deployed service was "
            "matched to this code (no Dockerfile, compose service or function points at it).",
        ]
    node, sure, detail = _holder(nodes, fps)
    adj = ag.graph.out_edges()
    exposed = _exposed(ag.graph, adj)
    if node.id not in exposed:
        return [f"Not on a path: it's in {node.name}, which isn't reachable from the internet."]
    if node.kind is NodeKind.WORKLOAD and sure is Confidence.LOW:
        return [f"In {node.name}. {_LOW}"]
    reached = "reached from the handler" in detail
    where = f"It's reachable at {node.name}" + (f" ({detail.split(', ', 1)[1]})." if reached else ".")
    return [
        f"Not on a path. {where}",
        f"From there a {cls.value.replace('_', ' ')} doesn't lead to a high-value asset: nothing it would "
        "control reaches one. Mark a store as a crown jewel if one is missing.",
    ]
