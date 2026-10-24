"""Attach scanner findings to graph nodes and connect code to the workloads that run it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from breachgraph.graph.model import (
    Confidence,
    Edge,
    EdgeKind,
    Evidence,
    Graph,
    Node,
    NodeKind,
    Weakness,
    WeaknessClass,
)
from breachgraph.graph.sources.routes import Route
from breachgraph.models import Category, Finding

CWE_CLASSES: dict[WeaknessClass, set[str]] = {
    WeaknessClass.CODE_EXECUTION: {
        "CWE-77",
        "CWE-78",
        "CWE-94",
        "CWE-95",
        "CWE-502",
        "CWE-917",
        "CWE-1336",
        "CWE-470",
    },
    WeaknessClass.SSRF: {"CWE-918"},
    WeaknessClass.INJECTION_DATA: {"CWE-89", "CWE-943", "CWE-90", "CWE-564"},
    WeaknessClass.FILE_READ: {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-611", "CWE-98"},
    WeaknessClass.AUTH_BYPASS: {"CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-639", "CWE-284"},
    WeaknessClass.CREDENTIAL_EXPOSURE: {"CWE-798", "CWE-259", "CWE-321", "CWE-522"},
}


def weakness_class(f: Finding) -> WeaknessClass | None:
    if f.category is Category.SECRETS:
        return WeaknessClass.CREDENTIAL_EXPOSURE
    if f.category in (Category.SCA, Category.CONTAINER):
        # Only dependency CVEs with real-world exploitation signal open a path.
        e = f.enrichment
        if e.kev or (e.epss is not None and e.epss >= 0.1 and (f.cvss or 0) >= 7.0):
            return WeaknessClass.VULNERABLE_DEPENDENCY
        return None
    for cls, cwes in CWE_CLASSES.items():
        if set(f.cwe) & cwes:
            return cls
    return None


def _weakness(f: Finding, cls: WeaknessClass) -> Weakness:
    return Weakness(
        cls=cls,
        fingerprint=f.fingerprint,
        title=f.title,
        evidence=Evidence(path=f.location.path, line=f.location.start_line, detail=f.rule_id, source=f.tool),
    )


@dataclass
class CodeUnit:
    """A deployable code directory (has a Dockerfile, compose build context or Lambda source)."""

    root: str  # repo-relative dir, "" for repo root
    workloads: list[str]
    confidence: Confidence


def _contains(root: str, path: str) -> bool:
    return root == "" or path == root or path.startswith(root.rstrip("/") + "/")


def code_units(graph: Graph, dockerfile_dirs: list[str], repo_name: str) -> list[CodeUnit]:
    """Map code directories to workloads by image name, with an honest confidence."""
    workloads = list(graph.of_kind(NodeKind.WORKLOAD))
    units: list[CodeUnit] = []
    for d in sorted(set(dockerfile_dirs), key=len, reverse=True):
        dir_name = PurePosixPath(d).name if d else repo_name
        matched: list[str] = []
        for w in workloads:
            raw_images = w.attrs.get("images") or []
            images = [str(i) for i in raw_images] if isinstance(raw_images, list) else []
            for img in images:
                base = img.rsplit("/", 1)[-1].split("@")[0].split(":")[0]
                if base and (
                    base == dir_name or base.endswith("-" + dir_name) or base.startswith(dir_name + "-")
                ):
                    matched.append(w.id)
                    break
        if matched:
            units.append(CodeUnit(d, matched, Confidence.HIGH))
    if not units and len(dockerfile_dirs) == 1 and len(workloads) == 1:
        units.append(CodeUnit(dockerfile_dirs[0], [workloads[0].id], Confidence.MEDIUM))
    return units


def attach(graph: Graph, findings: list[Finding], routes: list[Route], units: list[CodeUnit]) -> None:
    """Route nodes + weaknesses from findings, then the edges that weaknesses unlock."""
    route_nodes: list[tuple[Route, Node, CodeUnit | None]] = []
    for r in routes:
        unit = next((u for u in units if _contains(u.root, r.file)), None)
        node = graph.add_node(
            Node(
                id=f"route:{r.file}:{r.start_line}:{r.label}",
                kind=NodeKind.ROUTE,
                name=r.label,
                attrs={"framework": r.framework, "handler": r.handler, "file": r.file},
                evidence=[
                    Evidence(
                        path=r.file,
                        line=r.start_line,
                        detail=f"{r.framework} handler {r.handler}",
                        source="routes",
                    )
                ],
            )
        )
        route_nodes.append((r, node, unit))
        for wid in unit.workloads if unit else []:
            graph.add_edge(
                Edge(
                    src=wid,
                    dst=node.id,
                    kind=EdgeKind.SERVES,
                    confidence=unit.confidence if unit else Confidence.LOW,
                    evidence=node.evidence,
                )
            )

    for f in findings:
        cls = weakness_class(f)
        if cls is None or f.status.value == "suppressed":
            continue
        loc = f.location
        # 1. code findings inside a route handler
        hit = False
        for r, node, _unit in route_nodes:
            if loc.path == r.file and loc.start_line and r.start_line <= loc.start_line <= r.end_line:
                node.weaknesses.append(_weakness(f, cls))
                hit = True
        if hit:
            continue
        # 2. infrastructure findings inside a Terraform resource that became a node
        for node in graph.nodes.values():
            tf = node.attrs.get("tf_range")
            if (
                isinstance(tf, list)
                and tf[0] == loc.path
                and loc.start_line
                and tf[1]
                and tf[2]
                and tf[1] <= loc.start_line <= tf[2]
            ):
                node.weaknesses.append(_weakness(f, cls))
                hit = True
        if hit:
            continue
        # 3. everything else in a deployable unit belongs to its workloads
        for unit in units:
            if loc.in_repo and _contains(unit.root, loc.path):
                for wid in unit.workloads:
                    graph.nodes[wid].weaknesses.append(_weakness(f, cls))

    _unlock(graph, route_nodes)


def _unlock(graph: Graph, route_nodes: list[tuple[Route, Node, CodeUnit | None]]) -> None:
    """Add the attack edges that a weapon on a route unlocks (each gated by ``requires``).

    Reaching a workload over the network only gives network access. Turning that into control of
    the workload's identity, secrets or databases needs an actual weapon, so every edge added here
    carries a ``requires`` of the weakness class that achieves it.
    """
    adj = graph.out_edges()
    for _r, route, unit in route_nodes:
        for wid in unit.workloads if unit else []:
            w = graph.nodes[wid]
            privilege = adj.get(wid, [])
            graph.add_edge(
                Edge(
                    src=route.id,
                    dst=wid,
                    kind=EdgeKind.COMPROMISES,
                    requires=[WeaknessClass.CODE_EXECUTION],
                    evidence=route.evidence,
                    note="code execution in this handler runs as the workload",
                )
            )
            # Full control (code execution): inherit everything the workload itself can do.
            for e in privilege:
                if e.kind in (EdgeKind.USES_IDENTITY, EdgeKind.MOUNTS, EdgeKind.CONNECTS_TO):
                    graph.add_edge(
                        Edge(
                            src=route.id,
                            dst=e.dst,
                            kind=e.kind,
                            requires=[WeaknessClass.CODE_EXECUTION],
                            evidence=route.evidence,
                            note="inherited by code execution in this workload",
                        )
                    )
                elif e.kind is EdgeKind.RUNS_ON and w.has({WeaknessClass.CONTAINER_ESCAPE}):
                    graph.add_edge(
                        Edge(
                            src=route.id,
                            dst=e.dst,
                            kind=EdgeKind.RUNS_ON,
                            requires=[WeaknessClass.CODE_EXECUTION],
                            evidence=route.evidence,
                            note="code execution + weak container isolation reaches the node",
                        )
                    )
            # SSRF to the cloud metadata/credentials endpoint -> the compute's role.
            if w.has({WeaknessClass.METADATA_REACHABLE}):
                imdsv1 = w.attrs.get("imdsv2") is False or w.attrs.get("host_network") is True
                if w.attrs.get("platform") == "kubernetes":
                    targets = [
                        e.dst for e in adj.get("k8s:host:nodes", []) if e.kind is EdgeKind.USES_IDENTITY
                    ]
                else:
                    targets = [e.dst for e in privilege if e.kind is EdgeKind.USES_IDENTITY]
                for ident in targets:
                    graph.add_edge(
                        Edge(
                            src=route.id,
                            dst=ident,
                            kind=EdgeKind.USES_IDENTITY,
                            requires=[WeaknessClass.SSRF],
                            evidence=route.evidence,
                            confidence=Confidence.HIGH if imdsv1 else Confidence.LOW,
                            note="server-side requests reach the cloud credential endpoint"
                            + ("" if imdsv1 else " (IMDSv2 reduces this risk)"),
                        )
                    )
            # File read -> any mounted secret file.
            for e in privilege:
                if e.kind is EdgeKind.MOUNTS:
                    graph.add_edge(
                        Edge(
                            src=route.id,
                            dst=e.dst,
                            kind=EdgeKind.MOUNTS,
                            requires=[WeaknessClass.FILE_READ],
                            evidence=route.evidence,
                            confidence=Confidence.MEDIUM,
                            note="arbitrary file read exposes mounted secret files",
                        )
                    )
            # SQL/NoSQL injection -> the database this service's identity can reach.
            for e in privilege:
                if e.kind is not EdgeKind.USES_IDENTITY:
                    continue
                for e2 in adj.get(e.dst, []):
                    if e2.kind is EdgeKind.CAN_ACCESS and str(
                        graph.nodes[e2.dst].attrs.get("tf", "")
                    ).startswith(("aws_db", "aws_rds")):
                        graph.add_edge(
                            Edge(
                                src=route.id,
                                dst=e2.dst,
                                kind=EdgeKind.CONNECTS_TO,
                                requires=[WeaknessClass.INJECTION_DATA],
                                evidence=route.evidence,
                                confidence=Confidence.MEDIUM,
                                note="query injection against the database this service uses",
                            )
                        )
    # Exposed workloads whose image/dependencies carry a known-exploited CVE.
    for w in graph.of_kind(NodeKind.WORKLOAD):
        if w.has({WeaknessClass.VULNERABLE_DEPENDENCY}):
            graph.add_edge(
                Edge(
                    src=w.id,
                    dst=w.id,
                    kind=EdgeKind.COMPROMISES,
                    requires=[WeaknessClass.VULNERABLE_DEPENDENCY],
                    confidence=Confidence.MEDIUM,
                    note="exposed service ships a dependency with a known-exploited or likely-exploited CVE "
                    "(reachability of the vulnerable function not yet verified)",
                )
            )
