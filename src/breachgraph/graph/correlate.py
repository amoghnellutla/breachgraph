"""Attach scanner findings to graph nodes and connect code to the workloads that run it."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from breachgraph.cicd import UNTRUSTED_CONTEXT
from breachgraph.graph.callgraph import CallGraph
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
    not_run,
)
from breachgraph.graph.sources.app import APP_ID
from breachgraph.graph.sources.routes import Route
from breachgraph.models import Category, Finding, Reachability

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


# Well-known rules whose CWE doesn't say what they let an attacker do.
RULE_HINTS: list[tuple[str, WeaknessClass]] = [
    ("ssrf", WeaknessClass.SSRF),
    ("dynamic-urllib-use-detected", WeaknessClass.SSRF),  # CWE-939; also file:// reads
    ("server-side-request", WeaknessClass.SSRF),
]


def weakness_class(f: Finding) -> WeaknessClass | None:
    if f.category is Category.SECRETS:
        return WeaknessClass.CREDENTIAL_EXPOSURE
    if f.category in (Category.SCA, Category.CONTAINER):
        # Only dependency CVEs with real-world exploitation signal open a path, and only when the
        # package is actually used (reachability analysis didn't rule it out as unused).
        e = f.enrichment
        exploitable = e.kev or (e.epss is not None and e.epss >= 0.1 and (f.cvss or 0) >= 7.0)
        used = f.package is None or f.package.reachability is not Reachability.UNUSED
        if exploitable and used:
            return WeaknessClass.VULNERABLE_DEPENDENCY
        return None
    for cls, cwes in CWE_CLASSES.items():
        if set(f.cwe) & cwes:
            return cls
    rule = f.rule_id.lower()
    for hint, cls in RULE_HINTS:
        if hint in rule:
            return cls
    return None


def _weakness(f: Finding, cls: WeaknessClass, sure: Confidence = Confidence.HIGH) -> Weakness:
    return Weakness(
        cls=cls,
        confidence=sure,
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


_CI_CONFIG = re.compile(
    r"^(?:\.github/|\.gitlab-ci\.ya?ml$|\.circleci/|azure-pipelines\.ya?ml$|Jenkinsfile$)"
)


def _is_ci_config(path: str) -> bool:
    return bool(_CI_CONFIG.match(path))


def code_units(
    graph: Graph, dockerfile_dirs: list[str], repo_name: str, root: Path | None = None
) -> list[CodeUnit]:
    """Map code directories to workloads, with an honest confidence: the source Terraform deploys
    to a serverless function (exact), then container images matched to Dockerfile directories."""
    workloads = list(graph.of_kind(NodeKind.WORKLOAD))
    units: list[CodeUnit] = []
    deployed: dict[str, list[str]] = {}
    for w in workloads:
        raw = w.attrs.get("code_paths")
        for cp in raw if isinstance(raw, list) else []:
            if root is None or (root / str(cp)).exists():
                deployed.setdefault(str(cp), []).append(w.id)
    for cp in sorted(deployed, key=len, reverse=True):
        units.append(CodeUnit(cp, deployed[cp], Confidence.HIGH))
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


# What a request can trigger: a weakness of these in a helper a handler calls is on that route.
_ROUTE_WEAPONS = {
    WeaknessClass.CODE_EXECUTION,
    WeaknessClass.SSRF,
    WeaknessClass.INJECTION_DATA,
    WeaknessClass.FILE_READ,
    WeaknessClass.AUTH_BYPASS,
}


_MANIFEST_FAMILY = {
    "package-lock.json": "js",
    "package.json": "js",
    "yarn.lock": "js",
    "pnpm-lock.yaml": "js",
    "requirements.txt": "py",
    "poetry.lock": "py",
    "Pipfile.lock": "py",
    "uv.lock": "py",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "java",
    "build.gradle": "java",
}
_SOURCE_FAMILY = {".py": "py", ".go": "go", ".java": "java"}


def _other_language(
    path: str, unit: CodeUnit, route_nodes: list[tuple[Route, Node, CodeUnit | None]]
) -> bool:
    """A dependency of a language none of the service's routes are written in. A frontend's
    package isn't what a Go backend runs, whatever the repository layout."""
    family = _MANIFEST_FAMILY.get(PurePosixPath(path).name)
    served = {
        _SOURCE_FAMILY.get(PurePosixPath(r.file).suffix.lower(), "js")
        for r, _n, u in route_nodes
        if u is unit
    }
    return bool(family and served and family not in served)


def _expands_trusted_text(f: Finding, root: Path) -> bool:
    """A template-injection finding whose line expands nothing an outsider writes: a workflow
    input, a category slug or a repository name."""
    if "template-injection" not in f.rule_id or not f.location.start_line:
        return False
    try:
        lines = (root / f.location.path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    line = lines[f.location.start_line - 1] if f.location.start_line <= len(lines) else ""
    return "${{" in line and not UNTRUSTED_CONTEXT.search(line)


def _called_from_routes(
    f: Finding,
    cls: WeaknessClass,
    route_nodes: list[tuple[Route, Node, CodeUnit | None]],
    calls: CallGraph,
    sure: Confidence,
) -> bool:
    """Attach a weakness in a helper to every route whose handler reaches it, with the chain.
    Returns whether any did."""
    loc = f.location
    if cls not in _ROUTE_WEAPONS or not loc.start_line or not loc.in_repo or not_run(loc.path):
        return False
    linked = False
    if calls._links is None:
        # Nothing deployed behind a route without a unit, so there is nothing to reach.
        calls.link([(r.file, r.start_line, r.end_line) for r, _n, unit in route_nodes if unit])
    served = [(r, node) for r, node, unit in route_nodes if unit]
    for i, chain in sorted(calls.routes_reaching(loc.path, loc.start_line).items()):
        r, node = served[i]
        link = " -> ".join([*([r.handler] if r.handler != "<inline>" else []), *chain])
        weakness = _weakness(f, cls)
        # A parameter rule doesn't show that request data arrives, and a name-only chain doesn't
        # prove the call: together they're a lead to report, not grounds to block a merge.
        lead = sure is Confidence.LOW or f.rule_id.endswith("-parameter")
        weakness.confidence = Confidence.LOW if lead else Confidence.MEDIUM
        weakness.evidence.detail = f"{f.rule_id}, reached from the handler by {link}"
        node.weaknesses.append(weakness)
        linked = True
    return linked


def attach(
    graph: Graph,
    findings: list[Finding],
    routes: list[Route],
    units: list[CodeUnit],
    calls: CallGraph | None = None,
) -> None:
    """Route nodes + weaknesses from findings, then the edges that weaknesses unlock."""
    route_nodes: list[tuple[Route, Node, CodeUnit | None]] = []
    for r in routes:
        unit = next((u for u in units if _contains(u.root, r.file)), None)
        node = graph.add_node(
            Node(
                id=f"route:{r.file}:{r.start_line}:{r.label}",
                kind=NodeKind.ROUTE,
                name=r.label,
                attrs={"framework": r.framework, "handler": r.handler, "file": r.file, "auth": r.auth},
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
        # A sink fed only by literals is still reported, at a confidence that doesn't gate a merge.
        constant = bool(
            calls is not None
            and cls in _ROUTE_WEAPONS
            and loc.start_line
            and calls.constant_input(loc.path, loc.start_line, f.rule_id)
        )
        # A guessed secret (see scanners/gitleaks.py) can't carry a path that gates either.
        guess = f.category is Category.SECRETS and f.confidence.value == "low"
        harmless = calls is not None and _expands_trusted_text(f, calls.root)
        sure = Confidence.LOW if constant or guess or harmless else Confidence.HIGH
        # 1. code findings inside a route handler
        hit = False
        for r, node, _unit in route_nodes:
            if loc.path == r.file and loc.start_line and r.start_line <= loc.start_line <= r.end_line:
                node.weaknesses.append(_weakness(f, cls, sure))
                hit = True
        if hit:
            continue
        # A helper the handler calls: the same weapon, one or more calls away.
        linked = calls is not None and _called_from_routes(f, cls, route_nodes, calls, sure)
        if linked:
            continue  # on its routes; on the workload too it would read as a second way in
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
        # (CI configuration, tests and examples are not part of what a service runs.)
        ci = _is_ci_config(loc.path)
        if not_run(loc.path):
            continue
        for unit in units:
            if loc.in_repo and _contains(unit.root, loc.path):
                # With routes to go on, a weapon none of them reaches (a management command, a
                # build script) isn't shown to be reachable by a request: reported, but no gate.
                served = any(u is unit for _r, _n, u in route_nodes)
                unreached = cls in _ROUTE_WEAPONS and served and calls is not None and not linked
                # The whole-repository stand-in can't say which service ships a dependency.
                guessed = cls is WeaknessClass.VULNERABLE_DEPENDENCY and (
                    APP_ID in unit.workloads or _other_language(loc.path, unit, route_nodes)
                )
                sure_here = Confidence.LOW if unreached or guessed else sure
                for wid in unit.workloads:
                    if ci and graph.nodes[wid].attrs.get("platform") != "github-actions":
                        continue
                    graph.nodes[wid].weaknesses.append(_weakness(f, cls, sure_here))

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
                # A plain GET is enough on IMDSv1 or from the host network. IMDSv2 (AWS) and the
                # Metadata / Metadata-Flavor header (Azure, GCP) need an SSRF that controls headers.
                header = w.attrs.get("metadata_header")
                imdsv1 = (w.attrs.get("imdsv2") is False and not header) or w.attrs.get(
                    "host_network"
                ) is True
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
                            + ("" if imdsv1 else f" ({header or 'IMDSv2'} reduces this risk)"),
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
            # SQL/NoSQL injection -> the database this service connects to directly.
            for e in privilege:
                if e.kind is EdgeKind.CONNECTS_TO and graph.nodes[e.dst].attrs.get("queryable"):
                    graph.add_edge(
                        Edge(
                            src=route.id,
                            dst=e.dst,
                            kind=EdgeKind.CONNECTS_TO,
                            requires=[WeaknessClass.INJECTION_DATA],
                            evidence=route.evidence,
                            confidence=Confidence.MEDIUM,
                            note="query injection against the database this service uses",
                        )
                    )
            # SQL/NoSQL injection -> the database this service's identity can reach.
            for e in privilege:
                if e.kind is not EdgeKind.USES_IDENTITY:
                    continue
                for e2 in adj.get(e.dst, []):
                    if e2.kind is EdgeKind.CAN_ACCESS and graph.nodes[e2.dst].attrs.get("queryable"):
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
    # Query injection in a workload's own code (serverless handlers have no framework routes).
    for w in graph.of_kind(NodeKind.WORKLOAD):
        hits = w.has({WeaknessClass.INJECTION_DATA})
        if not hits:
            continue
        for e in adj.get(w.id, []):
            if e.kind is EdgeKind.CONNECTS_TO and graph.nodes[e.dst].attrs.get("queryable"):
                graph.add_edge(
                    Edge(
                        src=w.id,
                        dst=e.dst,
                        kind=EdgeKind.CONNECTS_TO,
                        requires=[WeaknessClass.INJECTION_DATA],
                        evidence=[hits[0].evidence],
                        confidence=Confidence.MEDIUM,
                        note="query injection against the database this service uses",
                    )
                )
            if e.kind is not EdgeKind.USES_IDENTITY:
                continue
            for e2 in adj.get(e.dst, []):
                if e2.kind is EdgeKind.CAN_ACCESS and graph.nodes[e2.dst].attrs.get("queryable"):
                    graph.add_edge(
                        Edge(
                            src=w.id,
                            dst=e2.dst,
                            kind=EdgeKind.CONNECTS_TO,
                            requires=[WeaknessClass.INJECTION_DATA],
                            evidence=[hits[0].evidence],
                            confidence=Confidence.MEDIUM,
                            note="query injection against the database this service uses",
                        )
                    )
    # SSRF in a workload's own code reaches its metadata/credential endpoint (serverless handlers).
    for w in graph.of_kind(NodeKind.WORKLOAD):
        ssrf = w.has({WeaknessClass.SSRF})
        if (
            not ssrf
            or not w.has({WeaknessClass.METADATA_REACHABLE})
            or w.attrs.get("platform") == "kubernetes"
        ):
            continue
        header = w.attrs.get("metadata_header")
        plain = w.attrs.get("imdsv2") is False and not header
        for e in adj.get(w.id, []):
            if e.kind is EdgeKind.USES_IDENTITY:
                graph.add_edge(
                    Edge(
                        src=w.id,
                        dst=e.dst,
                        kind=EdgeKind.USES_IDENTITY,
                        requires=[WeaknessClass.SSRF],
                        evidence=[ssrf[0].evidence],
                        confidence=Confidence.HIGH if plain else Confidence.LOW,
                        note="server-side requests reach the cloud credential endpoint"
                        + ("" if plain else f" ({header or 'IMDSv2'} reduces this risk)"),
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
