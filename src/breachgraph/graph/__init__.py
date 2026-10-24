"""Attack-graph layer: build a code-to-cloud graph and find attack paths to crown-jewel assets."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from breachgraph.config import Config
from breachgraph.graph.correlate import attach, code_units
from breachgraph.graph.model import Graph, Node, NodeKind
from breachgraph.graph.paths import AttackPath, ChokePoint, choke_points, find_paths
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.images import ImageSource
from breachgraph.graph.sources.kubernetes import KubernetesSource
from breachgraph.graph.sources.routes import RouteSource
from breachgraph.graph.sources.terraform import TerraformSource
from breachgraph.models import Finding

__all__ = ["AttackGraphResult", "AttackPath", "ChokePoint", "Graph", "build_attack_graph"]


@dataclass
class AttackGraphResult:
    graph: Graph
    paths: list[AttackPath]
    choke_points: list[ChokePoint]
    skipped: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def has_paths(self) -> bool:
        return bool(self.paths)


def mark_crown_jewels(graph: Graph, config: Config) -> None:
    """Apply user overrides, then a floor: data stores and secrets always have some value."""
    patterns = config.attack_graph.crown_jewels
    for node in graph.nodes.values():
        if node.kind in (NodeKind.DATASTORE, NodeKind.SECRET) and node.value == 0:
            node.value = 6
        for rule in patterns:
            if (rule.kind is None or rule.kind == node.kind.value) and _matches(rule.match, node):
                node.value = rule.value


def _matches(pattern: str, node: Node) -> bool:
    import fnmatch

    hay = f"{node.name} {node.id}".lower()
    return fnmatch.fnmatchcase(hay, f"*{pattern.lower()}*") or pattern.lower() in hay


def build_attack_graph(
    target: Path, findings: list[Finding], config: Config, repo_name: str | None = None
) -> AttackGraphResult:
    ctx = SourceContext(root=target, exclude=config.exclude_paths)
    graph = Graph()

    images = ImageSource()
    images.collect(ctx, graph)
    KubernetesSource().collect(ctx, graph)
    TerraformSource().collect(ctx, graph)
    routes = RouteSource().collect(ctx)

    name = repo_name or PurePosixPath(target.resolve().as_posix()).name
    units = code_units(graph, list(images.dockerfile_dirs), name)
    attach(graph, findings, routes, units)
    mark_crown_jewels(graph, config)

    paths = find_paths(
        graph,
        crown_value=config.attack_graph.crown_value,
        max_depth=config.attack_graph.max_depth,
        max_paths=config.attack_graph.max_paths,
    )
    chokes = choke_points(graph, paths)
    stats = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "routes": len(routes),
        "workloads": sum(1 for _ in graph.of_kind(NodeKind.WORKLOAD)),
        "crown_jewels": sum(1 for n in graph.nodes.values() if n.value >= config.attack_graph.crown_value),
        "paths": len(paths),
    }
    return AttackGraphResult(graph=graph, paths=paths, choke_points=chokes, skipped=ctx.skipped, stats=stats)
