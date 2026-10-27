"""Find deployable code units: Dockerfile directories and docker-compose build contexts.

Used to map source directories to the images (and therefore the workloads) that ship them.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import PurePosixPath

import yaml

from breachgraph.graph.model import (
    INTERNET_ID,
    Confidence,
    Edge,
    EdgeKind,
    Evidence,
    Graph,
    Node,
    NodeKind,
    internet,
)
from breachgraph.graph.sources.common import SourceContext
from breachgraph.paths import iter_files


class ImageSource:
    name = "images"

    def __init__(self) -> None:
        # repo-relative build-context dir -> image name declared for it (compose), if any
        self.dockerfile_dirs: dict[str, str | None] = {}

    def collect(self, ctx: SourceContext, graph: Graph) -> None:
        for path, rel in iter_files(ctx.root, ctx.exclude):
            name = path.name.lower()
            if name == "dockerfile" or name.startswith("dockerfile."):
                self.dockerfile_dirs.setdefault(str(PurePosixPath(rel).parent).replace(".", ""), None)
            elif name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                self._compose(ctx, path, rel, graph)

    def _compose(self, ctx: SourceContext, path: object, rel: str, graph: Graph) -> None:
        text = ctx.read(path)  # type: ignore[arg-type]
        if not text:
            return
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            ctx.skipped.append(f"{rel}: invalid compose YAML")
            return
        base = str(PurePosixPath(rel).parent).replace(".", "")
        for svc, spec in (doc.get("services") or {}).items() if isinstance(doc, dict) else []:
            if not isinstance(spec, dict):
                continue
            build = spec.get("build")
            context = (
                build
                if isinstance(build, str)
                else (build or {}).get("context")
                if isinstance(build, dict)
                else None
            )
            image = spec.get("image")
            if context:
                ctx_dir = _join(base, str(context))
                self.dockerfile_dirs[ctx_dir] = str(image) if image else None
                exposed = _ports_public(spec.get("ports"))
                node = graph.add_node(
                    Node(
                        id=f"compose:service:{svc}",
                        kind=NodeKind.WORKLOAD,
                        name=f"compose service {svc}",
                        attrs={
                            "platform": "compose",
                            "images": [str(image)] if image else [],
                            "build_context": ctx_dir,
                            "code_paths": [ctx_dir],
                        },
                        evidence=[Evidence(path=rel, detail=f"service {svc}", source="images")],
                    )
                )
                if exposed:
                    node.attrs["published_ports"] = exposed
                    _expose(graph, node.id, f"publishes port {exposed[0]}", rel, svc)
        # A reverse proxy that publishes ports forwards the internet to the services it fronts.
        for svc, spec in (doc.get("services") or {}).items() if isinstance(doc, dict) else []:
            if not isinstance(spec, dict) or spec.get("build") or not _PROXY.search(str(spec.get("image"))):
                continue
            exposed = _ports_public(spec.get("ports"))
            deps = spec.get("depends_on") or []
            for dep in [*deps, *(spec.get("links") or [])]:
                target = f"compose:service:{str(dep).split(':')[0]}"
                if exposed and target in graph.nodes:
                    _expose(graph, target, f"behind proxy {svc} (port {exposed[0]})", rel, svc)


_PROXY = re.compile(r"(?:^|/)(nginx|traefik|caddy|haproxy|envoy|httpd)(?::|$)")


def _expose(graph: Graph, node_id: str, why: str, rel: str, svc: str) -> None:
    graph.add_node(internet())
    graph.add_edge(
        Edge(
            src=INTERNET_ID,
            dst=node_id,
            kind=EdgeKind.EXPOSES,
            confidence=Confidence.MEDIUM,
            evidence=[Evidence(path=rel, detail=f"service {svc}", source="images")],
            note=f"compose {why}; assumed reachable from the internet",
        )
    )


def _join(base: str, rel: str) -> str:
    joined = posixpath.normpath(posixpath.join(base, rel)).strip("/")
    return "" if joined in (".", "..") or joined.startswith("../") else joined


def _ports_public(ports: object) -> list[str]:
    out: list[str] = []
    if not isinstance(ports, list):
        return out
    for p in ports:
        s = str(p.get("published") if isinstance(p, dict) else p)
        m = re.match(r"(?:(\d+\.\d+\.\d+\.\d+):)?(\d+):", s)
        if m and m.group(1) not in ("127.0.0.1", "::1"):
            out.append(s)
    return out
