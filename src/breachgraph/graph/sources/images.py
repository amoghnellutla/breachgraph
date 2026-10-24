"""Find deployable code units: Dockerfile directories and docker-compose build contexts.

Used to map source directories to the images (and therefore the workloads) that ship them.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

import yaml

from breachgraph.graph.model import Evidence, Graph, Node, NodeKind
from breachgraph.graph.sources.common import SourceContext


class ImageSource:
    name = "images"

    def __init__(self) -> None:
        # repo-relative build-context dir -> image name declared for it (compose), if any
        self.dockerfile_dirs: dict[str, str | None] = {}

    def collect(self, ctx: SourceContext, graph: Graph) -> None:
        for path in ctx.root.rglob("*"):
            if not path.is_file():
                continue
            rel = ctx.rel(path)
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
                        },
                        evidence=[Evidence(path=rel, detail=f"service {svc}", source="images")],
                    )
                )
                if exposed:
                    node.attrs["published_ports"] = exposed


def _join(base: str, rel: str) -> str:
    p = PurePosixPath(base) / rel if base else PurePosixPath(rel)
    return str(p).replace("./", "").strip("/")


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
