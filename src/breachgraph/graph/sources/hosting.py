"""Applications deployed to hosting platforms: Vercel, Netlify, Render, Fly.io, Heroku-style
Procfiles and Google App Engine.

A platform's own configuration says whether the app is served on a public URL, so a repository
with no Terraform or Kubernetes still gets a real entry point, with evidence, instead of the
medium-confidence "assumed internet-facing" application. Each service becomes a workload whose
code is the directory the platform builds from; services the platform does not expose (Render
private services and workers, Fly apps without an HTTP service) are workloads with no way in.
"""

from __future__ import annotations

import json
import posixpath
import re
import tomllib

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

_FILES = {"vercel.json", "netlify.toml", "render.yaml", "fly.toml", "procfile", "app.yaml"}


class HostingSource:
    name = "hosting"

    def collect(self, ctx: SourceContext, graph: Graph) -> None:
        for path, rel in iter_files(ctx.root, ctx.exclude):
            if path.name.lower() not in _FILES or path.stat().st_size > 512_000:
                continue
            text = ctx.read(path)
            if text is None:
                continue
            base = posixpath.dirname(rel)
            try:
                for svc in _parse(path.name.lower(), text, base):
                    _add(graph, rel, *svc)
            except (ValueError, yaml.YAMLError, tomllib.TOMLDecodeError):
                ctx.skipped.append(f"{rel}: could not be parsed")


# (platform, service name, code directory, public, confidence, detail)
Service = tuple[str, str, str, bool, Confidence, str]


def _parse(name: str, text: str, base: str) -> list[Service]:
    folder = posixpath.basename(base) or "app"
    if name == "vercel.json":
        json.loads(text)  # valid config, otherwise not a deployment
        return [("vercel", folder, base, True, Confidence.HIGH, "Vercel serves the project on a public URL")]
    if name == "netlify.toml":
        doc = tomllib.loads(text)
        build = doc.get("build") or {}
        code = _dir(base, build.get("base"))
        return [("netlify", folder, code, True, Confidence.HIGH, "Netlify serves the site on a public URL")]
    if name == "render.yaml":
        doc = yaml.safe_load(text) or {}
        out: list[Service] = []
        for svc in doc.get("services") or [] if isinstance(doc, dict) else []:
            if not isinstance(svc, dict) or not svc.get("name"):
                continue
            public = svc.get("type") == "web"
            code = _dir(base, svc.get("rootDir"))
            detail = (
                "Render web service (public URL)" if public else f"Render {svc.get('type')} service (private)"
            )
            out.append(("render", str(svc["name"]), code, public, Confidence.HIGH, detail))
        return out
    if name == "fly.toml":
        doc = tomllib.loads(text)
        services = doc.get("services") or []
        public = bool(doc.get("http_service")) or any(
            isinstance(s, dict) and s.get("ports") for s in services if isinstance(services, list)
        )
        detail = "Fly.io app with a public HTTP service" if public else "Fly.io app without public services"
        return [("fly", str(doc.get("app") or folder), base, public, Confidence.HIGH, detail)]
    if name == "procfile":
        if re.search(r"^web\s*:", text, re.M):
            return [
                (
                    "procfile",
                    folder,
                    base,
                    True,
                    Confidence.MEDIUM,
                    "Procfile web process (Heroku-style platforms serve it publicly)",
                )
            ]
        return []
    if name == "app.yaml":
        doc = yaml.safe_load(text)
        if isinstance(doc, dict) and "runtime" in doc and "apiVersion" not in doc and "kind" not in doc:
            return [
                (
                    "app-engine",
                    str(doc.get("service") or folder),
                    base,
                    True,
                    Confidence.HIGH,
                    "App Engine service (public by default)",
                )
            ]
        return []
    return []


def _dir(base: str, sub: object) -> str:
    """A directory relative to the repository root ("" for the root itself)."""
    joined = posixpath.normpath(posixpath.join(base, str(sub or ".")))
    return "" if joined == "." else joined


def _add(
    graph: Graph, rel: str, platform: str, name: str, code: str, public: bool, conf: Confidence, detail: str
) -> None:
    ev = Evidence(path=rel, detail=detail, source="hosting")
    node = graph.add_node(
        Node(
            id=f"hosting:{platform}:{name}",
            kind=NodeKind.WORKLOAD,
            name=f"{_LABEL[platform]} {name}",
            attrs={"platform": platform, "code_paths": [code]},
            evidence=[ev],
        )
    )
    if public:
        graph.add_node(internet())
        graph.add_edge(
            Edge(
                src=INTERNET_ID,
                dst=node.id,
                kind=EdgeKind.EXPOSES,
                confidence=conf,
                evidence=[ev],
                note=detail,
            )
        )


_LABEL: dict[str, str] = {
    "vercel": "Vercel project",
    "netlify": "Netlify site",
    "render": "Render service",
    "fly": "Fly.io app",
    "procfile": "Procfile app",
    "app-engine": "App Engine service",
}
