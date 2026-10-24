"""Import-level reachability for dependency findings.

For each dependency CVE, decide whether first-party code actually uses the package, and whether
the code that uses it is reachable from an HTTP entry point. This is deliberately *import-level*,
not a full call graph: it cheaply removes the large tail of transitive CVEs the app never calls,
without pretending to prove exploitability of a specific function.
"""

from __future__ import annotations

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.routes import RouteSource
from breachgraph.models import Category, Finding, Reachability
from breachgraph.reachability.imports import ImportIndex, collect_imports

# PyPI distribution name -> import name, where they differ (common cases).
_PY_IMPORT_ALIASES = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "pil",
    "python-dateutil": "dateutil",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "msgpack-python": "msgpack",
    "protobuf": "google",
    "pycryptodome": "crypto",
    "pyjwt": "jwt",
    "python-jose": "jose",
    "setuptools": "setuptools",
    "attrs": "attr",
    "typing-extensions": "typing_extensions",
}
_ANALYZED_ECOSYSTEMS = {
    "pip",
    "python",
    "npm",
    "yarn",
    "node-pkg",
    "gomod",
    "go",
    "pom",
    "gradle",
    "jar",
    "maven",
}


def _py_candidates(name: str) -> set[str]:
    low = name.lower()
    base = {low, low.replace("-", "_"), _PY_IMPORT_ALIASES.get(low, low)}
    if low.startswith("python-"):
        base.add(low[len("python-") :])
    return {b for b in base if b}


def import_candidates(name: str, ecosystem: str | None) -> tuple[str, set[str]]:
    """(language, candidate import tokens) for matching against collected imports."""
    eco = (ecosystem or "").lower()
    if eco in ("npm", "yarn", "node-pkg"):
        return "js", {name.lower()}
    if eco in ("gomod", "go"):
        return "go", {name}  # go import path == module path
    if eco in ("pom", "gradle", "jar", "maven"):
        # Trivy PkgName is "group:artifact"; code imports start with the group id.
        group = name.split(":")[0]
        return "java", {group, ".".join(group.split(".")[:2])}
    if eco in ("pip", "python", "poetry", "pipenv") or not eco:
        return "python", _py_candidates(name)
    return "", set()


def _reachable_modules(index: ImportIndex, route_files: set[str]) -> set[str]:
    """First-party files reachable from a route file by following local imports (BFS)."""
    # Map a local-import target (path without extension) to the real file(s) that provide it.
    providers: dict[str, set[str]] = {}
    for path in index.files:
        stem = path.rsplit(".", 1)[0]
        for key in (stem, stem.removesuffix("/index"), stem.removesuffix("/__init__")):
            providers.setdefault(key, set()).add(path)

    reachable = set(route_files)
    queue = list(route_files)
    while queue:
        current = queue.pop()
        fi = index.files.get(current)
        if fi is None:
            continue
        for target in fi.local:
            for prov in providers.get(target, set()) | providers.get(target.rstrip("/"), set()):
                if prov not in reachable:
                    reachable.add(prov)
                    queue.append(prov)
    return reachable


def annotate_reachability(target: Path, findings: list[Finding], config: Config) -> dict[str, int]:
    """Set ``finding.package.reachability`` in place. Returns a small stats dict."""
    deps = [f for f in findings if f.category in (Category.SCA, Category.CONTAINER) and f.package]
    if not deps:
        return {}
    ctx = SourceContext(root=target, exclude=config.exclude_paths)
    index = collect_imports(ctx)
    if not index.files:  # nothing we can analyze (e.g. a container-only scan)
        for f in deps:
            if f.package is not None:
                f.package.reachability = Reachability.UNKNOWN
        return {"unknown": len(deps)}

    langs_present = {fi.lang for fi in index.files.values()}
    ext_to_files = index.external_to_files()
    routes = RouteSource().collect(ctx)
    reachable_files = _reachable_modules(index, {r.file for r in routes})

    stats: dict[str, int] = {}
    for f in deps:
        pkg = f.package
        if pkg is None:
            continue
        lang, cands = import_candidates(pkg.name, pkg.ecosystem)
        if not cands or lang not in langs_present:
            pkg.reachability = Reachability.UNKNOWN
        else:
            hit_files: set[str] = set()
            for c in cands:
                hit_files |= _match(ext_to_files, c, lang)
            if not hit_files:
                pkg.reachability = Reachability.UNUSED
            elif hit_files & reachable_files:
                pkg.reachability = Reachability.ENTRYPOINT
                sample = sorted(hit_files & reachable_files)[:3]
                pkg.reach_evidence = [f"imported by {p} (reachable from a route)" for p in sample]
            else:
                pkg.reachability = Reachability.DIRECT
                pkg.reach_evidence = [f"imported by {p}" for p in sorted(hit_files)[:3]]
        stats[pkg.reachability.value] = stats.get(pkg.reachability.value, 0) + 1
    return stats


def _match(ext_to_files: dict[str, set[str]], candidate: str, lang: str) -> set[str]:
    if candidate in ext_to_files:
        return ext_to_files[candidate]
    if lang == "go":  # a CVE may name a module; code may import a subpackage of it
        out: set[str] = set()
        for name, files in ext_to_files.items():
            if name == candidate or name.startswith(candidate + "/"):
                out |= files
        return out
    if lang == "java":  # match by group-id prefix
        out = set()
        for name, files in ext_to_files.items():
            if name == candidate or name.startswith(candidate + "."):
                out |= files
        return out
    return set()
