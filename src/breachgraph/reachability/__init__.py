"""Import-level reachability for dependency findings.

For each dependency CVE, decide whether first-party code actually uses the package, and whether
the code that uses it is reachable from an HTTP entry point. This is deliberately *import-level*,
not a full call graph: it cheaply removes the large tail of transitive CVEs the app never calls,
without pretending to prove exploitability of a specific function.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.routes import RouteSource
from breachgraph.models import Category, Finding, Package, Reachability
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
                _not_imported(pkg, f, target, ext_to_files, reachable_files, lang)
            elif hit_files & reachable_files:
                pkg.reachability = Reachability.ENTRYPOINT
                sample = sorted(hit_files & reachable_files)[:3]
                pkg.reach_evidence = [f"imported by {p} (reachable from a route)" for p in sample]
            else:
                pkg.reachability = Reachability.DIRECT
                pkg.reach_evidence = [f"imported by {p}" for p in sorted(hit_files)[:3]]
        state = (pkg.reachability or Reachability.UNKNOWN).value
        stats[state] = stats.get(state, 0) + 1
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


def _not_imported(
    pkg: Package,
    f: Finding,
    target: Path,
    ext_to_files: dict[str, set[str]],
    reachable_files: set[str],
    lang: str,
) -> None:
    """First-party code doesn't import the package. It is still used when a package that *is*
    imported depends on it (Jinja2 under Flask), so "unused" needs a dependency graph to say so."""
    parents = list(pkg.dependents)
    graph_known = pkg.dependency_graph
    via = _pip_via(target / f.location.path) if lang == "python" and f.location.in_repo else None
    if via is not None:
        graph_known = True
        parents = sorted(set(parents) | _ancestors(via, _norm(pkg.name)))
    for parent in parents:
        _plang, cands = import_candidates(parent, pkg.ecosystem)
        hits: set[str] = set()
        for c in cands:
            hits |= _match(ext_to_files, c, lang)
        if hits:
            near = sorted(hits & reachable_files)
            pkg.reachability = Reachability.ENTRYPOINT if near else Reachability.DIRECT
            where = near[0] + " (reachable from a route)" if near else sorted(hits)[0]
            pkg.reach_evidence = [f"used through {parent}, which is imported by {where}"]
            return
    if graph_known:
        pkg.reachability = Reachability.UNUSED
        pkg.reach_evidence = ["not imported by first-party code or by any package it uses"]
    else:
        pkg.reachability = Reachability.UNKNOWN
        pkg.reach_evidence = [
            "not imported by first-party code, but the manifest has no dependency graph (no lockfile), "
            "so another dependency may still use it"
        ]


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==")


@lru_cache(maxsize=64)
def _pip_via(path: Path) -> dict[str, set[str]] | None:
    """{package: packages that require it} from pip-compile / uv `# via` annotations; None when the
    file has none (a hand-written requirements file says nothing about who needs what)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not any(re.search(r"#\s*via(?![\w-])", ln) for ln in lines):
        return None
    out: dict[str, set[str]] = {}
    current: str | None = None
    for line in lines:
        m = _REQ_LINE.match(line.strip())
        if m:
            current = _norm(m.group(1))
            out.setdefault(current, set())
        comment = line.split("#", 1)[1].strip() if "#" in line else ""
        if current is None or not comment:
            continue
        names = comment.removeprefix("via").strip() if comment.startswith("via") else comment
        for name in re.split(r"[\s,]+", names):
            if name and not name.startswith(("-", "(")) and not name.endswith((".in", ".txt", ".toml")):
                out[current].add(_norm(name))
    return out


def _ancestors(via: dict[str, set[str]], name: str) -> set[str]:
    seen: set[str] = set()
    queue = [name]
    while queue:
        for parent in via.get(queue.pop(), set()):
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)
    return seen
