"""Terraform inputs: `var.x` and `local.y` as far as the repository says what they are.

Real infrastructure names almost everything through variables. Resolving them here, before any cloud
source runs, means `function_name = var.name` compares like a literal. Values come from a variable's
default, then `terraform.tfvars` and `*.auto.tfvars`, then what a local `module` block passes in. An
expression this can't evaluate stays as it was, so the sources treat it as unknown, as they always
have. A remote module's source isn't in the repository, so it is reported as a blind spot.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.hcl import unquote
from breachgraph.paths import iter_files

_ONE = re.compile(r"^\$\{\s*((?:var|local)\.[\w-]+)\s*\}$")
_INNER = re.compile(r"\$\{\s*((?:var|local)\.[\w-]+)\s*\}")
_LOCAL_SOURCE = re.compile(r"^\.\.?/")


def substitute(value: Any, env: dict[str, Any]) -> Any:
    """`value` with every reference `env` knows filled in. A whole-string reference keeps its type."""
    if isinstance(value, dict):
        return {k: substitute(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, env) for v in value]
    if not isinstance(value, str):
        return value
    whole = _ONE.match(value)
    if whole:
        return env.get(whole.group(1), value)

    def scalar(m: re.Match[str]) -> str:
        found = env.get(m.group(1))
        return str(found) if isinstance(found, str | int | float) else m.group(0)

    return _INNER.sub(scalar, value)


def _settle(env: dict[str, Any]) -> dict[str, Any]:
    """Locals can name variables and other locals."""
    for _ in range(4):
        env = {k: substitute(v, env) for k, v in env.items()}
    return env


def _directory(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """A parsed file's defaults and locals, and its module blocks."""
    env: dict[str, Any] = {}
    modules: dict[str, dict[str, Any]] = {}
    for entry in doc.get("variable") or []:
        for name, body in unquote(entry).items():
            if isinstance(body, dict) and body.get("default") is not None:
                env[f"var.{name}"] = body["default"]
    for entry in doc.get("locals") or []:
        for name, value in unquote(entry).items():
            env[f"local.{name}"] = value
    for entry in doc.get("module") or []:
        for name, body in unquote(entry).items():
            if isinstance(body, dict):
                modules[name] = body
    return env, modules


def directory_inputs(ctx: SourceContext, parse: Any) -> dict[str, dict[str, Any]]:
    """{directory: {"var.x": value, "local.y": value}}, with module arguments applied."""
    found: dict[str, dict[str, Any]] = {}
    calls: list[tuple[str, str, dict[str, Any]]] = []
    tfvars: dict[str, dict[str, Any]] = {}
    for path, rel in iter_files(ctx.root, ctx.exclude):
        folder = posixpath.dirname(rel)
        if rel.endswith(".tf"):
            doc = parse("\n".join(line.rstrip() for line in (ctx.read(path) or "").splitlines()))
            env, modules = _directory(doc or {})
            found.setdefault(folder, {}).update(env)
            calls += [(folder, name, body) for name, body in modules.items()]
        elif path.name == "terraform.tfvars" or path.name.endswith(".auto.tfvars"):
            doc = parse(ctx.read(path) or "") or {}
            tfvars.setdefault(folder, {}).update({f"var.{k}": v for k, v in unquote(doc).items()})
    for folder, values in tfvars.items():
        found.setdefault(folder, {}).update(values)
    settled = {folder: _settle(env) for folder, env in found.items()}
    remote: set[str] = set()
    for folder, name, body in sorted(calls, key=lambda c: c[0].count("/")):  # outermost first
        source = str(body.get("source") or "")
        if not _LOCAL_SOURCE.match(source):
            remote.add(f"{folder or '.'}: module {name} comes from {source}, which isn't in the repository")
            continue
        child = posixpath.normpath(posixpath.join(folder, source))
        given = {f"var.{k}": substitute(v, settled.get(folder, {})) for k, v in body.items()}
        settled[child] = _settle({**settled.get(child, {}), **given})
    ctx.skipped.extend(sorted(remote))
    return settled
