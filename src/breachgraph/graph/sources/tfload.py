"""Load every Terraform `resource`/`data` block in the repo once, for all cloud providers."""

from __future__ import annotations

import io
import re
from dataclasses import dataclass
from typing import Any

import hcl2

from breachgraph.graph.model import Evidence
from breachgraph.graph.sources.common import SourceContext, line_of
from breachgraph.graph.sources.hcl import blocks

# A reference plus the attribute path after it: azurerm_linux_virtual_machine.vm.identity[0].principal_id
_ATTR_REF_RE = re.compile(
    r"\b((?:data\.)?(?:aws|azurerm|google)_[a-z0-9_]+\.[A-Za-z0-9_-]+)((?:\[[^\]]*\]|\.[A-Za-z_][A-Za-z0-9_]*)*)"
)


@dataclass
class Res:
    rtype: str
    name: str
    body: dict[str, Any]
    ev: Evidence
    end_line: int | None = None
    node_id: str | None = None

    @property
    def tf_range(self) -> list[object]:
        return [self.ev.path, self.ev.line, self.end_line]


def load_resources(ctx: SourceContext) -> dict[str, Res]:
    """{"aws_iam_role.web": Res, ...} across all .tf files (later duplicates win; see module_views)."""
    return {key: r for view in module_views(ctx) for key, r in view.items()}


def module_views(ctx: SourceContext) -> list[dict[str, Res]]:
    """The resources each Terraform module (directory) sees, keyed "type.name".

    References resolve within a module, so two modules may both declare `aws_s3_bucket.this`.
    Without such collisions there is one view of everything. With them, each directory gets its
    own resources plus every uniquely named resource elsewhere, so cross-module wildcards still
    see all data stores while same-named blocks don't overwrite each other."""
    entries = _load(ctx)
    dirs: dict[str, dict[str, Res]] = {}
    for key, r in entries:
        dirs.setdefault(r.ev.path.rsplit("/", 1)[0] if "/" in r.ev.path else "", {})[key] = r
    counts: dict[str, int] = {}
    for own in dirs.values():
        for key in own:
            counts[key] = counts.get(key, 0) + 1
    if all(n == 1 for n in counts.values()):
        return [dict(entries)] if entries else []
    shared = {key: r for own in dirs.values() for key, r in own.items() if counts[key] == 1}
    return [{**shared, **own} for own in dirs.values()]


def _load(ctx: SourceContext) -> list[tuple[str, Res]]:
    res: list[tuple[str, Res]] = []
    for path in ctx.files(".tf"):
        text = ctx.read(path)
        if text is None:
            continue
        rel = ctx.rel(path)
        try:
            doc = hcl2.load(io.StringIO(text))
        except Exception:  # hcl2 raises lark errors of many types
            ctx.skipped.append(f"{rel}: could not parse HCL")
            continue
        for section in ("resource", "data"):
            for rtype, name, body in blocks(doc, section):
                key = f"{rtype}.{name}" if section == "resource" else f"data.{rtype}.{name}"
                start = line_of(text, f'{section} "{rtype}" "{name}"')
                ev = Evidence(path=rel, line=start, detail=key, source="terraform")
                res.append((key, Res(rtype, name, body, ev, end_line=block_end(text, start))))
    return res


def attr_refs(value: Any) -> list[tuple[str, str]]:
    """[(reference, attribute path)] in a value.

    e.g. ("azurerm_user_assigned_identity.app", ".principal_id")
    """
    text = value if isinstance(value, str) else repr(value)
    return [(m.group(1), m.group(2)) for m in _ATTR_REF_RE.finditer(text)]


def list_of(v: Any) -> list[str]:
    if v is None:
        return []
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def list_blocks(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    return [x for x in items if isinstance(x, dict)]


def first_block(value: Any) -> dict[str, Any]:
    found = list_blocks(value)
    return found[0] if found else {}


def block_end(text: str, start: int | None) -> int | None:
    """Line where the block starting at ``start`` closes (brace matching, strings ignored)."""
    if not start:
        return None
    lines = text.splitlines()
    depth, seen = 0, False
    for i in range(start - 1, len(lines)):
        stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', lines[i])
        depth += stripped.count("{") - stripped.count("}")
        seen = seen or "{" in stripped
        if seen and depth <= 0:
            return i + 1
    return None
