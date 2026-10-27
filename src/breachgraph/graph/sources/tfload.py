"""Load every Terraform `resource`/`data` block in the repo once, for all cloud providers."""

from __future__ import annotations

import io
import posixpath
import re
from dataclasses import dataclass
from typing import Any

import hcl2

from breachgraph.graph.model import Evidence
from breachgraph.graph.sources.common import SourceContext, line_of
from breachgraph.graph.sources.hcl import blocks
from breachgraph.paths import normalize_path

# A reference plus the attribute path after it: azurerm_linux_virtual_machine.vm.identity[0].principal_id
_ATTR_REF_RE = re.compile(
    r"\b((?:data\.)?(?:aws|azurerm|google)_[a-z0-9_]+\.[A-Za-z0-9_-]+)((?:\[[^\]]*\]|\.[A-Za-z0-9_]+)*)"
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


_BLOCK_HEADER = re.compile(r'^(resource|data)\s+"([^"]+)"\s+"([^"]+)"', re.M)
_TOP_LEVEL = re.compile(r"^[A-Za-z_][\w-]*(?:\s+\"[^\"]*\")*\s*\{", re.M)


def _parse(text: str) -> dict[str, Any] | None:
    try:
        doc: dict[str, Any] = hcl2.load(io.StringIO(text))
        return doc
    except Exception:  # hcl2 raises lark errors of many types
        return None


def _blocks_of(text: str) -> list[tuple[str, str, str, dict[str, Any]]]:
    """(section, type, name, body) of every resource/data block. Parses the whole file, and falls
    back to one block at a time so a single construct python-hcl2 rejects can't hide the rest."""
    found: list[tuple[str, str, str, dict[str, Any]]] = []
    doc = _parse(text)
    if doc is not None:
        for section in ("resource", "data"):
            found += [(section, t, n, b) for t, n, b in blocks(doc, section)]
        if len(found) >= len(_BLOCK_HEADER.findall(text)):
            return found
    found = []
    lines = text.splitlines()
    for m in _TOP_LEVEL.finditer(text):
        start = text.count("\n", 0, m.start()) + 1
        end = block_end(text, start) or len(lines)
        part = _parse("\n".join(lines[start - 1 : end]))
        if part is None:
            continue
        for section in ("resource", "data"):
            found += [(section, t, n, b) for t, n, b in blocks(part, section)]
    return found


def _load(ctx: SourceContext) -> list[tuple[str, Res]]:
    res: list[tuple[str, Res]] = []
    for path in ctx.files(".tf"):
        raw = ctx.read(path)
        if raw is None:
            continue
        rel = ctx.rel(path)
        # Trailing whitespace is insignificant to Terraform but breaks python-hcl2 on heredoc
        # terminators ("EOF "), which then swallows the rest of the file without an error.
        text = "\n".join(line.rstrip() for line in raw.splitlines())
        found = _blocks_of(text)
        declared = _BLOCK_HEADER.findall(text)
        got = {(sec, t, n) for sec, t, n, _b in found}
        missing = [f"{t}.{n}" for sec, t, n in declared if (sec, t, n) not in got]
        if missing:
            ctx.skipped.append(
                f"{rel}: could not parse {len(missing)} block(s) ({', '.join(missing[:3])}"
                + (", ..." if len(missing) > 3 else "")
                + ")"
            )
        for section, rtype, name, body in found:
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


_ARCHIVE_REF = re.compile(r"data\.archive_file\.([\w-]+)")
_OBJECT_TYPES = (
    "aws_s3_object",
    "aws_s3_bucket_object",
    "azurerm_storage_blob",
    "google_storage_bucket_object",
)


def _local_path(value: Any, tf_dir: str) -> list[str]:
    """Repo-relative candidates for a path written in Terraform (`${path.module}/src`, `./src`)."""
    if not isinstance(value, str):
        return []
    text = value.replace("${path.module}", tf_dir or ".").replace("${path.root}", tf_dir or ".")
    if "${" in text:
        return []
    text = text.strip().removeprefix("./")
    if not text or text.startswith(("/", "s3://", "http")):
        return []
    joined = normalize_path(posixpath.normpath(posixpath.join(tf_dir, text))) if tf_dir else ""
    plain = normalize_path(posixpath.normpath(text))
    return [c for c in dict.fromkeys([joined, plain]) if c and not c.startswith("..")]


def code_paths(res: dict[str, Res], r: Res) -> list[str]:
    """Source paths of the code a serverless function deploys, followed through Terraform:
    data "archive_file" (source_dir / source_file), a local `filename`, and storage objects
    (S3 / Blob / GCS) that upload the archive. Candidates may not exist; callers check."""
    tf_dir = posixpath.dirname(r.ev.path)
    archives = {k: a for k, a in res.items() if k.startswith("data.archive_file.")}
    by_output: dict[str, Res] = {}
    for a in archives.values():
        for cand in _local_path(a.body.get("output_path"), posixpath.dirname(a.ev.path)):
            by_output[cand] = a
    out: list[str] = []

    def from_archive(a: Res) -> None:
        a_dir = posixpath.dirname(a.ev.path)
        out.extend(
            _local_path(a.body.get("source_dir"), a_dir) + _local_path(a.body.get("source_file"), a_dir)
        )

    def visit(value: Any, depth: int) -> None:
        text = value if isinstance(value, str) else repr(value)
        for name in _ARCHIVE_REF.findall(text):
            if f"data.archive_file.{name}" in archives:
                from_archive(archives[f"data.archive_file.{name}"])
        for cand in _local_path(value, tf_dir) if isinstance(value, str) else []:
            if cand in by_output:
                from_archive(by_output[cand])
        if depth == 0:
            return
        for ref, _tail in attr_refs(text):
            obj = res.get(ref)
            if obj is not None and obj.rtype in _OBJECT_TYPES:
                visit(obj.body.get("source"), depth - 1)

    for key in ("filename", "source_dir", "source_file"):
        visit(r.body.get(key), 0)
    visit(r.body, 1)
    return list(dict.fromkeys(out))
