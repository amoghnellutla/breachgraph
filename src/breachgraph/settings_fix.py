"""Fixes that change a setting, proved by rebuilding the attack graph.

Many attack paths are cheapest to break in configuration: a public bucket, a privileged pod, IMDSv1.
For each resource on a path, every setting below that appears in it becomes a candidate one-token
edit. Each edit, and each deterministic fix from `fix.py`, is applied to a throwaway copy of the
repository and the graph is rebuilt, so a fix states exactly which paths it removes and adds. An
edit that removes nothing is dropped, which also decides which candidates are worth showing.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from breachgraph.config import Config
from breachgraph.fix import Fix
from breachgraph.graph import AttackGraphResult, build_attack_graph
from breachgraph.graph.summary import path_id
from breachgraph.models import Category, Finding, Location, ScanResult, Severity
from breachgraph.paths import iter_files


@dataclass(frozen=True)
class Setting:
    pattern: re.Pattern[str]
    value: str
    summary: str
    note: str


_TF = [
    Setting(
        re.compile(r'(\bacl\s*=\s*)"public-read(?:-write)?"'),
        r'\1"private"',
        "Make the bucket private",
        "Anything that reads this bucket anonymously will stop working.",
    ),
    Setting(
        re.compile(r"(\bpublicly_accessible\s*=\s*)true"),
        r"\1false",
        "Take the database off the internet",
        "Clients outside its network need a VPN, peering or a bastion.",
    ),
    Setting(
        re.compile(r'(\bcontainer_access_type\s*=\s*)"(?:blob|container)"'),
        r'\1"private"',
        "Make the storage container private",
        "Anonymous readers will need a SAS token or a role.",
    ),
    Setting(
        re.compile(r"(\b(?:allow_nested_items_to_be_public|allow_blob_public_access)\s*=\s*)true"),
        r"\1false",
        "Turn off public blob access",
        "Containers that rely on anonymous access will stop serving it.",
    ),
    Setting(
        re.compile(r"(\bpublic_network_access_enabled\s*=\s*)true"),
        r"\1false",
        "Turn off public network access",
        "Clients need a private endpoint or an allowed network.",
    ),
    Setting(
        re.compile(r'(\bhttp_tokens\s*=\s*)"optional"'),
        r'\1"required"',
        "Require IMDSv2",
        "Old SDKs that only speak IMDSv1 need an update.",
    ),
]
_K8S = [
    Setting(
        re.compile(r"(\bprivileged:\s*)true"),
        r"\1false",
        "Stop running the container as privileged",
        "Check that nothing in the container needs host devices.",
    ),
    Setting(
        re.compile(r"(\bhostNetwork:\s*)true"),
        r"\1false",
        "Take the pod off the host network",
        "Check that it doesn't bind a node port directly.",
    ),
    Setting(
        re.compile(r"(\bhostPID:\s*)true"),
        r"\1false",
        "Stop sharing the host's process namespace",
        "Check that it doesn't inspect host processes.",
    ),
    Setting(
        re.compile(r"(\bautomountServiceAccountToken:\s*)true"),
        r"\1false",
        "Stop mounting the service account token",
        "Check that the pod doesn't call the Kubernetes API.",
    ),
]


_PUBLIC_MEMBER = re.compile(r"\"?all(?:Authenticated)?Users\"?", re.I)
_LIST_ENTRY = re.compile(r"\"all(?:Authenticated)?Users\"\s*,\s*|,\s*\"all(?:Authenticated)?Users\"", re.I)


def _spots(ag: AttackGraphResult) -> list[tuple[str, int]]:
    """(file, line) of what each path rests on: the resource behind each node, and the grant or
    setting behind each edge."""
    spots: list[tuple[str, int]] = []
    for path in ag.paths:
        for step in path.steps:
            spots += [(e.path, e.line) for e in step.edge.evidence if e.line]
            for nid in (step.edge.src, step.edge.dst):
                node = ag.graph.nodes[nid]
                tf = node.attrs.get("tf_range")
                if isinstance(tf, list) and len(tf) == 3 and all(tf):
                    spots.append((str(tf[0]), int(tf[1])))
                elif node.evidence and node.evidence[0].line:
                    spots.append((node.evidence[0].path, node.evidence[0].line))
    return list(dict.fromkeys(spots))


def _top_block(lines: list[str], index: int) -> tuple[int, int]:
    """First and last index of the top-level Terraform block holding a line."""
    start = index
    while start > 0 and not re.match(r"(?:resource|data|module)\s", lines[start]):
        start -= 1
    end = index
    while end < len(lines) - 1 and lines[end].rstrip() != "}":
        end += 1
    return start, end


def _inner_block(lines: list[str], index: int) -> tuple[int, int] | None:
    """First and last index of the innermost `{ ... }` holding a line."""
    depth = 0
    start = index
    while start >= 0:
        depth += lines[start].count("}") - lines[start].count("{") if start != index else 0
        if depth < 0:
            break
        start -= 1
    if start < 0:
        return None
    depth = 0
    for end in range(start, len(lines)):
        depth += lines[end].count("{") - lines[end].count("}")
        if depth == 0:
            return start, end
    return None


def _drop_public_grant(lines: list[str], index: int) -> tuple[list[str], str] | None:
    """Remove `allUsers` from a member list, or the block that grants it."""
    line = lines[index]
    if _LIST_ENTRY.search(line):
        return [*lines[:index], _LIST_ENTRY.sub("", line, count=1), *lines[index + 1 :]], "from the list"
    block = _inner_block(lines, index)
    if block is None:
        return None
    first, last = block
    return [*lines[:first], *lines[last + 1 :]], ""


def _fix(rel: str, index: int, text: str, summary: str, note: str) -> Fix:
    return Fix(
        Finding(
            tool="breachgraph",
            rule_id="setting",
            title=summary,
            severity=Severity.MEDIUM,
            category=Category.IAC,
            location=Location(path=rel, start_line=index + 1),
        ),
        files={rel: text},
        summary=f"{summary} ({rel}:{index + 1})",
        notes=[note],
    )


def _edits(rel: str, lines: list[str], first: int, last: int) -> list[tuple[int, Fix]]:
    found: list[tuple[int, Fix]] = []
    for i in range(first, min(last + 1, len(lines))):
        for setting in _TF if rel.endswith(".tf") else _K8S:
            new = setting.pattern.sub(setting.value, lines[i])
            if new != lines[i]:
                text = "\n".join([*lines[:i], new, *lines[i + 1 :]])
                found.append((i, _fix(rel, i, text, setting.summary, setting.note)))
        if rel.endswith(".tf") and _PUBLIC_MEMBER.search(lines[i]):
            dropped = _drop_public_grant(lines, i)
            if dropped:
                note = "Anything that reads this anonymously will need a credential."
                found.append(
                    (
                        i,
                        _fix(
                            rel,
                            i,
                            "\n".join(dropped[0]),
                            f"Remove the public grant {dropped[1]}".strip(),
                            note,
                        ),
                    )
                )
    return found


def candidates(ag: AttackGraphResult, target: Path) -> list[Fix]:
    """One edit per setting or public grant found where a path rests."""
    out: dict[tuple[str, int], Fix] = {}
    for rel, line in _spots(ag):
        path = target / rel
        if not path.is_file() or not rel.endswith((".tf", ".yaml", ".yml")):
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        index = min(line, len(lines)) - 1
        if rel.endswith(".tf"):
            first, last = _top_block(lines, index)
        else:
            first = index
            last = next((i for i in range(index, len(lines)) if lines[i].strip() == "---"), len(lines) - 1)
        for i, fix in _edits(rel, lines, first, last):
            out.setdefault((rel, i), fix)
    return list(out.values())


def _overlay(target: Path, exclude: list[str], dest: Path, files: dict[str, str]) -> None:
    for path, rel in iter_files(target, exclude):
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        if rel in files:
            out.write_text(files[rel], encoding="utf-8")
            continue
        try:
            os.link(path, out)
        except OSError:
            shutil.copy2(path, out)


def _changed_lines(old: str, new: str) -> set[int]:
    out: set[int] = set()
    matcher = difflib.SequenceMatcher(a=old.splitlines(), b=new.splitlines(), autojunk=False)
    for tag, i1, i2, _j1, _j2 in matcher.get_opcodes():
        if tag != "equal":
            out |= set(range(i1 + 1, i2 + 1))
    return out


def _without(findings: list[Finding], fix: Fix, target: Path) -> list[Finding]:
    """The findings left once the fix is in: its own, and any on the lines it changes."""
    gone = {id(fix.finding)}
    for rel, new in fix.files.items():
        lines = _changed_lines((target / rel).read_text(encoding="utf-8", errors="replace"), new)
        gone |= {id(f) for f in findings if f.location.path == rel and f.location.start_line in lines}
    fp = fix.finding.fingerprint
    return [f for f in findings if id(f) not in gone and not (fp and f.fingerprint == fp)]


def prove(fixes: list[Fix], result: ScanResult, target: Path, config: Config) -> list[Fix]:
    """Rebuild the graph with each fix. Sets `removed` and `added`; a fix that removes nothing
    gets a reason instead of its files."""
    before = build_attack_graph(target, result.findings, config)
    ids = {path_id(p) for p in before.paths}
    for fix in fixes:
        if not fix.files:
            continue
        with tempfile.TemporaryDirectory(prefix="breachgraph-fix-") as tmp:
            _overlay(target, config.exclude_paths, Path(tmp), fix.files)
            after = build_attack_graph(Path(tmp), _without(result.findings, fix, target), config)
        now = {path_id(p) for p in after.paths}
        fix.removed, fix.added = len(ids - now), len(now - ids)
        if not fix.removed:
            fix.reason = "rebuilding the graph with this change removed no attack path"
            fix.files = {}
    return fixes


def proved_settings(result: ScanResult, target: Path, config: Config, top: int) -> list[Fix]:
    """Setting edits that are shown to break a path, those that break the most first."""
    ag = build_attack_graph(target, result.findings, config)
    fixes = prove(candidates(ag, target), result, target, config)
    kept = [f for f in fixes if f.files and not f.added]
    return sorted(kept, key=lambda f: -f.removed)[:top]
