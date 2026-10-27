"""Incremental scans for pull requests: rescan what changed, reuse the base report for the rest.

Every report records a digest of each file in the scanned tree. A pull request compared with the
default branch's report (--compare) then knows exactly which files changed, without needing git
history (CI checkouts are usually shallow):

- Semgrep runs on the changed files only; Checkov on the changed infrastructure files only.
- Trivy, Gitleaks and zizmor run in full when a file they read changed, and are skipped otherwise.
- The built-in CI/CD checks always run (they take milliseconds).
- Findings for unchanged files come from the base report. The attack graph is always rebuilt
  from the whole tree, so paths that cross changed and unchanged files are found.

Any doubt means a full scan: no base report, a base without digests, a different breachgraph
version, or different scanner settings.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from breachgraph.config import Config
from breachgraph.models import Finding, ScanResult, Status
from breachgraph.paths import iter_files

Mode = Literal["full", "files", "carry"]
_BIG = 5_000_000
# Files each scanner reads, for deciding whether a change concerns it.
_IAC = re.compile(
    r"(\.tf|\.tfvars|\.ya?ml|\.json|\.bicep|\.template)$|(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile)$", re.I
)
_TRIVY = re.compile(
    r"(^|/)(requirements[^/]*\.txt|Pipfile(\.lock)?|poetry\.lock|uv\.lock|pyproject\.toml|package(-lock)?\.json"
    r"|yarn\.lock|pnpm-lock\.yaml|go\.(mod|sum)|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|Gemfile(\.lock)?"
    r"|composer\.(json|lock)|Cargo\.(toml|lock)|packages\.lock\.json|[^/]*\.csproj)$",
    re.I,
)
_WORKFLOWS = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|action\.ya?ml)$")


def tree_digest(target: Path, exclude: list[str]) -> dict[str, str]:
    """{repo-relative path: short content digest} for every file breachgraph would scan."""
    out: dict[str, str] = {}
    for path, rel in iter_files(target, exclude):
        try:
            size = path.stat().st_size
            out[rel] = f"size:{size}" if size > _BIG else hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        except OSError:
            continue
    return out


def scanner_fingerprint(config: Config) -> str:
    """Changes when anything that decides scanner output changes."""
    data = {"scanners": config.scanners.model_dump(mode="json"), "exclude": sorted(config.exclude_paths)}
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


@dataclass
class Plan:
    changed: set[str] = field(default_factory=set)  # added or modified
    deleted: set[str] = field(default_factory=set)
    modes: dict[str, Mode] = field(default_factory=dict)
    files: dict[str, list[str]] = field(default_factory=dict)  # scanner -> files for mode "files"
    reason: str = ""  # why the scan is full, when it is


def plan(
    base: ScanResult | None, tree: dict[str, str], config: Config, version: str, names: list[str]
) -> Plan:
    full = Plan(modes={n: "full" for n in names})
    if base is None:
        full.reason = "no base report"
        return full
    base_tree = base.metadata.get("tree")
    if not isinstance(base_tree, dict):
        full.reason = "the base report has no file digests (made by an older version)"
        return full
    if base.breachgraph_version != version:
        full.reason = f"the base report is from breachgraph {base.breachgraph_version}"
        return full
    if base.metadata.get("scanner_fingerprint") != scanner_fingerprint(config):
        full.reason = "scanner settings differ from the base report"
        return full
    changed = {p for p, d in tree.items() if base_tree.get(p) != d}
    deleted = {p for p in base_tree if p not in tree}
    out = Plan(changed=changed, deleted=deleted)
    touched = changed | deleted
    for name in names:
        if name == "cicd":
            out.modes[name] = "full"
        elif name == "semgrep":
            _files_or_carry(out, name, sorted(changed))
        elif name == "checkov":
            _files_or_carry(out, name, sorted(p for p in changed if _IAC.search(p)))
        elif name == "trivy":
            out.modes[name] = "full" if any(_TRIVY.search(p) or _IAC.search(p) for p in touched) else "carry"
        elif name == "zizmor":
            out.modes[name] = "full" if any(_WORKFLOWS.search(p) for p in touched) else "carry"
        else:  # gitleaks and anything new: whole-tree tools, rerun when anything changed
            out.modes[name] = "full" if touched else "carry"
    return out


def _files_or_carry(out: Plan, name: str, files: list[str]) -> None:
    if not files:
        out.modes[name] = "carry"
    elif len(files) > 400:  # a big change: a full run is simpler and not much slower
        out.modes[name] = "full"
    else:
        out.modes[name], out.files[name] = "files", files


def carried(base: ScanResult, p: Plan) -> list[Finding]:
    """Base findings that still stand, each once, by the scanner that produced it: all of a
    scanner's findings when it didn't run, those outside the changed files when it ran on just
    those, none when it ran in full. Identity (tool, rule, location) is kept, so a carried finding
    matches the base and is not new."""
    out = []
    for f in base.findings:
        mode = p.modes.get(f.tool)
        if mode is None or mode == "full":
            continue  # reran in full (or not a scanner this run): its own output stands
        gone = p.changed | p.deleted if mode == "files" else p.deleted
        if f.location.in_repo and f.location.path in gone:
            continue
        g = f.model_copy(deep=True)
        g.status, g.gating, g.ai, g.suppression_reason = Status.NEW, False, None, None
        out.append(g)
    return out
