"""Semgrep (SAST). Parses `semgrep scan --json` output.

One run over a large monorepo can outlast the time limit and leave nothing. Past LARGE_REPO source
files, test code is left out (the attack graph ignores it anyway) and the rest runs in batches,
server code first. Rules look at one file at a time, so batching loses nothing, and a batch that
runs out of time costs only what was left.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, cast

from breachgraph.config import SemgrepConfig
from breachgraph.graph.model import not_run
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.paths import iter_files
from breachgraph.scanners._util import first_sentence, read_snippet, simple_dir_excludes
from breachgraph.scanners.base import ScanContext, Scanner, Step, as_list

_CONFIDENCE = {c.value: c for c in Confidence}
LARGE_REPO = 4000
BATCH = 1500
_SOURCE = re.compile(r"\.(?:py|js|jsx|mjs|cjs|ts|tsx|vue|java|kt|go|rb|php|cs|rs|scala|c|cc|cpp|h)$", re.I)
_SKIP = re.compile(
    r"\.min\.js$|\.d\.ts$|(?:^|/)(?:__snapshots__|cassettes|generated|vendor|third_party)/", re.I
)
_SERVER = re.compile(
    r"(?:^|/)(?:api|server|backend|routes?|controllers?|services?|handlers?|cli|core|cmd)/", re.I
)
_CLIENT = re.compile(r"(?:^|/)(?:frontend|web|ui|editor-ui|client|components|design-system|apps?/web)/", re.I)


def batches(files: list[str]) -> list[list[str]]:
    """Source files worth a look in a large repository, server code first; [] if it isn't large."""
    source = [f for f in files if _SOURCE.search(f)]
    if len(source) <= LARGE_REPO:
        return []
    keep = [f for f in source if not not_run(f) and not _SKIP.search(f)]
    keep.sort(key=lambda f: (not _SERVER.search(f), bool(_CLIENT.search(f)), f))
    return [keep[i : i + BATCH] for i in range(0, len(keep), BATCH)]


class SemgrepScanner(Scanner):
    name: ClassVar[str] = "semgrep"
    binary: ClassVar[str] = "semgrep"
    partial_results: ClassVar[bool] = True

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        settings = cast(SemgrepConfig, self.settings(ctx.config))
        out = ctx.work_dir / "semgrep.json"
        cmd = [
            exe,
            "scan",
            "--json",
            "--output",
            str(out),
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
        ]
        for rules in settings.config:
            cmd += ["--config", rules]
        for name in simple_dir_excludes(ctx.config.exclude_paths):
            cmd += ["--exclude", name]
        cmd += settings.extra_args
        groups = (
            []
            if ctx.files is not None
            else batches([r for _, r in iter_files(ctx.target, ctx.config.exclude_paths)])
        )
        if groups:
            steps = []
            for i, group in enumerate(groups):
                part = ctx.work_dir / f"semgrep-{i}.json"
                command = [part.as_posix() if c == str(out) else c for c in cmd]
                steps.append(Step([*command, *group], part))
            return steps
        return [Step([*cmd, *(ctx.files if ctx.files is not None else ["."])], out)]

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []
        for r in raw.get("results", []):
            if ".compatibility." in r["check_id"]:
                continue  # "this needs Python 3.7" says nothing about security
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            path = r["path"]
            start = r.get("start", {}).get("line")
            end = r.get("end", {}).get("line")
            message = (extra.get("message") or r["check_id"]).strip()
            confidence = _CONFIDENCE.get(str(meta.get("confidence", "")).lower(), Confidence.MEDIUM)
            severity = Severity.parse(extra.get("severity"))
            # Semgrep's ERROR covers everything from "bad" to "critical"; use impact/likelihood
            # metadata (present on registry security rules) to find the critical ones.
            if (
                severity is Severity.HIGH
                and str(meta.get("impact", "")).upper() == "HIGH"
                and str(meta.get("likelihood", "")).upper() == "HIGH"
                and confidence is Confidence.HIGH
            ):
                severity = Severity.CRITICAL
            refs = [str(u) for u in as_list(meta.get("references"))]
            for key in ("source", "shortlink", "source-rule-url"):
                if isinstance(meta.get(key), str) and meta[key] not in refs:
                    refs.append(meta[key])
            fix = extra.get("fix")
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=r["check_id"],
                    title=first_sentence(message),
                    description=message,
                    severity=severity,
                    category=Category.CICD
                    if str(r["check_id"]).startswith("yaml.github-actions.")
                    else Category.SAST,
                    confidence=confidence,
                    location=Location(
                        path=path,
                        start_line=start,
                        end_line=end,
                        snippet=read_snippet(ctx.target, path, start, end),
                    ),
                    cwe=[str(c) for c in as_list(meta.get("cwe"))],
                    owasp=[str(o) for o in as_list(meta.get("owasp"))],
                    remediation=f"Suggested fix:\n{fix}" if fix else None,
                    references=refs,
                )
            )
        return findings
