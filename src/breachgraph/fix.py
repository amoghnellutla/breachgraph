"""Deterministic fixes for the findings that break the most attack paths.

Two kinds of finding have a fix that is safe to write without a person or a model in the loop:

- a vulnerable dependency with a fixed version, declared directly in requirements*.txt,
  package.json or go.mod: the declared version is moved to the fixed one;
- a GitHub Actions script injection: each untrusted `${{ ... }}` in the `run:` script moves into
  the step's `env:` and the script reads the variable instead, the fix GitHub itself documents.

Anything else (code vulnerabilities, transitive dependencies, hash-pinned lock files) gets a
reason instead of a guess. Edits are returned as file contents; the CLI shows them as a diff,
writes them, or commits them to a branch and opens a pull request.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import httpx

from breachgraph.cicd import UNTRUSTED_CONTEXT
from breachgraph.models import Category, Finding, ScanResult


@dataclass
class Fix:
    finding: Finding
    files: dict[str, str] = field(default_factory=dict)  # repo-relative path -> new content
    summary: str = ""
    notes: list[str] = field(default_factory=list)
    reason: str = ""  # why no fix was made (files is empty)
    paths_cut: int = 0


def plan(result: ScanResult, target: Path, top: int = 3) -> list[Fix]:
    """Fixes for the top choke points, most paths broken first; falls back to every finding on a
    path when there are fewer choke points than asked for."""
    by_fp = {fp: f for f in result.findings for fp in (f.fingerprints or [f.fingerprint])}
    ag = result.attack_graph
    order: list[tuple[str, int]] = [
        (c.fingerprint, c.paths_cut) for c in (ag.choke_points if ag else []) if c.fingerprint
    ]
    for p in ag.paths if ag else []:
        order += [(fp, 0) for fp in p.weaknesses if fp not in {o[0] for o in order}]
    fixes: list[Fix] = []
    seen: set[str] = set()
    for fp, cut in order:
        f = by_fp.get(fp)
        if f is None or f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        fix = fix_finding(f, target)
        fix.paths_cut = cut
        fixes.append(fix)
        if len(fixes) >= top:
            break
    return fixes


def fix_finding(f: Finding, target: Path) -> Fix:
    if f.category in (Category.SCA, Category.CONTAINER) and f.package:
        return _dependency(f, target)
    workflow = re.match(r"\.github/workflows/[^/]+\.ya?ml$", f.location.path)
    if workflow and re.search(r"(script|shell|template)-injection", f.rule_id):  # any tool's name for it
        return _script_injection(f, target)
    return Fix(f, reason="no automatic fix for this kind of finding; see its remediation")


# ---------------------------------------------------------------- dependencies


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def fixed_version(f: Finding) -> str | None:
    """The lowest listed fixed version above the installed one ("2.32.0, 2.31.1" is common)."""
    pkg = f.package
    if pkg is None or not pkg.fixed_version:
        return None
    current = _vkey(pkg.version or "0")
    options = sorted((v.strip().lstrip("v") for v in pkg.fixed_version.split(",") if v.strip()), key=_vkey)
    return next((v for v in options if _vkey(v) > current), options[-1] if options else None)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _dependency(f: Finding, target: Path) -> Fix:
    pkg = f.package
    if pkg is None:
        return Fix(f, reason="no package recorded for this finding")
    to = fixed_version(f)
    if not to:
        return Fix(f, reason=f"no fixed version of {pkg.name} is known yet")
    manifest = PurePosixPath(f.location.path)
    folder = manifest.parent
    candidates = (
        [manifest] if manifest.name in ("package.json", "go.mod") or "requirements" in manifest.name else []
    )
    candidates += [folder / "package.json", folder / "go.mod", folder / "requirements.txt"]
    for rel in dict.fromkeys(candidates):
        path = target / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if rel.name == "package.json":
            new = _package_json(text, pkg.name, to)
            notes = ["Run `npm install` (or your package manager) so the lock file matches."]
        elif rel.name == "go.mod":
            new = _go_mod(text, pkg.name, to)
            notes = ["Run `go mod tidy` so go.sum matches."]
        else:
            if "--hash=" in text:
                return Fix(f, reason=f"{rel} is a hash-pinned lock; regenerate it with {pkg.name}>={to}")
            new = _requirements(text, pkg.name, to)
            notes = []
        if new is not None and new != text:
            return Fix(
                f,
                files={str(rel): new},
                summary=f"Upgrade {pkg.name} {pkg.version or ''} to {to} in {rel}".replace("  ", " "),
                notes=notes,
            )
    return Fix(
        f, reason=f"{pkg.name} is not declared directly (a transitive dependency): upgrade what pulls it in"
    )


def _requirements(text: str, name: str, to: str) -> str | None:
    pattern = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*==\s*)([^\s;#]+)", re.M)
    hit = False

    def repl(m: re.Match[str]) -> str:
        nonlocal hit
        if _norm(m.group(2)) != _norm(name):
            return m.group(0)
        hit = True
        return f"{m.group(1)}{m.group(2)}{m.group(3) or ''}{m.group(4)}{to}"

    out = pattern.sub(repl, text)
    return out if hit else None


def _package_json(text: str, name: str, to: str) -> str | None:
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    sections = ("dependencies", "devDependencies", "optionalDependencies")
    if not any(name in (doc.get(s) or {}) for s in sections):
        return None
    pattern = re.compile(r'("' + re.escape(name) + r'"\s*:\s*")([\^~]|>=)?\d[^"]*(")')
    out, n = pattern.subn(lambda m: f"{m.group(1)}{m.group(2) or ''}{to}{m.group(3)}", text)
    return out if n else None


def _go_mod(text: str, name: str, to: str) -> str | None:
    pattern = re.compile(r"^(\s*(?:require\s+)?" + re.escape(name) + r"\s+)v\S+", re.M)
    out, n = pattern.subn(lambda m: f"{m.group(1)}v{to}", text)
    return out if n else None


# ---------------------------------------------------------------- workflows

_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_RUN = re.compile(r"^(\s*)(-\s+)?run:\s*(.*)$")


def env_name(expr: str) -> str:
    """github.event.issue.title -> ISSUE_TITLE; github.head_ref -> HEAD_REF."""
    parts = [p for p in re.split(r"[.\[\]'\"]+", expr) if p and p not in ("github", "event", "inputs")]
    return re.sub(r"[^A-Z0-9_]", "_", "_".join(parts[-2:]).upper()) or "UNTRUSTED_INPUT"


def _script_injection(f: Finding, target: Path) -> Fix:
    rel = f.location.path
    path = target / rel
    if not path.is_file() or not f.location.start_line:
        return Fix(f, reason=f"{rel} not found")
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    i = min(f.location.start_line, len(lines)) - 1
    # The run: key at or above the finding.
    m = None
    while i >= 0 and (m := _RUN.match(lines[i])) is None:
        i -= 1
    if m is None:
        return Fix(f, reason="the expression is not in a run: script (github-script needs a manual fix)")
    key_col = len(m.group(1)) + len(m.group(2) or "")
    block = m.group(3).strip() in ("|", ">", "|-", ">-", "|+", ">+")
    end = i + 1
    if block:
        while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > key_col):
            end += 1
    script_lines = range(i + 1, end) if block else range(i, i + 1)
    names: dict[str, str] = {}
    for n in script_lines:
        lines[n] = _rewrite(lines[n], names)
    if not names:
        return Fix(f, reason="no untrusted expression found in that script")
    # Add to the step's env: (existing block, or a new one after the script).
    step_end = end
    while step_end < len(lines) and (not lines[step_end].strip() or _indent(lines[step_end]) >= key_col):
        if _indent(lines[step_end]) == key_col and lines[step_end].lstrip().startswith("- "):
            break
        step_end += 1
    step_start = i
    while step_start > 0 and not lines[step_start].lstrip().startswith("- "):
        step_start -= 1
    env_at = next(
        (
            n
            for n in range(step_start, step_end)
            if _indent(lines[n], dash=True) == key_col and _key(lines[n]) == "env"
        ),
        None,
    )
    pad = " " * (key_col + 2)
    entries = [f"{pad}{name}: ${{{{ {expr} }}}}\n" for expr, name in names.items()]
    if env_at is not None:
        lines[env_at + 1 : env_at + 1] = entries
    else:
        lines[end:end] = [f"{' ' * key_col}env:\n", *entries]
    return Fix(
        f,
        files={rel: "".join(lines)},
        summary=f"Pass {', '.join(sorted(names))} to the script through env in {rel}",
        notes=["The script reads the values as shell variables, so they can no longer inject commands."],
    )


def _indent(line: str, dash: bool = False) -> int:
    stripped = line.lstrip(" ")
    col = len(line) - len(stripped)
    if dash and stripped.startswith("- "):
        col += 2
    return col


def _key(line: str) -> str:
    return line.strip().removeprefix("- ").split(":", 1)[0].strip()


def _rewrite(line: str, names: dict[str, str]) -> str:
    out, pos = [], 0
    for m in _EXPR.finditer(line):
        expr = m.group(1)
        if not UNTRUSTED_CONTEXT.search(expr):
            continue
        name = names.setdefault(expr, _unique(env_name(expr), names))
        quoting = _quoting(line[: m.start()])
        if quoting == '"':
            ref = f"${{{name}}}"  # already inside double quotes
        elif quoting == "'":
            ref = f"'\"${{{name}}}\"'"  # close the single quotes around it
        else:
            ref = f'"${{{name}}}"'
        out += [line[pos : m.start()], ref]
        pos = m.end()
    return "".join(out) + line[pos:] if out else line


def _quoting(prefix: str) -> str:
    """The shell quote open at the end of ``prefix``: '"', "'" or ""."""
    state, escaped = "", False
    for ch in prefix:
        if escaped:
            escaped = False
        elif ch == "\\" and state != "'":
            escaped = True
        elif state == "" and ch in "'\"":
            state = ch
        elif ch == state:
            state = ""
    return state


def _unique(name: str, taken: dict[str, str]) -> str:
    used = set(taken.values())
    candidate, n = name, 2
    while candidate in used:
        candidate, n = f"{name}_{n}", n + 1
    return candidate


# ---------------------------------------------------------------- pull requests


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise FixError(f"git {' '.join(args)}: {(proc.stderr or proc.stdout).strip()[-300:]}")
    return proc.stdout.strip()


class FixError(Exception):
    pass


def pr_body(fix: Fix, result: ScanResult) -> str:
    fps = set(fix.finding.fingerprints or [fix.finding.fingerprint])
    paths = [p for p in (result.attack_graph.paths if result.attack_graph else []) if fps & set(p.weaknesses)]
    lines = [
        f"This change fixes **{fix.finding.title}** (`{fix.finding.location.path}"
        f"{':' + str(fix.finding.location.start_line) if fix.finding.location.start_line else ''}`)"
        f" and breaks {len(paths)} attack path(s):",
        "",
        *[f"- {' → '.join(['Internet', *(s.dst for s in p.steps)])}" for p in paths[:10]],
        "",
        fix.summary + ".",
        *(["", *fix.notes] if fix.notes else []),
        "",
        "Opened by `breachgraph fix`. Review it like any other change.",
    ]
    return "\n".join(lines)


def open_pull_requests(fixes: list[Fix], result: ScanResult, repo: Path, token: str | None) -> list[str]:
    """One branch and pull request per fix, each from the current branch. Returns PR or compare URLs."""
    if _git(repo, "status", "--porcelain"):
        raise FixError("the working tree has uncommitted changes; commit or stash them first")
    base = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    remote = _git(repo, "config", "--get", "remote.origin.url")
    m = re.search(r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$", remote)
    if m is None:
        raise FixError(f"origin is not a GitHub repository: {remote}")
    owner, name = m.group(1), m.group(2)
    top = Path(_git(repo, "rev-parse", "--show-toplevel"))
    prefix = _git(repo, "rev-parse", "--show-prefix")
    urls = []
    for fix in fixes:
        if not fix.files:
            continue
        branch = f"breachgraph/fix-{fix.finding.fingerprint[:10]}"
        _git(repo, "switch", "-c", branch, base)
        try:
            for rel, content in fix.files.items():
                (top / prefix / rel).write_text(content, encoding="utf-8")
                _git(repo, "add", "--", str(PurePosixPath(prefix) / rel) if prefix else rel)
            _git(
                repo,
                "commit",
                "-m",
                fix.summary,
                "-m",
                f"Breaks {fix.paths_cut} attack path(s) found by breachgraph.",
            )
            _git(repo, "push", "-u", "origin", branch)
        finally:
            _git(repo, "switch", base)
        urls.append(_create_pr(owner, name, base, branch, fix.summary, pr_body(fix, result), token))
    return urls


def _create_pr(
    owner: str, name: str, base: str, branch: str, title: str, body: str, token: str | None
) -> str:
    compare = f"https://github.com/{owner}/{name}/compare/{base}...{branch}?expand=1"
    if not token:
        return compare
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    resp = httpx.post(
        f"{api}/repos/{owner}/{name}/pulls",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"title": title, "head": branch, "base": base, "body": body},
        timeout=30,
    )
    if resp.status_code >= 300:
        return f"{compare} (could not open the pull request: HTTP {resp.status_code})"
    return str(resp.json().get("html_url") or compare)
