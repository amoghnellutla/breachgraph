"""Evidence for AI triage: what a reviewer would open before deciding.

A few lines around a match are not enough to tell a real injection from a false positive. For
each finding we gather the context a human reviewer would look at:

- code findings: the whole enclosing function (tree-sitter), flagged lines marked, plus the HTTP
  route that runs it, if any;
- dependency findings: the CVE facts, reachability, and the first-party lines that use the package;
- IaC/config findings: the reported block (e.g. the whole Terraform resource);
- every finding: whether it is a step on an internet-to-crown-jewel attack path, and the risk
  factors breachgraph scored.

Secrets never leave the machine: secret findings are never read from disk (only a scanner-redacted
match is sent), and token-shaped string literals are masked in all code we send.
"""

from __future__ import annotations

import contextlib
import math
import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import tree_sitter as ts

from breachgraph.graph.sources.routes import parse_tree, routes_in_file
from breachgraph.models import (
    AttackGraphSummary,
    AttackPathView,
    AttackStep,
    Category,
    Finding,
    Reachability,
)
from breachgraph.normalize import is_secret
from breachgraph.paths import normalize_path
from breachgraph.reachability import import_candidates
from breachgraph.scanners._util import read_lines

_FUNCTION_NODES = {
    "function_definition",  # Python
    "function_declaration",  # JS/TS, Go
    "function_expression",
    "function",
    "generator_function_declaration",
    "arrow_function",
    "method_definition",
    "method_declaration",  # Java, Go
    "constructor_declaration",
    "lambda_expression",
    "func_literal",
}
_MAX_CODE_LINES = 120  # a whole function up to this size; longer ones get a window around the finding
_WINDOW = 40
_MAX_LINE_CHARS = 300
_MAX_USAGE_FILES = 3
_MAX_USAGE_LINES = 10
_REDACTING_TOOLS = {"gitleaks"}  # scanners that strip the secret value from their own match
_IMPORTED_BY = re.compile(r"imported by (\S+)")
_TF_RESOURCE = re.compile(r'^resource\s+"([\w-]+)"\s+"([\w-]+)"')
_TF_REF = re.compile(r"\b((?:aws|google|azurerm|kubernetes)_[a-z0-9_]+)\.([A-Za-z0-9_-]+)")
_TF_NAME = re.compile(
    r'^\s*(name|bucket|function_name|cluster_name|identifier|queue_name|topic_name)\s*=\s*"([^"$]{3,})"'
)
_MAX_TF_FILES = 30
_MAX_TF_REFERENCED = 2
_MAX_WHOLE_FILE_LINES = 80

_TOKEN_PATTERNS = re.compile(
    r"(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|sk-[A-Za-z0-9_-]{20,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)
_STRING_LITERAL = re.compile(r"""(["'`])([^"'`\\\n]{6,})\1""")
_TOKEN_LIKE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def _entropy(s: str) -> float:
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _token_like(s: str) -> bool:
    """A random-looking key/token (hex, base64...), as opposed to a name like
    "acme-customer-data-2024", which the model needs to see."""
    if not _TOKEN_LIKE.fullmatch(s) or not (re.search(r"\d", s) and re.search(r"[A-Za-z]", s)):
        return False
    words = re.split(r"[-_.]", s)
    if len(words) > 1 and all(w.isalpha() or w.isdigit() for w in words):
        return False
    return _entropy(s) >= 3.0


def _mask(line: str, all_literals: bool) -> str:
    """Mask credentials in a source line: known token formats, random-looking string literals,
    and (for hardcoded-credential findings) every string literal on the flagged line."""
    line = _TOKEN_PATTERNS.sub("<redacted>", line)

    def literal(m: re.Match[str]) -> str:
        if all_literals or _token_like(m.group(2)):
            return f"{m.group(1)}<redacted>{m.group(1)}"
        return m.group(0)

    return _STRING_LITERAL.sub(literal, line)


def _numbered(lines: list[str], start: int, end: int, flagged: range, credential: bool) -> str:
    width = len(str(end))
    out = []
    for n in range(start, end + 1):
        text = _mask(lines[n - 1], all_literals=credential and n in flagged)
        if len(text) > _MAX_LINE_CHARS:
            text = text[:_MAX_LINE_CHARS] + " …"
        out.append(f"{'>' if n in flagged else ' '}{n:>{width}} | {text}")
    return "\n".join(out)


def _enclosing_function(tree: ts.Tree, line: int) -> tuple[int, int] | None:
    """Line span of the function containing ``line``. Skips one-line callbacks in favour of the
    function around them, and includes Python decorators (they carry the route)."""
    row = line - 1
    node: ts.Node | None = tree.root_node.descendant_for_point_range((row, 0), (row, 0))
    smallest = None
    while node is not None:
        if node.type in _FUNCTION_NODES:
            start, end = node.start_point[0] + 1, node.end_point[0] + 1
            if node.parent is not None and node.parent.type == "decorated_definition":
                start = node.parent.start_point[0] + 1
            smallest = smallest or (start, end)
            if end - start >= 3:
                return start, end
        node = node.parent
    return smallest


def _code(target: Path, f: Finding) -> tuple[str, str | None]:
    """(numbered code around the finding, label of the HTTP route that runs it)."""
    lines = read_lines(target, f.location.path)  # None if outside the scanned tree
    first = f.location.start_line
    if lines is None:
        return "", None
    if not first:  # reported on the whole file (e.g. a Dockerfile rule): show it if it is small
        if 0 < len(lines) <= _MAX_WHOLE_FILE_LINES:
            return _numbered(lines, 1, len(lines), range(0), credential=False), None
        return "", None
    if first > len(lines):
        return "", None
    path = target / normalize_path(f.location.path)
    last = min(max(first, f.location.end_line or first), len(lines))
    try:
        tree = parse_tree(path)
    except (OSError, ValueError):
        tree = None
    span = _enclosing_function(tree, first) if tree is not None else None
    if span is None and f.location.path.endswith(".tf"):
        block = next(((s, e) for _, s, e in _tf_blocks(lines) if s <= first <= e), None)
        span = (block[0] - 1, block[1] + 1) if block else None
    if span is None:  # module-level code or a config file: the reported block plus a margin
        span = (first - 2, last + 2) if last > first else (first - 10, last + 10)
    start, end = max(1, span[0]), min(len(lines), span[1])
    if end - start + 1 > _MAX_CODE_LINES:
        start, end = max(start, first - _WINDOW), min(end, last + _WINDOW)

    route = None
    if tree is not None:
        with contextlib.suppress(OSError, ValueError):
            route = next(
                (
                    f"{r.label} ({r.framework} handler `{r.handler}`)"
                    for r in routes_in_file(path, f.location.path)
                    if r.start_line <= first <= r.end_line
                ),
                None,
            )
    return _numbered(lines, start, end, range(first, last + 1), is_secret(f)), route


def _usage(target: Path, f: Finding) -> str:
    """First-party lines that reference a vulnerable package, so the model can judge whether the
    vulnerable API is what the code actually calls."""
    pkg = f.package
    if pkg is None:
        return ""
    lang, cands = import_candidates(pkg.name, pkg.ecosystem)
    tokens = cands | {c.rsplit("/", 1)[-1] for c in cands}  # Go: last path segment is the identifier
    if not tokens:
        return ""
    alts = [rf"\b{re.escape(t)}\b" if t.isidentifier() else re.escape(t) for t in sorted(tokens)]
    pattern = re.compile("|".join(alts), re.IGNORECASE if lang == "python" else 0)
    files = [m.group(1) for e in pkg.reach_evidence if (m := _IMPORTED_BY.match(e))]
    out = []
    for rel in files[:_MAX_USAGE_FILES]:
        lines = read_lines(target, rel)
        if lines is None:
            continue
        hits = [n for n, text in enumerate(lines, 1) if pattern.search(text)][:_MAX_USAGE_LINES]
        if hits:
            out.append(f"{rel}:")
            out += [f"  {n:>5} | {_mask(lines[n - 1], False)[:_MAX_LINE_CHARS]}" for n in hits]
    return "\n".join(out)


def _ids(f: Finding) -> set[str]:
    return {f.fingerprint, *f.fingerprints}


def on_attack_path(f: Finding, ag: AttackGraphSummary | None) -> bool:
    return ag is not None and any(_ids(f) & set(p.weaknesses) for p in ag.paths)


def _chain(p: AttackPathView, here: Callable[[AttackStep], bool] | None = None) -> str:
    hops = ["Internet"]
    for s in p.steps:
        hop = s.dst + (f" [via {s.via}]" if s.via else "")
        hops.append(hop + (" [defined here]" if here and here(s) else ""))
    gate = ", fails the build" if p.gating else ""
    return f"- {' -> '.join(hops)} (reaches {p.target_kind} '{p.target}', {p.confidence} confidence{gate})"


def _tf_block(target: Path, f: Finding) -> tuple[int, int, set[str]] | None:
    """(first line, last line, cloud names) of the Terraform resource a finding is on. The names
    (``name``/``bucket`` values) are how attack-path nodes label the resource."""
    lines = read_lines(target, f.location.path)
    line = f.location.start_line
    if lines is None or not line:
        return None
    span = next(((s, e) for _, s, e in _tf_blocks(lines) if s <= line <= e), None)
    if span is None:
        return None
    names = {m[2] for text in lines[span[0] - 1 : span[1]] if (m := _TF_NAME.match(text))}
    return span[0], span[1], names


def _attack_paths(f: Finding, ag: AttackGraphSummary | None, target: Path) -> list[str]:
    if ag is None or not ag.enabled:
        return []
    ids = _ids(f)
    out = [_chain(p) for p in ag.paths if ids & set(p.weaknesses)][:3]
    cut = next((c.paths_cut for c in ag.choke_points if c.fingerprint in ids), 0)
    if cut:
        out.append(f"- Fixing this finding breaks {cut} attack path(s).")
    if out:
        return ["Attack paths through this finding (each [via ...] step needs a real vulnerability):", *out]

    # Not a step itself, but a misconfiguration on a resource a path goes through (hostNetwork on
    # the exposed pod, an over-broad policy on the role a path uses) still matters.
    is_tf = f.location.path.endswith(".tf")
    block = _tf_block(target, f) if is_tf else None

    def here(s: AttackStep) -> bool:
        if not f.location.in_repo:
            return False
        if not is_tf:
            return s.evidence_path == f.location.path
        if block is None:
            return False
        start, end, names = block
        if s.evidence_path == f.location.path and s.evidence_line and start <= s.evidence_line <= end:
            return True
        return any(re.search(rf"\b{re.escape(n)}$", s.dst) for n in names)  # e.g. "S3 bucket <name>"

    related = [_chain(p, here) for p in ag.paths if any(here(s) for s in p.steps)][:3]
    if related:
        where = (
            "the Terraform resource this finding is on"
            if is_tf
            else f"resources defined in {f.location.path}"
        )
        return [
            f"Attack paths: this finding is not itself a step, but these paths go through {where} "
            "(marked [defined here]):",
            *related,
        ]
    return ["Attack paths: none of the internet-to-crown-jewel paths breachgraph found involve this finding."]


def _tf_blocks(lines: list[str]) -> list[tuple[str, int, int]]:
    """(address, first line, last line) of each top-level ``resource`` block."""
    out = []
    i = 0
    while i < len(lines):
        m = _TF_RESOURCE.match(lines[i])
        if m:
            j = i
            while j < len(lines) - 1 and lines[j].rstrip() != "}":
                j += 1
            out.append((f"{m[1]}.{m[2]}", i + 1, j + 1))
            i = j
        i += 1
    return out


def _terraform(target: Path, f: Finding) -> list[str]:
    """For a finding on a Terraform resource: the module's other resources that reference it (a
    separate public-access block, encryption config or policy changes the verdict), and the
    resources it references (e.g. the role a policy attaches to, with its trust policy)."""
    line = f.location.start_line
    if not f.location.path.endswith(".tf") or not line:
        return []
    folder = PurePosixPath(f.location.path).parent
    files: dict[str, list[str]] = {}
    for p in sorted((target / folder).glob("*.tf"))[:_MAX_TF_FILES]:
        rel = (folder / p.name).as_posix()
        if (lines := read_lines(target, rel)) is not None:
            files[rel] = lines
    blocks = [(rel, *b) for rel, lines in files.items() for b in _tf_blocks(lines)]
    own = next((b for b in blocks if b[0] == f.location.path and b[2] <= line <= b[3]), None)
    if own is None:
        return []
    own_rel, addr, start, end = own

    pattern = re.compile(rf"\b{re.escape(addr)}\b")
    referrers = []
    for rel, other, s, e in blocks:
        hit = next((n for n in range(s, e + 1) if pattern.search(files[rel][n - 1])), None)
        if other != addr and hit:
            text = _mask(files[rel][hit - 1].strip(), False)[:160]
            referrers.append(f"- {other} ({rel}:{s}), line {hit}: {text}")
    if referrers:
        out = [f"Other Terraform resources in this module that reference {addr}:", *referrers[:8]]
    else:
        out = [f"No other Terraform resource in this module references {addr}."]

    own_text = "\n".join(files[own_rel][start - 1 : end])
    referenced = sorted({f"{m[1]}.{m[2]}" for m in _TF_REF.finditer(own_text)} - {addr})
    for rel, other, s, e in blocks:
        if other in referenced[:_MAX_TF_REFERENCED]:
            body = _numbered(files[rel], s, min(e, s + 24), range(0), credential=False)
            out.append(f"Resource it references, {other} ({rel}):\n{body}")
    return out


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_evidence(f: Finding, target: Path, ag: AttackGraphSummary | None) -> str:
    loc = f.location.path + (f":{f.location.start_line}" if f.location.start_line else "")
    out = [
        f"Title: {f.title}",
        f"Rule: {f.tool}:{f.rule_id}"
        + (f" (also reported by {', '.join(f.sources)})" if len(f.sources) > 1 else ""),
        f"Category: {f.category.value} | Severity: {f.severity.value} | "
        f"Scanner confidence: {f.confidence.value}" + (f" | {', '.join(f.cwe)}" if f.cwe else ""),
        f"Location: {loc}",
    ]
    if f.description:
        out.append(f"Scanner description: {_clip(f.description, 600)}")
    if f.remediation:
        out.append(f"Scanner's suggested fix: {_clip(f.remediation, 300)}")
    if f.score_reasons:
        out.append("Risk factors: " + "; ".join(f.score_reasons))
    out += _attack_paths(f, ag, target)

    if f.category is Category.SECRETS:
        if f.tool in _REDACTING_TOOLS and f.location.snippet:
            out.append(
                "Matched text (the scanner redacted the secret value):\n" + _clip(f.location.snippet, 300)
            )
        else:
            out.append("Code: not included. breachgraph never sends secret values.")
    elif f.package is not None:
        pkg = f.package
        out.append(
            f"Package: {pkg.name} {pkg.version or '?'} ({pkg.ecosystem or 'unknown ecosystem'}), "
            f"fixed in: {pkg.fixed_version or 'no fixed version yet'}"
        )
        if f.vuln_ids:
            out.append("Advisories: " + ", ".join(f.vuln_ids[:6]) + (f" (CVSS {f.cvss})" if f.cvss else ""))
        if pkg.reachability is not None:
            ev = f" ({'; '.join(pkg.reach_evidence)})" if pkg.reach_evidence else ""
            out.append(f"Reachability: {pkg.reachability.value}{ev}")
        usage = _usage(target, f)
        if usage:
            out.append("First-party lines that reference this package:\n" + usage)
        elif pkg.reachability is Reachability.UNUSED:
            out.append("First-party usage: none. No first-party file imports this package.")
        elif pkg.reachability in (None, Reachability.UNKNOWN):
            out.append("First-party usage: not analyzed for this package.")
    else:
        code, route = _code(target, f)
        if route:
            out.append(f"Runs in HTTP route: {route}")
        if code:
            out.append("Code (flagged lines marked '>'):\n" + code)
            out += _terraform(target, f)
        elif f.location.snippet:
            masked = "\n".join(_mask(line, False) for line in f.location.snippet.splitlines())
            out.append("Scanner snippet:\n" + masked[:1500])
    return "\n".join(out)
