"""Fingerprinting and cross-tool deduplication."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable

from triagegate.models import Category, Confidence, Finding
from triagegate.normalize.taxonomy import normalize_cwes, normalize_owasp, owasp_for
from triagegate.paths import normalize_path

__all__ = ["dedupe", "finalize", "fingerprint_of"]

# Checks that different IaC tools implement under different ids. Findings from these pairs,
# on overlapping lines of the same file, are the same issue.
_EQUIVALENT_RULES: list[set[str]] = [
    {"trivy:AWS86", "checkov:CKV_AWS_53"},  # S3 block public ACLs
    {"trivy:AWS87", "checkov:CKV_AWS_54"},  # S3 block public policy
    {"trivy:AWS91", "checkov:CKV_AWS_55"},  # S3 ignore public ACLs
    {"trivy:AWS93", "checkov:CKV_AWS_56"},  # S3 restrict public buckets
    {"trivy:AWS88", "checkov:CKV_AWS_19"},  # S3 encryption at rest
    {"trivy:AWS90", "checkov:CKV_AWS_21"},  # S3 versioning
    {"trivy:AWS89", "checkov:CKV_AWS_18"},  # S3 access logging
    {"trivy:AWS107", "checkov:CKV_AWS_24", "checkov:CKV_AWS_25", "checkov:CKV_AWS_260"},  # open SG
    {"trivy:DS2", "checkov:CKV_DOCKER_3", "checkov:CKV_DOCKER_8"},  # container runs as root
    {"trivy:DS26", "checkov:CKV_DOCKER_2"},  # no HEALTHCHECK
    {"trivy:DS1", "checkov:CKV_DOCKER_7"},  # ':latest' base image
]

_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "be",
    "been",
    "by",
    "does",
    "enabled",
    "ensure",
    "for",
    "has",
    "have",
    "in",
    "is",
    "it",
    "not",
    "of",
    "on",
    "or",
    "should",
    "that",
    "the",
    "to",
    "with",
}


def _rule_key(f: Finding) -> str:
    rid = f.rule_id.upper()
    if f.tool == "trivy":
        rid = re.sub(r"^AVD-", "", rid)
        m = re.match(r"^([A-Z]+)-?0*(\d+)$", rid)
        if m:
            rid = f"{m.group(1)}{int(m.group(2))}"
    return f"{f.tool}:{rid}"


_EQUIV_INDEX: dict[str, int] = {r: i for i, group in enumerate(_EQUIVALENT_RULES) for r in group}


def _norm_snippet(snippet: str) -> str:
    return re.sub(r"\s+", "", snippet)[:400]


def fingerprint_of(f: Finding) -> str:
    """Stable id that survives unrelated edits elsewhere in the file (line shifts).

    Code findings hash the matched snippet rather than the line number; dependency findings
    hash package + vulnerability (not the installed version, so a bump that does not fix it is
    still the same finding). Secrets use the line, because their snippet is redacted.
    """
    parts = [f.tool, f.rule_id, f.location.path]
    if f.category in (Category.SCA, Category.CONTAINER) and f.package:
        parts += [f.package.name.lower(), ",".join(sorted(f.vuln_ids))]
    elif f.location.snippet and f.category is not Category.SECRETS:
        parts.append(_norm_snippet(f.location.snippet))
    else:
        parts.append(str(f.location.start_line or 0))
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:32]


def finalize(findings: Iterable[Finding]) -> list[Finding]:
    """Normalize fields and assign unique fingerprints (identical matches get #n suffixes)."""
    items = list(findings)
    items.sort(key=lambda f: (f.tool, f.location.path, f.location.start_line or 0, f.rule_id))
    seen: dict[str, int] = defaultdict(int)
    for f in items:
        f.location.path = normalize_path(f.location.path)
        f.cwe = normalize_cwes(f.cwe)
        f.owasp = normalize_owasp(f.owasp) or owasp_for(f.cwe, f.category)
        f.vuln_ids = sorted({v.strip() for v in f.vuln_ids if v.strip()})
        raw = fingerprint_of(f)
        n = seen[raw]
        seen[raw] += 1
        f.fingerprint = raw if n == 0 else hashlib.sha256(f"{raw}#{n}".encode()).hexdigest()[:32]
        f.fingerprints = [f.fingerprint]
        f.sources = [f.tool]
    return items


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in _STOPWORDS}


def _similar_titles(a: Finding, b: Finding) -> bool:
    ta, tb = _tokens(a.title), _tokens(b.title)
    if not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= 0.5


def _overlap(a: Finding, b: Finding) -> bool:
    if a.location.start_line is None or b.location.start_line is None:
        return False
    a1, a2 = a.location.start_line, a.location.end_line or a.location.start_line
    b1, b2 = b.location.start_line, b.location.end_line or b.location.start_line
    return a1 <= b2 and b1 <= a2


def _is_secret(f: Finding) -> bool:
    return f.category is Category.SECRETS or "CWE-798" in f.cwe


def _strength(a: Finding, b: Finding, keys_a: set[str], keys_b: set[str]) -> int:
    """How sure we are that two findings (from different tools) are the same issue: 0-3."""
    if a.location.path != b.location.path:
        return 0
    if _is_secret(a) and _is_secret(b):
        return 3 if _overlap(a, b) else 0
    if a.category is not b.category:
        return 0
    groups_a = {_EQUIV_INDEX[k] for k in keys_a if k in _EQUIV_INDEX}
    if groups_a & {_EQUIV_INDEX[k] for k in keys_b if k in _EQUIV_INDEX}:
        # Known-equivalent checks. Some tools (Trivy on Dockerfiles) report no lines.
        no_lines = a.location.start_line is None or b.location.start_line is None
        return 3 if no_lines or _overlap(a, b) else 0
    if not _overlap(a, b):
        return 0
    if set(a.cwe) & set(b.cwe):
        return 2
    return 1 if _similar_titles(a, b) else 0


_CONF_RANK = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}


def _merge(group: list[Finding]) -> Finding:
    if len(group) == 1:
        return group[0]
    primary = max(
        group,
        key=lambda f: (
            f.severity.rank,
            _CONF_RANK[f.confidence],
            f.remediation is not None,
            len(f.description),
        ),
    )
    merged = primary.model_copy(deep=True)
    for other in group:
        if other is primary:
            continue
        for src in other.sources:
            if src not in merged.sources:
                merged.sources.append(src)
        merged.related_rules.append(f"{other.tool}:{other.rule_id}")
        merged.fingerprints.extend(fp for fp in other.fingerprints if fp not in merged.fingerprints)
        merged.cwe.extend(c for c in other.cwe if c not in merged.cwe)
        merged.owasp.extend(o for o in other.owasp if o not in merged.owasp)
        merged.vuln_ids.extend(v for v in other.vuln_ids if v not in merged.vuln_ids)
        merged.references.extend(r for r in other.references if r not in merged.references)
        if merged.remediation is None and other.remediation:
            merged.remediation = other.remediation
        if other.cvss is not None and (merged.cvss is None or other.cvss > merged.cvss):
            merged.cvss = other.cvss
    return merged


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> int:
        ri, rj = self.find(i), self.find(j)
        if ri != rj:
            self.parent[rj] = ri
        return ri

    def groups(self) -> list[list[int]]:
        out: dict[int, list[int]] = defaultdict(list)
        for i in range(len(self.parent)):
            out[self.find(i)].append(i)
        return list(out.values())


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that describe the same issue.

    Stage 1 merges exact duplicates: same fingerprint, same CVE in the same package and file,
    or several rules of one SAST tool flagging overlapping lines for the same CWE (e.g. Semgrep's
    Flask, Django and SQLAlchemy SQL-injection rules all firing on one query).

    Stage 2 clusters across tools, strongest evidence first (known-equivalent rule ids, then
    shared CWE, then similar titles on overlapping lines). A cluster never holds two findings
    from the same tool, which stops chains of weak matches from swallowing distinct issues.
    """
    uf = _UnionFind(len(findings))
    first_with: dict[tuple[object, ...], int] = {}
    same_cwe: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        loc = f.location
        keys: list[tuple[object, ...]] = [("fp", f.fingerprint)]
        if f.package and f.vuln_ids:
            keys.append(("vuln", f.vuln_ids[0], f.package.name.lower(), loc.path))
        for key in keys:
            if key in first_with:
                uf.union(first_with[key], i)
            else:
                first_with[key] = i
        if f.category is Category.SAST:
            for cwe in f.cwe:
                same_cwe[(f.tool, loc.path, cwe)].append(i)
    for idxs in same_cwe.values():
        for x, i in enumerate(idxs):
            for j in idxs[x + 1 :]:
                if _overlap(findings[i], findings[j]):
                    uf.union(i, j)
    stage1 = uf.groups()
    clusters = [_merge([findings[i] for i in g]) for g in stage1]
    tools = [{findings[i].tool for i in g} for g in stage1]
    rule_keys = [{_rule_key(findings[i]) for i in g} for g in stage1]

    by_path: dict[str, list[int]] = defaultdict(list)
    for c, f in enumerate(clusters):
        by_path[f.location.path].append(c)
    candidates: list[tuple[int, int, int, int]] = []
    for idxs in by_path.values():
        for x, i in enumerate(idxs):
            for j in idxs[x + 1 :]:
                if tools[i] & tools[j]:
                    continue
                s = _strength(clusters[i], clusters[j], rule_keys[i], rule_keys[j])
                if s:
                    gap = abs(
                        (clusters[i].location.start_line or 0)
                        - (clusters[j].location.start_line or 0)
                    )
                    candidates.append((-s, gap, i, j))
    candidates.sort()

    uf2 = _UnionFind(len(clusters))
    for _, _, i, j in candidates:
        ri, rj = uf2.find(i), uf2.find(j)
        if ri == rj or tools[ri] & tools[rj]:
            continue
        root = uf2.union(ri, rj)
        tools[root] = tools[ri] | tools[rj]

    merged = [_merge([findings[k] for c in group for k in stage1[c]]) for group in uf2.groups()]
    merged.sort(key=lambda f: (f.location.path, f.location.start_line or 0, f.rule_id))
    return merged
