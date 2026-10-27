"""Markdown summary for PR comments and $GITHUB_STEP_SUMMARY."""

from __future__ import annotations

import re
from pathlib import Path

from breachgraph.compare import path_changes
from breachgraph.graph.attack import technique_url
from breachgraph.models import AttackPathView, Finding, Priority, ScanResult, Status, ToolStatus

MARKER = "<!-- breachgraph-report -->"
_MAX_CHARS = 60_000  # GitHub comments are capped at 65,536 characters
_TOOL_STATUS = {
    ToolStatus.OK: "",
    ToolStatus.IMPORTED: "imported",
    ToolStatus.SKIPPED: "skipped",
    ToolStatus.FAILED: "failed",
}


def defang(text: str) -> str:
    """Scanner output is untrusted: stop it from @-mentioning people or teams."""
    return text.replace("@", "@​")


def _cell(text: str, limit: int = 120) -> str:
    text = defang(" ".join(text.split()).replace("|", "\\|"))
    return text if len(text) <= limit else text[: limit - 1] + "…"


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")


def _plain(text: str, limit: int) -> str:
    """Model-written prose as inert text: no links, images, HTML or formatting get through
    (repository content can steer a model via prompt injection)."""
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return defang(_MD_SPECIAL.sub(r"\\\1", text))


_FENCE_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".tf": "hcl",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
}


def _fenced(code: str, path: str = "", limit: int = 1500) -> list[str]:
    """A code block the code itself cannot close: the fence is longer than any backtick run in it."""
    code = code if len(code) <= limit else code[:limit] + "\n…"
    longest = max((len(run) for run in re.findall(r"`+", code)), default=0)
    fence = "`" * max(3, longest + 1)
    name = path.rsplit("/", 1)[-1]
    lang = "dockerfile" if name.lower().startswith("dockerfile") else _FENCE_LANG.get(Path(name).suffix, "")
    return [fence + lang, code, fence]


def _where(f: Finding, link_base: str | None) -> str:
    loc = f.location
    label = loc.path + (f":{loc.start_line}" if loc.start_line else "")
    if link_base and loc.in_repo:
        anchor = f"#L{loc.start_line}" if loc.start_line else ""
        if loc.start_line and loc.end_line and loc.end_line > loc.start_line:
            anchor += f"-L{loc.end_line}"
        return f"[`{_cell(label, 80)}`]({link_base}/{loc.path}{anchor})"
    return f"`{_cell(label, 80)}`"


def _table(findings: list[Finding], link_base: str | None, limit: int) -> list[str]:
    rows = ["| Priority | Finding | Location | Severity | Found by |", "|---|---|---|---|---|"]
    for f in findings[:limit]:
        tags = []
        if f.enrichment.kev:
            tags.append("**KEV**")
        if f.enrichment.epss is not None and f.enrichment.epss >= 0.1:
            tags.append(f"EPSS {f.enrichment.epss:.0%}")
        if f.ai:
            tags.append("AI: " + f.ai.verdict.label)
        title = _cell(f.title) + (" " + " ".join(tags) if tags else "")
        if f.ai and f.ai.summary:
            title += "<br>_" + _plain(f.ai.summary, 200) + "_"
        rows.append(
            f"| {f.priority.value} | {title} | {_where(f, link_base)} "
            f"| {f.severity.value} | {', '.join(f.sources)} |"
        )
    if len(findings) > limit:
        rows.append(f"\n_…and {len(findings) - limit} more. See the full HTML/SARIF report._")
    return rows


_MERMAID_SAFE = re.compile(r"[^\w .,:/()+*='-]")


def _mermaid_label(text: str) -> str:
    """Node names come from the scanned repo: keep a conservative character set so a label can't
    close its quotes, start a directive or carry markup."""
    text = _MERMAID_SAFE.sub("", " ".join(text.split()))
    return text if len(text) <= 48 else text[:47] + "…"


def _mermaid(path: AttackPathView) -> list[str]:
    out = ["```mermaid", "flowchart LR", '  n0["Internet"]']
    for i, s in enumerate(path.steps, 1):
        out.append(f'  n{i}["{_mermaid_label(s.dst)}"]')
        arrow = f'-- "{_mermaid_label(s.via.replace("_", " "))}" -->' if s.via else "-->"
        out.append(f"  n{i - 1} {arrow} n{i}")
    out.append(f"  style n{len(path.steps)} stroke-width:3px")
    out.append("```")
    return out


def _route(path: AttackPathView) -> str:
    return " → ".join(["Internet", *(_cell(s.dst, 40) for s in path.steps)])


def _change_md(result: ScanResult) -> list[str]:
    """The headline a reviewer needs: does this change open or close a way in?"""
    changes = path_changes(result)
    if changes is None:
        return []
    opened, closed = changes
    out: list[str] = []
    if opened:
        out += [f"### This change opens {len(opened)} new attack path(s)", ""]
        for p in opened[:3]:
            out += [f"**→ {_cell(p.target, 60)}** · {p.confidence} confidence", "", *_mermaid(p), ""]
        if len(opened) > 3:
            out += [f"_…and {len(opened) - 3} more below._", ""]
    if closed:
        out += [f"### This change closes {len(closed)} attack path(s)", ""]
        out += [f"- ~~{_route(p)}~~" for p in closed[:5]] + [""]
    if not opened and not closed:
        out += ["> No change to attack paths compared with the base branch.", ""]
    return out


def _coverage_md(result: ScanResult) -> list[str]:
    cov = result.attack_graph.coverage if result.attack_graph else None
    return [f"_{_cell(cov.line(), 600)}_", ""] if cov else []


def _attack_paths_md(result: ScanResult) -> list[str]:
    ag = result.attack_graph
    if ag is None or not ag.enabled:
        return []
    if not ag.paths:
        if ag.stats.get("crown_jewels", 0):
            return [
                "> **No attack path** found from the internet to a crown-jewel asset.",
                "",
                *_coverage_md(result),
            ]
        return _coverage_md(result)
    out = [f"### Attack paths ({len(ag.paths)})", "", *_coverage_md(result)]
    out.append(
        "An attacker on the internet can reach a high-value asset by chaining these steps. "
        "Bold steps need a real vulnerability; fix any one and the path breaks."
    )
    out.append("")
    for i, p in enumerate(ag.paths[:8], 1):
        flag = " · **blocks merge**" if p.gating else ""
        tag = "" if p.is_new or not result.baseline_used else " _(pre-existing)_"
        out.append(
            f"**Path {i} → {_cell(p.target, 60)}** · risk {p.score} · {p.confidence} confidence{flag}{tag}"
        )
        chain = []
        for s in p.steps:
            if s.via:
                loc = f", `{s.evidence_path}:{s.evidence_line}`" if s.evidence_path else ""
                chain.append(f"**{_cell(s.dst, 40)}** ({s.via.replace('_', ' ')}{loc})")
            else:
                chain.append(_cell(s.dst, 40))
        out.append("`Internet` → " + " → ".join(chain))
        if p.techniques:
            out.append("")
            out.append("MITRE ATT&CK: " + ", ".join(f"[{t}]({technique_url(t)})" for t in p.techniques))
        out.append("")
    if ag.choke_points:
        out.append("**Fix these first (each breaks the most paths):**")
        for c in ag.choke_points[:5]:
            loc = f" `{c.path}:{c.line}`" if c.path else ""
            out.append(f"- {_cell(c.title, 70)}{loc}, breaks {c.paths_cut} path(s)")
        out.append("")
    if ag.skipped:
        out.append(f"<details><summary>Attack-graph blind spots ({len(ag.skipped)})</summary>\n")
        out += [f"- {_cell(s, 200)}" for s in ag.skipped[:20]]
        out += ["", "</details>", ""]
    return out


def _ai_md(findings: list[Finding], link_base: str | None, limit: int = 10) -> list[str]:
    triaged = [(f, f.ai) for f in findings if f.ai][:limit]
    if not triaged:
        return []
    out = [f"<details><summary>AI triage: verdicts and fixes ({len(triaged)})</summary>", ""]
    for f, ai in triaged:
        out += [
            f"**{_cell(f.title, 100)}** · {_where(f, link_base)} · "
            f"**{ai.verdict.label}** ({ai.confidence.value} confidence)",
            "",
            _plain(ai.reasoning, 900),
            "",
        ]
        if ai.remediation:
            out += [f"**Fix:** {_plain(ai.remediation, 500)}", ""]
        if ai.fix_code:
            out += [*_fenced(ai.fix_code, f.location.path), ""]
    out += [
        f"_AI-assisted ({_cell(triaged[0][1].model, 40)}). Advisory only: it does not affect the "
        "gate. Check a fix before applying it._",
        "",
        "</details>",
        "",
    ]
    return out


def render(result: ScanResult, link_base: str | None = None, details_url: str | None = None) -> str:
    gate = result.gate
    head = "Security gate passed" if gate.passed else "Security gate failed"
    out = [MARKER, f"## breachgraph: {head}", ""]
    if gate.reasons:
        out.append("> " + "; ".join(gate.reasons) + f" (threshold: {gate.threshold})")
    else:
        out.append(f"> No findings at or above the threshold ({gate.threshold}).")
    out.append("")

    def count(status: Status, prio: Priority) -> int:
        return sum(1 for f in result.findings if f.status is status and f.priority is prio)

    out += ["| | P1 | P2 | P3 | P4 |", "|---|---|---|---|---|"]
    rows = [(Status.NEW, "New" if result.baseline_used else "Open")]
    if result.baseline_used:
        rows.append((Status.BASELINE, "Baseline"))
    rows.append((Status.SUPPRESSED, "Suppressed"))
    for status, label in rows:
        out.append(f"| **{label}** | " + " | ".join(str(count(status, p)) for p in Priority) + " |")
    out.append("")

    tools = ", ".join(
        f"{t.name} ({t.findings})"
        if t.status is ToolStatus.OK
        else f"{t.name} ({_TOOL_STATUS[t.status]}{f', {t.findings}' if t.findings else ''})"
        for t in result.tools
    )
    out += [f"**Scanners:** {tools}", ""]

    out += _change_md(result)
    out += _attack_paths_md(result)

    gating = [f for f in result.findings if f.gating]
    if gating:
        out += ["### Must fix before merge", *_table(gating, link_base, 25), ""]
    others = [f for f in result.findings if f.status is Status.NEW and not f.gating]
    if others:
        scope = "new " if result.baseline_used else ""
        out += [
            f"<details><summary>Other {scope}findings ({len(others)})</summary>",
            "",
            *_table(others, link_base, 50),
            "",
            "</details>",
            "",
        ]
    out += _ai_md([*gating, *others], link_base)
    if result.warnings:
        out += ["<details><summary>Warnings</summary>", ""]
        out += [f"- {_cell(w, 300)}" for w in result.warnings]
        out += ["", "</details>", ""]
    if details_url:
        out.append(f"[Full report and artifacts]({details_url})")
    text = "\n".join(out)
    if len(text) > _MAX_CHARS:
        text = text[:_MAX_CHARS] + "\n\n_Report truncated. See the full report artifact._"
    return text
