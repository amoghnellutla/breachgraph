"""Markdown summary for PR comments and $GITHUB_STEP_SUMMARY."""

from __future__ import annotations

from secgate.models import Finding, Priority, ScanResult, Status, ToolStatus

MARKER = "<!-- secgate-report -->"
_MAX_CHARS = 60_000  # GitHub comments are capped at 65,536 characters
_PRIO_ICON = {Priority.P1: "🔴", Priority.P2: "🟠", Priority.P3: "🟡", Priority.P4: "⚪"}
_TOOL_ICON = {
    ToolStatus.OK: "✅",
    ToolStatus.IMPORTED: "📥",
    ToolStatus.SKIPPED: "⏭️",
    ToolStatus.FAILED: "⚠️",
}


def defang(text: str) -> str:
    """Scanner output is untrusted: stop it from @-mentioning people or teams."""
    return text.replace("@", "@​")


def _cell(text: str, limit: int = 120) -> str:
    text = defang(" ".join(text.split()).replace("|", "\\|"))
    return text if len(text) <= limit else text[: limit - 1] + "…"


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
        title = _cell(f.title) + (" " + " ".join(tags) if tags else "")
        rows.append(
            f"| {_PRIO_ICON[f.priority]} {f.priority.value} | {title} | {_where(f, link_base)} "
            f"| {f.severity.value} | {', '.join(f.sources)} |"
        )
    if len(findings) > limit:
        rows.append(f"\n_…and {len(findings) - limit} more. See the full HTML/SARIF report._")
    return rows


def render(result: ScanResult, link_base: str | None = None, details_url: str | None = None) -> str:
    gate = result.gate
    head = "✅ Security gate passed" if gate.passed else "❌ Security gate failed"
    out = [MARKER, f"## 🛡️ secgate: {head}", ""]
    if gate.reasons:
        out.append("> " + "; ".join(gate.reasons) + f" (threshold: {gate.threshold})")
    else:
        out.append(f"> No findings at or above the threshold ({gate.threshold}).")
    out.append("")

    def count(status: Status, prio: Priority) -> int:
        return sum(1 for f in result.findings if f.status is status and f.priority is prio)

    out += ["| | 🔴 P1 | 🟠 P2 | 🟡 P3 | ⚪ P4 |", "|---|---|---|---|---|"]
    rows = [(Status.NEW, "New" if result.baseline_used else "Open")]
    if result.baseline_used:
        rows.append((Status.BASELINE, "Baseline"))
    rows.append((Status.SUPPRESSED, "Suppressed"))
    for status, label in rows:
        out.append(f"| **{label}** | " + " | ".join(str(count(status, p)) for p in Priority) + " |")
    out.append("")

    tools = " · ".join(
        f"{_TOOL_ICON[t.status]} {t.name} ({t.findings})"
        if t.status is not ToolStatus.SKIPPED
        else f"{_TOOL_ICON[t.status]} {t.name} (skipped)"
        for t in result.tools
    )
    out += [f"**Scanners:** {tools}", ""]

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
