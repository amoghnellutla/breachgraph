"""An audit evidence pack: one zip with what an auditor asks for after a security scan.

Inside: the full JSON report, SARIF, the HTML report, the SBOM and OpenVEX when present, the
policy the gate ran with (thresholds, suppressions with reasons and expiry dates), a plain-language
summary, and a manifest with the SHA-256 of every file so the pack can be checked later.

The summary lists the controls this kind of evidence is commonly used for. It does not claim a
control is met: that is the auditor's call, and it depends on the process around the tool.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from breachgraph.models import ScanResult, Status

PACK = "breachgraph-evidence.zip"

# Where scan evidence like this is usually requested. Wording is deliberately "supports".
CONTROLS = [
    ("SOC 2 CC7.1", "Detection of vulnerabilities and configuration changes that introduce them"),
    ("SOC 2 CC8.1", "Changes are checked before they are deployed (the gate decision per change)"),
    ("ISO/IEC 27001:2022 A.8.8", "Management of technical vulnerabilities"),
    ("ISO/IEC 27001:2022 A.8.25, A.8.28", "Secure development life cycle and secure coding"),
    (
        "PCI DSS v4.0 6.3.1, 6.3.2",
        "Vulnerabilities identified; inventory of bespoke and third-party components (SBOM)",
    ),
    (
        "NIST SP 800-218 (SSDF) PW.7, PW.8, RV.1",
        "Code review and testing for vulnerabilities; ongoing identification",
    ),
]


def write_pack(result: ScanResult, out_dir: Path, rendered: dict[str, str]) -> Path:
    """Write the zip. ``rendered`` maps file names to report text produced in the same run."""
    files: dict[str, bytes] = {name: text.encode("utf-8") for name, text in rendered.items()}
    for name in ("sbom",):
        src = result.artifacts.get(name)
        if src and Path(src).is_file():
            files[Path(src).name] = Path(src).read_bytes()
    files["policy.json"] = json.dumps(_policy(result), indent=2).encode("utf-8")
    files["SUMMARY.md"] = summary(result).encode("utf-8")
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "breachgraph_version": result.breachgraph_version,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
    }
    files["manifest.json"] = json.dumps(manifest, indent=2).encode("utf-8")
    path = out_dir / PACK
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
    return path


def _policy(result: ScanResult) -> dict[str, Any]:
    policy = dict(result.metadata.get("policy") or {})
    policy["suppressed_findings"] = [
        {"fingerprint": f.fingerprint, "title": f.title, "location": _loc(f), "reason": f.suppression_reason}
        for f in result.findings
        if f.status is Status.SUPPRESSED
    ]
    return policy


def _loc(f: Any) -> str:
    return f"{f.location.path}:{f.location.start_line}" if f.location.start_line else f.location.path


def _scan_identity(result: ScanResult) -> list[str]:
    env = os.environ
    rows = [
        ("Project", str(result.metadata.get("project") or result.target)),
        ("Repository", env.get("GITHUB_REPOSITORY", "")),
        ("Commit", env.get("GITHUB_SHA", "")),
        ("Ref", env.get("GITHUB_REF_NAME", "")),
        (
            "CI run",
            f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
            if all(k in env for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
            else "",
        ),
        ("Started", result.started_at.isoformat(timespec="seconds")),
        ("Finished", result.finished_at.isoformat(timespec="seconds") if result.finished_at else ""),
        ("breachgraph", result.breachgraph_version),
    ]
    return [f"| {k} | {v} |" for k, v in rows if v]


def summary(result: ScanResult) -> str:
    gate = result.gate
    ag = result.attack_graph
    open_counts = result.counts_by("priority")
    lines = [
        "# Security scan evidence",
        "",
        "| | |",
        "|---|---|",
        *_scan_identity(result),
        "",
        "## Gate decision",
        "",
        f"**{'Passed' if gate.passed else 'Failed'}**. Threshold: {gate.threshold or 'n/a'}.",
        "",
        *[f"- {r}" for r in gate.reasons],
        "",
        "## Scanners",
        "",
        "| Scanner | Status | Version | Findings |",
        "|---|---|---|---|",
        *[f"| {t.name} | {t.status.value} | {t.version or ''} | {t.findings} |" for t in result.tools],
        "",
        "## Findings",
        "",
        "| Priority | Open |",
        "|---|---|",
        *[f"| {p} | {open_counts.get(p, 0)} |" for p in ("P1", "P2", "P3", "P4")],
        "",
        f"Suppressed: {sum(1 for f in result.findings if f.status is Status.SUPPRESSED)} "
        "(each with its reason in policy.json).",
        "",
    ]
    if ag is not None:
        lines += ["## Attack paths", ""]
        if ag.coverage:
            lines += [ag.coverage.line(), ""]
        lines += [
            f"- {' -> '.join(['Internet', *(s.dst for s in p.steps)])} ({p.confidence} confidence"
            f"{', blocks merge' if p.gating else ''})"
            for p in ag.paths
        ] or ["No attack path from the internet to a crown-jewel asset."]
        lines.append("")
    suppressions = (result.metadata.get("policy") or {}).get("suppressions") or []
    lines += ["## Accepted risks", ""]
    lines += [f"- {s}" for s in suppressions] or ["None."]
    lines += [
        "",
        "## Controls this evidence supports",
        "",
        "Commonly requested for the controls below. Whether a control is met is the auditor's",
        "decision and depends on the process around this scan.",
        "",
        *[f"- **{c}**: {why}" for c, why in CONTROLS],
        "",
        "## Integrity",
        "",
        "manifest.json lists the SHA-256 of every file in this pack.",
        "",
    ]
    return "\n".join(lines)
