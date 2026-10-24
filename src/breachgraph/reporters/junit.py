"""JUnit XML: lets CI systems without SARIF support (Jenkins, GitLab, Azure DevOps) show
gating findings as failed tests."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict

from breachgraph.models import Finding, ScanResult, Status


def render(result: ScanResult) -> str:
    by_tool: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        if f.status is not Status.SUPPRESSED:
            by_tool[f.tool].append(f)
    suites = ET.Element("testsuites", name="breachgraph")
    for tool, findings in sorted(by_tool.items()):
        failures = sum(1 for f in findings if f.gating)
        suite = ET.SubElement(
            suites, "testsuite", name=tool, tests=str(len(findings)), failures=str(failures)
        )
        for f in findings:
            loc = f.location.path + (f":{f.location.start_line}" if f.location.start_line else "")
            case = ET.SubElement(
                suite,
                "testcase",
                classname=f"{tool}.{f.category.value}",
                name=f"{f.rule_id} @ {loc}",
            )
            body = f"{f.title}\n{'; '.join(f.score_reasons)}\n{f.remediation or ''}".strip()
            if f.gating:
                ET.SubElement(
                    case, "failure", message=f"[{f.priority.value}] {f.title}"[:500]
                ).text = body
            else:
                ET.SubElement(
                    case, "system-out"
                ).text = f"[{f.priority.value}/{f.status.value}] {body}"
    ET.indent(suites)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suites, encoding="unicode") + "\n"
    )
