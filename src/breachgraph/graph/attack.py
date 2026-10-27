"""MITRE ATT&CK (Enterprise) techniques for attack-path steps.

A step is labeled with what an attacker does to cross it, decided from the edge, the weakness used
and the nodes on either side. Labels are for triage and reporting (and SARIF tags); they never
change which paths exist.
"""

from __future__ import annotations

import re

from breachgraph.graph.model import Edge, EdgeKind, Node, NodeKind, WeaknessClass

TECHNIQUES: dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1677": "Poisoned Pipeline Execution",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1552.007": "Unsecured Credentials: Container API",
    "T1528": "Steal Application Access Token",
    "T1611": "Escape to Host",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1530": "Data from Cloud Storage",
    "T1213": "Data from Information Repositories",
    "T1555.006": "Credentials from Password Stores: Cloud Secrets Management Stores",
}

_EXPLOITS = {
    WeaknessClass.CODE_EXECUTION,
    WeaknessClass.INJECTION_DATA,
    WeaknessClass.SSRF,
    WeaknessClass.FILE_READ,
    WeaknessClass.AUTH_BYPASS,
    WeaknessClass.VULNERABLE_DEPENDENCY,
}
_STORAGE = re.compile(r"s3_bucket|gcs_bucket|storage_account|storage_container|bucket|blob", re.I)


def step_techniques(edge: Edge, src: Node, dst: Node, via: WeaknessClass | None) -> list[str]:
    out: list[str] = []
    ci = src.attrs.get("platform") == "github-actions"
    if via in _EXPLOITS:
        out.append("T1677" if ci and via is WeaknessClass.CODE_EXECUTION else "T1190")
    if via is WeaknessClass.SSRF and dst.kind is NodeKind.IDENTITY:
        out.append("T1552.005")
    if via is WeaknessClass.METADATA_REACHABLE:
        out.append("T1552.005")
    if via is WeaknessClass.CREDENTIAL_EXPOSURE or src.id.startswith("entry:key:"):
        out.append("T1552.001" if via else "T1078.004")
    if edge.kind is EdgeKind.RUNS_ON:
        out.append("T1611")
    elif edge.note.startswith("privilege escalation"):
        out.append("T1098.003")
    elif edge.kind is EdgeKind.USES_IDENTITY and via is not WeaknessClass.SSRF:
        out.append("T1528" if dst.id.startswith("k8s:") or ci else "T1078.004")
    elif edge.kind is EdgeKind.CAN_ACCESS and dst.kind is NodeKind.IDENTITY:
        out.append("T1078.004")  # assuming or impersonating another identity
    if dst.kind is NodeKind.SECRET:
        out.append("T1552.007" if dst.id.startswith("k8s:") else "T1555.006")
    elif dst.kind is NodeKind.DATASTORE:
        out.append("T1530" if _STORAGE.search(dst.id) else "T1213")
    return list(dict.fromkeys(out))


def technique_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"
