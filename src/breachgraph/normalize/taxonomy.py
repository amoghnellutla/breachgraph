"""CWE / OWASP Top 10 (2021) normalization.

The CWE -> OWASP mapping follows the official OWASP Top 10:2021 category pages.
"""

from __future__ import annotations

import re

from breachgraph.models import Category

OWASP_2021_NAMES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

# fmt: off
_OWASP_CWES: dict[str, tuple[int, ...]] = {
    "A01:2021": (
        22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425,
        441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275
    ),
    "A02:2021": (
        261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336,
        337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916
    ),
    "A03:2021": (
        20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113,
        116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917
    ),
    "A04:2021": (
        73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434,
        444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799,
        807, 840, 841, 927, 1021, 1173
    ),
    "A05:2021": (
        2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004,
        1032, 1174
    ),
    "A06:2021": (937, 1035, 1104),
    "A07:2021": (
        255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613,
        620, 640, 798, 940, 1216
    ),
    "A08:2021": (345, 353, 426, 494, 502, 565, 784, 829, 830, 915),
    "A09:2021": (117, 223, 532, 778),
    "A10:2021": (918,),
}
# fmt: on

CWE_TO_OWASP: dict[str, str] = {f"CWE-{cwe}": cat for cat, cwes in _OWASP_CWES.items() for cwe in cwes}

CATEGORY_DEFAULT_OWASP = {
    Category.SCA: "A06:2021",
    Category.CONTAINER: "A06:2021",
    Category.SECRETS: "A07:2021",
    Category.IAC: "A05:2021",
    Category.CICD: "A08:2021",  # software and data integrity failures
}

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
_OWASP_RE = re.compile(r"A(\d{1,2})[:_ -]?(20\d\d)", re.IGNORECASE)
_CICD_RE = re.compile(r"CICD-SEC-(\d{1,2})", re.IGNORECASE)


def normalize_cwes(values: list[str] | str | None) -> list[str]:
    """'CWE-89: Improper Neutralization...' / 'cwe_89' / 89 -> 'CWE-89' (deduped, ordered)."""
    if values is None:
        return []
    items = [values] if isinstance(values, (str, int)) else values
    out: list[str] = []
    for item in items:
        text = str(item)
        m = _CWE_RE.search(text)
        if m:
            cwe = f"CWE-{int(m.group(1))}"
        elif text.strip().isdigit():
            cwe = f"CWE-{int(text.strip())}"
        else:
            continue
        if cwe not in out:
            out.append(cwe)
    return out


def normalize_owasp(values: list[str] | str | None) -> list[str]:
    """'A03:2021 - Injection' -> 'A03:2021', 'cicd-sec-4' -> 'CICD-SEC-4'. Non-2021 labels are
    kept in canonical form."""
    if values is None:
        return []
    items = [values] if isinstance(values, str) else values
    out: list[str] = []
    for item in items:
        if m := _OWASP_RE.search(str(item)):
            label = f"A{int(m.group(1)):02d}:{m.group(2)}"
        elif c := _CICD_RE.search(str(item)):
            label = f"CICD-SEC-{int(c.group(1))}"
        else:
            continue
        if label not in out:
            out.append(label)
    return out


def owasp_for(cwes: list[str], category: Category) -> list[str]:
    out: list[str] = []
    for cwe in cwes:
        cat = CWE_TO_OWASP.get(cwe)
        if cat and cat not in out:
            out.append(cat)
    if not out and category in CATEGORY_DEFAULT_OWASP:
        out.append(CATEGORY_DEFAULT_OWASP[category])
    return out


# OWASP Top 10 CI/CD Security Risks (https://owasp.org/www-project-top-10-ci-cd-security-risks/).
CICD_RISKS: dict[str, str] = {
    "CICD-SEC-1": "Insufficient Flow Control Mechanisms",
    "CICD-SEC-2": "Inadequate Identity and Access Management",
    "CICD-SEC-3": "Dependency Chain Abuse",
    "CICD-SEC-4": "Poisoned Pipeline Execution",
    "CICD-SEC-5": "Insufficient PBAC (Pipeline-Based Access Controls)",
    "CICD-SEC-6": "Insufficient Credential Hygiene",
    "CICD-SEC-7": "Insecure System Configuration",
    "CICD-SEC-8": "Ungoverned Usage of 3rd Party Services",
    "CICD-SEC-9": "Improper Artifact Integrity Validation",
    "CICD-SEC-10": "Insufficient Logging and Visibility",
}
# Rule id (built-in checks and zizmor audits) -> risk.
_CICD_RULES: dict[str, str] = {
    "cicd/script-injection": "CICD-SEC-4",
    "cicd/untrusted-checkout": "CICD-SEC-4",
    "supply-chain/dependency-confusion": "CICD-SEC-3",
    "template-injection": "CICD-SEC-4",
    "dangerous-triggers": "CICD-SEC-4",
    "github-env": "CICD-SEC-4",
    "bot-conditions": "CICD-SEC-1",
    "excessive-permissions": "CICD-SEC-5",
    "undocumented-permissions": "CICD-SEC-5",
    "unpinned-uses": "CICD-SEC-3",
    "unpinned-images": "CICD-SEC-3",
    "impostor-commit": "CICD-SEC-3",
    "ref-confusion": "CICD-SEC-3",
    "ref-version-mismatch": "CICD-SEC-3",
    "stale-action-refs": "CICD-SEC-3",
    "known-vulnerable-actions": "CICD-SEC-3",
    "archived-uses": "CICD-SEC-3",
    "dependabot-cooldown": "CICD-SEC-3",
    "dependabot-execution": "CICD-SEC-3",
    "forbidden-uses": "CICD-SEC-8",
    "artipacked": "CICD-SEC-6",
    "secrets-inherit": "CICD-SEC-6",
    "overprovisioned-secrets": "CICD-SEC-6",
    "unredacted-secrets": "CICD-SEC-6",
    "secrets-outside-env": "CICD-SEC-6",
    "hardcoded-container-credentials": "CICD-SEC-6",
    "use-trusted-publishing": "CICD-SEC-6",
    "cache-poisoning": "CICD-SEC-9",
    "self-hosted-runner": "CICD-SEC-7",
    "insecure-commands": "CICD-SEC-7",
    "obfuscation": "CICD-SEC-7",
    "concurrency-limits": "CICD-SEC-7",
    "anonymous-definition": "CICD-SEC-10",
}


def cicd_risk(rule_id: str) -> str | None:
    """The CI/CD risk for a rule id such as "template-injection" or "zizmor/template-injection"."""
    return _CICD_RULES.get(rule_id) or _CICD_RULES.get(rule_id.rsplit("/", 1)[-1])
