"""Tool-agnostic data model shared by every scanner adapter, the policy engine and reporters."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from breachgraph.paths import normalize_path


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | None, default: Severity | None = None) -> Severity:
        """Map the many spellings scanners use (ERROR, WARNING, UNKNOWN, moderate...) onto ours."""
        if value is None:
            return default or cls.MEDIUM
        key = str(value).strip().lower()
        if key in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[key]
        return default or cls.MEDIUM


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_SEVERITY_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "blocker": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "important": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.MEDIUM,
}


class Category(StrEnum):
    SAST = "sast"
    SECRETS = "secrets"
    SCA = "sca"
    IAC = "iac"
    CONTAINER = "container"
    DAST = "dast"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

    @property
    def rank(self) -> int:
        """Higher is more urgent: P1 -> 4 ... P4 -> 1."""
        return 5 - int(self.value[1])


class Status(StrEnum):
    NEW = "new"
    BASELINE = "baseline"  # present in the accepted baseline
    SUPPRESSED = "suppressed"


class Location(BaseModel):
    path: str  # repo-relative POSIX path; a URL (DAST) or image reference when in_repo is False
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    in_repo: bool = True

    @field_validator("path")
    @classmethod
    def _normalize(cls, value: str) -> str:
        return normalize_path(value)


class Package(BaseModel):
    name: str
    version: str | None = None
    fixed_version: str | None = None
    ecosystem: str | None = None


class Enrichment(BaseModel):
    kev: bool = False
    kev_date_added: str | None = None
    kev_ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None


class Finding(BaseModel):
    fingerprint: str = ""
    tool: str
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    category: Category
    confidence: Confidence = Confidence.MEDIUM
    location: Location
    cwe: list[str] = Field(default_factory=list)  # normalized "CWE-89"
    owasp: list[str] = Field(default_factory=list)  # normalized "A03:2021"
    vuln_ids: list[str] = Field(default_factory=list)  # CVE-/GHSA- identifiers
    cvss: float | None = None
    package: Package | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)

    # Populated by the pipeline after parsing.
    sources: list[str] = Field(default_factory=list)  # every tool that reported it (after dedupe)
    related_rules: list[str] = Field(default_factory=list)
    fingerprints: list[str] = Field(default_factory=list)  # all fingerprints merged into this one
    enrichment: Enrichment = Field(default_factory=Enrichment)
    risk_score: float = 0.0
    priority: Priority = Priority.P4
    score_reasons: list[str] = Field(default_factory=list)
    status: Status = Status.NEW
    suppression_reason: str | None = None
    gating: bool = False  # True when this finding causes the gate to fail

    @property
    def cves(self) -> list[str]:
        return [v for v in self.vuln_ids if v.upper().startswith("CVE-")]


class ToolStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"
    IMPORTED = "imported"


class ToolRun(BaseModel):
    name: str
    status: ToolStatus
    version: str | None = None
    duration_s: float = 0.0
    findings: int = 0
    message: str | None = None


class GateResult(BaseModel):
    passed: bool
    reasons: list[str] = Field(default_factory=list)
    threshold: str = ""


class ScanResult(BaseModel):
    breachgraph_version: str
    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    tools: list[ToolRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    gate: GateResult = Field(default_factory=lambda: GateResult(passed=True))
    baseline_used: bool = False
    warnings: list[str] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)  # e.g. {"sbom": "path"}
    metadata: dict[str, Any] = Field(default_factory=dict)

    def counts_by(
        self, attr: str, statuses: tuple[Status, ...] = (Status.NEW, Status.BASELINE)
    ) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            if f.status not in statuses:
                continue
            key = str(getattr(f, attr))
            out[key] = out.get(key, 0) + 1
        return out
