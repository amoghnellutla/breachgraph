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
    CICD = "cicd"  # CI/CD pipelines and supply chain


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


class Reachability(StrEnum):
    """Whether a vulnerable dependency is actually used by first-party code.

    This is *import-level* reachability, not a full interprocedural call graph: it answers
    "does our code use this package, and can a request reach the code that does?".
    """

    ENTRYPOINT = "entrypoint"  # imported by a module reachable from an HTTP entry point
    DIRECT = "direct"  # imported in first-party code, no entry point traced to it
    UNUSED = "unused"  # declared/transitive but never imported in first-party code
    UNKNOWN = "unknown"  # ecosystem not analyzed, or no source to analyze

    @property
    def rank(self) -> int:
        return {"entrypoint": 3, "direct": 2, "unknown": 1, "unused": 0}[self.value]


class Package(BaseModel):
    name: str
    version: str | None = None
    fixed_version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None  # package URL, e.g. pkg:pypi/requests@2.25.1
    # Packages that (transitively) depend on this one, from the manifest's dependency graph.
    dependents: list[str] = Field(default_factory=list)
    dependency_graph: bool = False  # True when the manifest/lockfile said who depends on what
    root_purl: str | None = None  # the project that declares this dependency, when the manifest names it
    reachability: Reachability | None = None
    reach_evidence: list[str] = Field(default_factory=list)  # "file imports <name>"
    # Function level (Go, from the Go vulnerability database): the vulnerable symbols, and
    # whether first-party code calls one. None: not known for this ecosystem or advisory.
    vulnerable_functions: list[str] = Field(default_factory=list)
    function_called: bool | None = None


class Enrichment(BaseModel):
    kev: bool = False
    kev_date_added: str | None = None
    kev_ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None


class AIVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_REVIEW = "needs_review"

    @property
    def label(self) -> str:
        return {"true_positive": "real", "likely_false_positive": "likely false positive"}.get(
            self.value, "needs review"
        )


class AIInsight(BaseModel):
    """AI-assisted triage for one finding. Advisory only: it never changes the gate on its own."""

    verdict: AIVerdict
    confidence: Confidence = Confidence.MEDIUM
    summary: str  # one-line plain-English explanation
    reasoning: str  # why, grounded in the code/config evidence
    remediation: str  # concrete fix guidance, prose
    fix_code: str = ""  # corrected code for the flagged lines, if a code change applies
    model: str = ""  # the model that actually answered (may differ after a refusal fallback)


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
    ai: AIInsight | None = None  # optional AI-assisted triage

    @property
    def cves(self) -> list[str]:
        return [v for v in self.vuln_ids if v.upper().startswith("CVE-")]


class ToolStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"
    IMPORTED = "imported"
    REUSED = "reused"  # incremental scan: nothing it reads changed, so the base report's findings stand


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


class AttackStep(BaseModel):
    src: str  # node display name
    dst: str
    dst_kind: str
    kind: str  # edge kind
    via: str | None = None  # weakness class used to cross
    weakness_title: str | None = None
    note: str = ""
    confidence: str = "high"
    evidence_path: str | None = None
    evidence_line: int | None = None
    techniques: list[str] = Field(default_factory=list)  # MITRE ATT&CK ids, e.g. "T1190"


class AttackPathView(BaseModel):
    id: str = ""  # stable across runs: entry, target and the findings it needs (see graph.summary)
    node_ids: list[str] = Field(default_factory=list)
    target: str
    target_kind: str
    score: float
    confidence: str
    length: int
    is_new: bool = True  # introduces a path not present in the baseline
    gating: bool = False
    steps: list[AttackStep] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)  # fingerprints of findings on the path
    techniques: list[str] = Field(default_factory=list)  # MITRE ATT&CK ids along the path, in order


class ChokePointView(BaseModel):
    title: str
    weakness: str
    paths_cut: int
    fingerprint: str | None = None
    path: str | None = None
    line: int | None = None


class GraphWeakness(BaseModel):
    title: str
    cls: str
    fingerprint: str | None = None
    location: str | None = None  # "path:line"


class GraphNodeView(BaseModel):
    id: str
    name: str
    kind: str
    value: int = 0
    evidence: list[str] = Field(default_factory=list)  # "path:line"
    weaknesses: list[GraphWeakness] = Field(default_factory=list)


class GraphEdgeView(BaseModel):
    src: str
    dst: str
    kind: str
    requires: list[str] = Field(default_factory=list)
    confidence: str = "high"
    note: str = ""
    evidence: str | None = None


class GraphExport(BaseModel):
    """The part of the graph the attack paths run through, for the interactive explorer."""

    nodes: list[GraphNodeView] = Field(default_factory=list)
    edges: list[GraphEdgeView] = Field(default_factory=list)
    truncated: bool = False


class Coverage(BaseModel):
    """What the attack graph modeled, and what it could not, so "no paths" is never read as "safe"
    when the inputs were thin."""

    routes: int = 0
    workloads: int = 0
    cloud_resources: int = 0
    kubernetes_objects: int = 0
    ci_jobs: int = 0
    crown_jewels: int = 0
    missing_scanners: list[str] = Field(default_factory=list)  # e.g. "semgrep (not installed)"
    blind_spots: int = 0
    gaps: list[str] = Field(default_factory=list)  # why the result is incomplete
    complete: bool = True

    def line(self) -> str:
        modeled = (
            f"{self.routes} HTTP routes, {self.workloads} workloads, {self.cloud_resources} cloud resources, "
            f"{self.kubernetes_objects} Kubernetes objects, {self.ci_jobs} CI jobs, "
            f"{self.crown_jewels} crown jewels"
        )
        if self.complete:
            return f"Modeled: {modeled}. No coverage gaps detected."
        return f"Modeled: {modeled}. Incomplete: {'; '.join(self.gaps)}."


class AttackGraphSummary(BaseModel):
    enabled: bool = True
    paths: list[AttackPathView] = Field(default_factory=list)
    choke_points: list[ChokePointView] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    graph: GraphExport | None = None
    coverage: Coverage | None = None

    @property
    def gating_paths(self) -> list[AttackPathView]:
        return [p for p in self.paths if p.gating]


class Comparison(BaseModel):
    """What changed against a base report (e.g. the default branch), for PR headlines."""

    base_version: str = ""
    base_started_at: datetime | None = None
    new_paths: list[str] = Field(default_factory=list)  # ids of paths absent from the base
    resolved_paths: list[AttackPathView] = Field(default_factory=list)  # in the base, gone now
    new_findings: int = 0
    resolved_findings: int = 0
    policy_changes: list[str] = Field(default_factory=list)  # gate settings that differ from the base


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
    attack_graph: AttackGraphSummary | None = None
    comparison: Comparison | None = None
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
