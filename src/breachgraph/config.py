"""`.breachgraph.yml` schema. Every field has a safe default so an empty file (or none) works."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from breachgraph.models import Priority, Severity

CONFIG_FILENAMES = (".breachgraph.yml", ".breachgraph.yaml")

DEFAULT_EXCLUDES = [
    ".git/",
    "node_modules/",
    "**/.venv/",
    "**/venv/",
    "**/__pycache__/",
    "**/dist/",
    "**/build/",
    "**/.terraform/",
    "breachgraph-report/",
]

DEFAULT_DEPRIORITIZE = [
    "tests/",
    "test/",
    "**/__tests__/",
    "spec/",
    "**/*_test.go",
    "**/test_*.py",
    "**/*_test.py",
    "**/*.test.js",
    "**/*.test.ts",
    "**/*.spec.js",
    "**/*.spec.ts",
    "docs/",
    "**/fixtures/",
    "**/testdata/",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScannerConfig(_Strict):
    enabled: bool = True
    timeout: int | None = None  # seconds; falls back to Config.timeout
    extra_args: list[str] = Field(default_factory=list)


class SemgrepConfig(ScannerConfig):
    config: list[str] = Field(default_factory=lambda: ["p/default"])


class GitleaksConfig(ScannerConfig):
    scan_history: bool = False  # True = scan every commit (slower, finds removed secrets)


TrivyScanner = Literal["vuln", "misconfig", "license"]


def _default_trivy_scanners() -> list[TrivyScanner]:
    return ["vuln", "misconfig"]


class TrivyConfig(ScannerConfig):
    scanners: list[TrivyScanner] = Field(default_factory=_default_trivy_scanners)
    sbom: bool = True  # also emit a CycloneDX SBOM artifact
    ignore_unfixed: bool = False
    # Don't query package registries (Maven Central...) to resolve dependencies. Faster and
    # air-gap friendly, but transitive Java dependencies are not resolved.
    offline_scan: bool = False
    images: list[str] = Field(default_factory=list)  # container images to scan, e.g. "app:latest"


class CheckovConfig(ScannerConfig):
    frameworks: list[str] = Field(default_factory=list)  # empty = checkov's auto-detection


class Scanners(_Strict):
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    gitleaks: GitleaksConfig = Field(default_factory=GitleaksConfig)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    checkov: CheckovConfig = Field(default_factory=CheckovConfig)
    zizmor: ScannerConfig = Field(default_factory=ScannerConfig)
    cicd: ScannerConfig = Field(default_factory=ScannerConfig)  # built in: no binary needed


class FailOn(_Strict):
    # Fail on findings at this priority or more urgent. P1 by default: on real projects P2 blocks
    # hundreds of findings per repo (docs/benchmark.md), and attack paths, KEV CVEs and secrets
    # gate separately below.
    priority: Priority | None = Priority.P1
    severity: Severity | None = None  # alternatively/additionally fail on raw severity
    kev: bool = True  # any finding with a CISA KEV CVE fails the gate
    secrets: bool = True  # any verified-format secret fails regardless of priority
    new_only: bool = True  # with a baseline, only findings not in it can fail the gate
    scanner_errors: bool = False  # a crashed scanner fails the gate (exit 3)


class Suppression(_Strict):
    """Accepted risk. Must say why, and (by default) when it should be looked at again."""

    fingerprint: str | None = None
    rule: str | None = None  # rule id, e.g. "CKV_AWS_20" or "python.flask.security...."
    vuln: str | None = None  # CVE/GHSA id
    path: str | None = None  # glob, narrows rule/vuln matches
    reason: str
    expires: date | None = None
    owner: str | None = None

    @model_validator(mode="after")
    def _has_selector(self) -> Suppression:
        if not (self.fingerprint or self.rule or self.vuln):
            raise ValueError("a suppression needs at least one of: fingerprint, rule, vuln")
        if not self.reason.strip():
            raise ValueError("a suppression needs a non-empty reason")
        return self


class Enrich(_Strict):
    kev: bool = True
    epss: bool = True
    cache_hours: int = 24


class SeverityOverride(_Strict):
    rule: str
    severity: Severity


class CrownJewel(_Strict):
    """Mark an asset as high value so attack paths that reach it are prioritized."""

    match: str  # substring/glob matched against the node name and id (e.g. "customer", "*prod*")
    value: int = Field(default=9, ge=0, le=10)
    kind: str | None = None  # restrict to one node kind: datastore, secret, identity...


class AIConfig(_Strict):
    """Optional AI-assisted triage. Bring your own Anthropic API key (ANTHROPIC_API_KEY).

    breachgraph never spends tokens on your behalf: this is off unless you enable it and a key
    is present. For the top findings it gives a real / likely-false-positive / needs-review verdict
    with reasoning and a concrete fix, from the enclosing code, route and attack-path context. It
    does not change the gate, and it never generates exploit code.
    """

    enabled: bool = False
    model: str = "claude-opus-5-5"  # any Anthropic model id; set a cheaper one to save cost
    max_findings: int = Field(default=10, ge=1, le=100)  # triage at most this many top findings
    max_usd: float = Field(default=1.0, gt=0)  # never start a request that could exceed this spend
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "low"  # reasoning depth vs cost
    # USD per 1M tokens as [input, output], merged over the built-in list prices. Use it when
    # Anthropic changes a price, for a model breachgraph doesn't know yet, or for a negotiated rate.
    prices: dict[str, tuple[float, float]] = Field(default_factory=dict)


class ReachabilityConfig(_Strict):
    enabled: bool = True
    deprioritize_unused: bool = True  # lower the score of CVEs in packages first-party code never imports
    gate_on_unused: bool = False  # if False, an unused-dependency CVE alone won't fail the gate


EntryPoint = Literal["internet", "credentials", "cluster"]


def _default_entries() -> list[EntryPoint]:
    return ["internet"]


class AttackGraph(_Strict):
    enabled: bool = True
    crown_value: int = Field(default=7, ge=1, le=10)  # a node at/above this value is a crown jewel
    crown_jewels: list[CrownJewel] = Field(default_factory=list)
    max_depth: int = 12
    max_paths: int = 40
    fail_on_new_path: bool = True  # a PR that introduces an internet->crown-jewel path fails
    min_confidence: Literal["high", "medium", "low"] = "medium"  # paths below this don't gate
    # Where attackers start. "internet" always applies. "credentials": long-lived cloud keys that
    # Terraform manages are assumed leaked. "cluster": an attacker already inside the cluster
    # network (a compromised neighbor pod) can reach every workload.
    entry_points: list[EntryPoint] = Field(default_factory=_default_entries)


class VexConfig(_Strict):
    """OpenVEX output (`--format openvex`), built from dependency reachability."""

    author: str = "breachgraph"  # who issues the statements: a team email or IRI is best
    # Product @id (a purl that appears in your SBOM / scan). Default: the manifest's own root
    # component when it has one (pom.xml, go.mod, package.json), else each package stands alone.
    product: str | None = None
    not_affected: bool = True  # False: never claim not_affected from import-level reachability


class Config(_Strict):
    version: Literal[1] = 1
    scanners: Scanners = Field(default_factory=Scanners)
    exclude_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    deprioritize_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_DEPRIORITIZE))
    fail_on: FailOn = Field(default_factory=FailOn)
    suppressions: list[Suppression] = Field(default_factory=list)
    require_suppression_expiry: bool = True
    severity_overrides: list[SeverityOverride] = Field(default_factory=list)
    enrich: Enrich = Field(default_factory=Enrich)
    reachability: ReachabilityConfig = Field(default_factory=ReachabilityConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    attack_graph: AttackGraph = Field(default_factory=AttackGraph)
    vex: VexConfig = Field(default_factory=VexConfig)
    timeout: int = 900

    @model_validator(mode="after")
    def _expiry_required(self) -> Config:
        if self.require_suppression_expiry:
            missing = [s.fingerprint or s.rule or s.vuln for s in self.suppressions if not s.expires]
            if missing:
                raise ValueError(
                    "suppressions must set 'expires' (or set require_suppression_expiry: false): "
                    + ", ".join(str(m) for m in missing)
                )
        return self


class ConfigError(Exception):
    pass


def find_config(target: Path) -> Path | None:
    for name in CONFIG_FILENAMES:
        candidate = target / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{path} is invalid:\n{exc}") from exc
