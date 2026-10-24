"""Optional AI-assisted triage — bring your own Anthropic API key.

breachgraph never spends tokens on your behalf. This runs only when you turn it on *and* a key is
present (``ANTHROPIC_API_KEY``). It explains findings and attack paths and gives a true/false-
positive verdict with a concrete fix, grounded in the scanner evidence and the attack graph. It is
advisory: it never changes the gate, and it is instructed never to produce exploit code.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from breachgraph.ai.prompts import (
    FINDINGS_SCHEMA,
    NARRATIVE_SYSTEM,
    TRIAGE_SYSTEM,
    build_narrative_prompt,
    build_triage_prompt,
)
from breachgraph.config import AIConfig
from breachgraph.models import AIInsight, AIVerdict, Confidence, Finding, ScanResult, Status

log = logging.getLogger("breachgraph")

# Approx USD per 1M tokens (input, output). Unknown models fall back to the most expensive here.
_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-5-5": (4.0, 20.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-fable-5-1": (10.0, 50.0),
}


class AIUnavailable(Exception):
    """Raised with a friendly, actionable message when AI triage can't run."""


class Refused(Exception):
    """The model declined (safety classifier). Triage degrades to a warning, scan continues."""


@dataclass
class AIRunResult:
    triaged: int = 0
    narrative: bool = False
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    cost_usd: float = 0.0
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"AI triage: {self.triaged} finding(s)"
            + (" + attack-path narrative" if self.narrative else "")
            + f", ~${self.cost_usd:.3f} ({self.model})"
        )


def available() -> tuple[bool, str]:
    """(ready, reason). Checks the SDK and a key without importing anthropic eagerly."""
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False, "the 'anthropic' package is not installed — run: pip install 'breachgraph[ai]'"
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return False, (
            "no Anthropic API key found. Get one at https://console.anthropic.com/ and set it:\n"
            "    export ANTHROPIC_API_KEY=sk-ant-...   (Windows: setx ANTHROPIC_API_KEY sk-ant-...)"
        )
    return True, ""


def _cost(model: str, inp: int, out: int) -> float:
    price_in, price_out = _PRICING.get(model, max(_PRICING.values()))
    return (inp * price_in + out * price_out) / 1_000_000


class _Client:
    """Thin wrapper over the Anthropic SDK with cost tracking and structured output."""

    def __init__(self, cfg: AIConfig) -> None:
        import anthropic

        self._anthropic = anthropic
        self.client = anthropic.Anthropic()
        self.cfg = cfg
        self.input_tokens = 0
        self.output_tokens = 0

    @property
    def cost(self) -> float:
        return _cost(self.cfg.model, self.input_tokens, self.output_tokens)

    def _call(
        self, system: str, prompt: str, schema: dict[str, object] | None, max_tokens: int = 2000
    ) -> str:
        output_config: dict[str, object] = {"effort": self.cfg.effort}
        if schema is not None:
            output_config["format"] = {"type": "json_schema", "name": "triage", "schema": schema}
        # Build params as a dict and splat: keeps us resilient across SDK versions (output_config
        # and structured-output param shapes change), rather than pinning to typed param classes.
        params: dict[str, object] = {
            "model": self.cfg.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": output_config,
        }
        resp = self.client.messages.create(**params)  # type: ignore[call-overload]
        self.input_tokens += resp.usage.input_tokens
        self.output_tokens += resp.usage.output_tokens
        # Safety classifiers can decline (HTTP 200, stop_reason "refusal") — common for security
        # content. Don't parse empty content as a result; signal it so callers degrade gracefully.
        if getattr(resp, "stop_reason", None) == "refusal":
            cat = getattr(getattr(resp, "stop_details", None), "category", None)
            raise Refused(f"model declined to analyze ({cat or 'safety'})")
        return "".join(b.text for b in resp.content if b.type == "text")


def triage(result: ScanResult, cfg: AIConfig, target: Path) -> AIRunResult:
    """Annotate top findings with AI verdicts and write an attack-path narrative, in place."""
    run = AIRunResult(model=cfg.model)
    ready, reason = available()
    if not ready:
        raise AIUnavailable(reason)

    try:
        client = _Client(cfg)
    except Exception as exc:
        raise AIUnavailable(f"could not initialize the Anthropic client: {exc}") from exc

    # Pick the findings worth the spend: gating first, then highest risk, capped.
    candidates = sorted(
        (f for f in result.findings if f.status is not Status.SUPPRESSED),
        key=lambda f: (not f.gating, -f.risk_score),
    )[: cfg.max_findings]

    api_errors = (getattr(client._anthropic, "APIError", Exception), Refused)

    if candidates:
        try:
            _triage_findings(client, candidates, target, run)
        except api_errors as exc:
            run.warnings.append(f"AI finding triage failed: {exc}")

    if cfg.explain_paths and result.attack_graph and result.attack_graph.paths:
        if client.cost < cfg.max_usd:
            try:
                result.attack_graph.ai_narrative = _narrative(client, result, run)
                run.narrative = True
            except api_errors as exc:
                run.warnings.append(f"AI attack-path narrative failed: {exc}")
        else:
            run.warnings.append("AI budget reached before attack-path narrative; skipped")

    run.input_tokens, run.output_tokens, run.cost_usd = (
        client.input_tokens,
        client.output_tokens,
        client.cost,
    )
    return run


def _triage_findings(client: _Client, findings: list[Finding], target: Path, run: AIRunResult) -> None:
    prompt = build_triage_prompt(findings, target)
    raw = client._call(TRIAGE_SYSTEM, prompt, FINDINGS_SCHEMA, max_tokens=4000)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        run.warnings.append("AI returned invalid JSON for finding triage; skipped")
        return
    by_id = {f.fingerprint: f for f in findings}
    for item in data.get("findings", []):
        f = by_id.get(item.get("id"))
        if f is None:
            continue
        try:
            f.ai = AIInsight(
                verdict=AIVerdict(item["verdict"]),
                confidence=Confidence(item.get("confidence", "medium")),
                summary=item.get("summary", "").strip(),
                reasoning=item.get("reasoning", "").strip(),
                remediation=item.get("remediation", "").strip(),
                model=client.cfg.model,
            )
            run.triaged += 1
        except (KeyError, ValueError):
            continue


def _narrative(client: _Client, result: ScanResult, run: AIRunResult) -> str:
    if result.attack_graph is None:
        return ""
    prompt = build_narrative_prompt(result.attack_graph)
    return client._call(NARRATIVE_SYSTEM, prompt, None, max_tokens=1500).strip()
