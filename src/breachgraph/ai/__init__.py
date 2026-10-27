"""Optional AI-assisted triage — bring your own Anthropic API key.

breachgraph never spends tokens on your behalf. This runs only when you turn it on *and* a key is
present (``ANTHROPIC_API_KEY``). For the top findings it asks the model for a real / likely-false-
positive / needs-review verdict with reasoning and a concrete fix, based on the evidence a reviewer
would open: the enclosing function, the HTTP route that runs it, the attack path it sits on, and
for dependencies the lines that call the package (see ``context.py``).

It is advisory: it never changes the gate, and it is instructed never to produce exploit code.
Failures (no key, API errors, refusals, budget) become warnings; a scan never fails because of AI.
"""

from __future__ import annotations

import logging
import os
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from breachgraph.ai.context import build_evidence, on_attack_path
from breachgraph.ai.prompts import TRIAGE_SYSTEM, TriageOutput, build_prompt
from breachgraph.config import AIConfig
from breachgraph.models import AIInsight, AIVerdict, Confidence, Finding, ScanResult, Status

if TYPE_CHECKING:
    import anthropic

log = logging.getLogger("breachgraph")

# USD per 1M tokens (input, output), Anthropic first-party list prices.
_PRICING: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (10.0, 50.0),
    "claude-fable-5": (10.0, 50.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-opus-4-7": (5.0, 25.0),
    "claude-opus-4-6": (5.0, 25.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-haiku-4-5": (1.0, 5.0),
}
_CEILING = max(_PRICING.values())  # used for unknown models, so the budget errs on the safe side
# Models that take server-side refusal fallback: if a safety classifier declines (security code
# can trip it), the API re-runs the request on a suitable model within the same call.
_FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"
_NO_EFFORT_MODELS = {"claude-haiku-4-5", "claude-sonnet-4-5"}  # reject output_config.effort
MAX_OUTPUT_TOKENS = 8000  # thinking counts against this; an answer itself is ~300-800 tokens
_CONCURRENCY = 4
_CHARS_PER_TOKEN = 3  # deliberately low, so the pre-flight input estimate errs high


def _strip_titles(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _strip_titles(v) for k, v in node.items() if k != "title"}
    if isinstance(node, list):
        return [_strip_titles(v) for v in node]
    return node


OUTPUT_SCHEMA: dict[str, Any] = {
    **_strip_titles(TriageOutput.model_json_schema()),
    "additionalProperties": False,
}


class AIUnavailable(Exception):
    """Raised with a friendly, actionable message when AI triage can't run."""


@dataclass
class AIRunResult:
    model: str
    attempted: int = 0
    triaged: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    cost_is_upper_bound: bool = False  # a model without a known price was billed at the ceiling
    warnings: list[str] = field(default_factory=list)


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


def _price(model: str, prices: dict[str, tuple[float, float]]) -> tuple[tuple[float, float], bool]:
    """((input, output) USD per 1M tokens, known). Unknown models get the ceiling price."""
    known = model in prices
    return (prices[model] if known else max(_CEILING, *prices.values())), known


class _Budget:
    """Reserve a request's worst-case cost before sending it; settle with real usage after.

    Thread-safe, so concurrent requests can never jointly overshoot ``max_usd``."""

    def __init__(self, max_usd: float, prices: dict[str, tuple[float, float]] | None = None) -> None:
        self.max_usd = max_usd
        self.prices = {**_PRICING, **(prices or {})}
        self.spent = 0.0
        self.reserved = 0.0
        self.input_tokens = 0
        self.output_tokens = 0
        self.upper_bound = False
        self._lock = threading.Lock()

    def reserve(self, model: str, prompt_chars: int) -> float | None:
        (p_in, p_out), _ = _price(model, self.prices)
        worst = (prompt_chars / _CHARS_PER_TOKEN * p_in + MAX_OUTPUT_TOKENS * p_out) / 1_000_000
        with self._lock:
            if self.spent + self.reserved + worst > self.max_usd:
                return None
            self.reserved += worst
            return worst

    def settle(self, reserved: float, charges: list[tuple[str, int, int]]) -> None:
        """Release the reservation and record what was billed: (model, input, output) per attempt."""
        with self._lock:
            self.reserved -= reserved
            for model, input_tokens, output_tokens in charges:
                (p_in, p_out), known = _price(model, self.prices)
                self.spent += (input_tokens * p_in + output_tokens * p_out) / 1_000_000
                self.input_tokens += input_tokens
                self.output_tokens += output_tokens
                self.upper_bound = self.upper_bound or not known


@dataclass
class _Answer:
    model: str  # the model that answered (differs from the requested one after a fallback)
    # (model, input tokens, output tokens) per attempt. After a fallback the declined attempt is
    # billed separately, at its own model's price, and only appears in usage.iterations.
    charges: list[tuple[str, int, int]]
    output: TriageOutput | None = None
    problem: str | None = None  # why there is no output: "refused (cyber)", "truncated", ...


class _Client:
    """Thin wrapper over the Anthropic SDK: one structured-output request per finding."""

    def __init__(self, cfg: AIConfig, client: anthropic.Anthropic | None = None) -> None:
        import anthropic

        self.sdk = anthropic
        self.client = client or anthropic.Anthropic(max_retries=3, timeout=300.0)
        self.cfg = cfg

    def ask(self, prompt: str) -> _Answer:
        sdk = self.sdk
        model = self.cfg.model
        fallback = model in _FALLBACK_MODELS
        output_config: anthropic.types.beta.BetaOutputConfigParam = {
            "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}
        }
        if model not in _NO_EFFORT_MODELS:
            output_config["effort"] = self.cfg.effort
        resp = self.client.beta.messages.create(
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=TRIAGE_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
            output_config=output_config,
            betas=[_FALLBACK_BETA] if fallback else sdk.omit,
            fallbacks="default" if fallback else sdk.omit,
        )
        log.debug("AI triage request %s served by %s", getattr(resp, "_request_id", "?"), resp.model)
        # Every attempt is counted, so a refusal before any output (billed only in some
        # categories) can make the estimate slightly high, never low.
        charges = [
            (getattr(it, "model", None) or model, it.input_tokens, it.output_tokens)
            for it in resp.usage.iterations or []
            if it.type in ("message", "fallback_message")
        ] or [(resp.model, resp.usage.input_tokens, resp.usage.output_tokens)]
        answer = _Answer(resp.model, charges)
        if resp.stop_reason == "refusal":
            category = resp.stop_details.category if resp.stop_details else None
            answer.problem = f"declined by the model's safety filter ({category or 'unspecified'})"
        elif resp.stop_reason == "max_tokens":
            answer.problem = f"answer cut off at {MAX_OUTPUT_TOKENS} output tokens"
        else:
            text = "".join(b.text for b in resp.content if b.type == "text")
            try:
                answer.output = TriageOutput.model_validate_json(text)
            except ValidationError:
                answer.problem = "answer did not match the expected format"
        return answer


def _select(result: ScanResult, cfg: AIConfig) -> list[Finding]:
    """The findings worth the spend: attack-path steps first, then gating, then new, then risk.

    One finding per location (file and line, or package) comes first: several rules firing on the
    same Terraform block or package share one context, so spreading the budget covers more ground."""
    ag = result.attack_graph
    pool = [f for f in result.findings if f.status is not Status.SUPPRESSED]
    pool.sort(
        key=lambda f: (
            not on_attack_path(f, ag),
            not f.gating,
            f.status is Status.BASELINE,
            -f.risk_score,
        )
    )
    first: list[Finding] = []
    repeats: list[Finding] = []
    seen: set[tuple[str, int | None, str | None]] = set()
    for f in pool:
        key = (f.location.path, f.location.start_line, f.package.name if f.package else None)
        (repeats if key in seen else first).append(f)
        seen.add(key)
    return (first + repeats)[: cfg.max_findings]


def triage(
    result: ScanResult, cfg: AIConfig, target: Path, client: anthropic.Anthropic | None = None
) -> AIRunResult:
    """Annotate the top findings with AI verdicts (``finding.ai``), in place."""
    if client is None:
        ready, reason = available()
        if not ready:
            raise AIUnavailable(reason)
    try:
        api = _Client(cfg, client)
    except Exception as exc:
        raise AIUnavailable(f"could not initialize the Anthropic client: {exc}") from exc

    run = AIRunResult(model=cfg.model)
    findings = _select(result, cfg)
    run.attempted = len(findings)
    if not findings:
        return run
    jobs = [(f, build_prompt(build_evidence(f, target, result.attack_graph))) for f in findings]

    budget = _Budget(cfg.max_usd, cfg.prices)
    stop = threading.Event()  # set on errors that would repeat for every request
    fatal: list[str] = []
    sdk = api.sdk
    fatal_errors = (
        sdk.AuthenticationError,
        sdk.PermissionDeniedError,
        sdk.NotFoundError,
        sdk.BadRequestError,
    )

    def work(f: Finding, prompt: str) -> str:
        if stop.is_set():
            return "skipped"
        reserved = budget.reserve(cfg.model, len(TRIAGE_SYSTEM) + len(prompt))
        if reserved is None:
            return "budget"
        try:
            answer = api.ask(prompt)
        except fatal_errors as exc:
            budget.settle(reserved, [])
            stop.set()
            fatal.append(f"{type(exc).__name__}: {getattr(exc, 'message', exc)}")
            return "skipped"
        except sdk.APIError as exc:
            budget.settle(reserved, [])
            return f"request failed ({type(exc).__name__}: {getattr(exc, 'message', exc)})"
        budget.settle(reserved, answer.charges)
        if answer.output is None:
            return answer.problem or "no answer"
        out = answer.output
        f.ai = AIInsight(
            verdict=AIVerdict(out.verdict),
            confidence=Confidence(out.confidence),
            summary=out.summary.strip(),
            reasoning=out.explanation.strip(),
            remediation=out.remediation.strip(),
            fix_code=out.fix_code.strip("\n"),
            model=answer.model,
        )
        return "ok"

    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        outcomes = list(pool.map(lambda job: work(*job), jobs))

    run.triaged = outcomes.count("ok")
    run.input_tokens, run.output_tokens = budget.input_tokens, budget.output_tokens
    run.cost_usd, run.cost_is_upper_bound = budget.spent, budget.upper_bound
    run.warnings += _summarize(outcomes, fatal, cfg, budget.upper_bound)
    return run


def _summarize(outcomes: list[str], fatal: list[str], cfg: AIConfig, upper_bound: bool) -> list[str]:
    warnings = []
    if fatal:
        warnings.append(f"AI triage stopped: {fatal[0]}")
    if n := outcomes.count("budget"):
        warnings.append(
            f"AI budget (${cfg.max_usd:.2f}) reached: {n} finding(s) not triaged. "
            "Raise ai.max_usd (--ai-budget) or lower ai.max_findings."
        )
    if upper_bound or cfg.model not in {**_PRICING, **cfg.prices}:
        warnings.append(
            "no list price known for a model used: the AI cost shown and the budget use the highest "
            "Claude price, so they are upper bounds (set ai.prices to give one)"
        )
    problems = Counter(o for o in outcomes if o not in ("ok", "budget", "skipped"))
    for problem, n in problems.most_common():
        warnings.append(f"AI triage: {n} finding(s) without a verdict: {problem}")
    return warnings
