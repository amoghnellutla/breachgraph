"""AI triage — tested with a fake client so no real API calls or key are needed."""

import json
from pathlib import Path

import pytest

import breachgraph.ai as ai_mod
from breachgraph.ai import AIUnavailable, available, triage
from breachgraph.ai.prompts import build_narrative_prompt, build_triage_prompt
from breachgraph.config import AIConfig
from breachgraph.models import (
    AttackGraphSummary,
    AttackPathView,
    AttackStep,
    Category,
    ChokePointView,
    Confidence,
    Finding,
    Location,
    ScanResult,
    Severity,
)

PLATFORM = Path(__file__).parent.parent / "examples" / "vulnerable-platform"


def finding(fp: str = "f1") -> Finding:
    return Finding(
        tool="semgrep",
        rule_id="ssrf",
        title="SSRF via requests.get",
        severity=Severity.HIGH,
        category=Category.SAST,
        confidence=Confidence.HIGH,
        cwe=["CWE-918"],
        location=Location(path="services/api/app.py", start_line=23),
        fingerprint=fp,
        gating=True,
    )


class FakeClient:
    """Stand-in for breachgraph.ai._Client. Records prompts; returns canned JSON/text."""

    def __init__(self, cfg: AIConfig, triage_json: dict | None = None, narrative: str = "Narrative."):
        import types

        self.cfg = cfg
        self.input_tokens = 100
        self.output_tokens = 50
        self._anthropic = types.SimpleNamespace(APIError=Exception)
        self._triage_json = triage_json
        self._narrative = narrative
        self.calls: list[str] = []

    @property
    def cost(self) -> float:
        return 0.01

    def _call(self, system, prompt, schema, max_tokens=2000):  # type: ignore[no-untyped-def]
        self.calls.append("triage" if schema else "narrative")
        if schema:
            return json.dumps(self._triage_json or {"findings": []})
        return self._narrative


@pytest.fixture
def ai_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ai_mod, "available", lambda: (True, ""))


def install_fake(monkeypatch: pytest.MonkeyPatch, **kw) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ai_mod, "_Client", lambda cfg: FakeClient(cfg, **kw))


def test_available_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    ok, reason = available()
    # anthropic may or may not be installed in the dev env; either way it's not ready.
    assert not ok
    assert "anthropic" in reason or "API key" in reason


def test_triage_unavailable_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ai_mod, "available", lambda: (False, "no key"))
    with pytest.raises(AIUnavailable):
        triage(ScanResult(breachgraph_version="t", target="."), AIConfig(), PLATFORM)


def test_triage_annotates_findings(ai_ready: None, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake(
        monkeypatch,
        triage_json={
            "findings": [
                {
                    "id": "f1",
                    "verdict": "true_positive",
                    "confidence": "high",
                    "summary": "User URL reaches requests.get.",
                    "reasoning": "request.args flows to requests.get with no allowlist.",
                    "remediation": "Validate the URL against an allowlist.",
                }
            ]
        },
    )
    result = ScanResult(breachgraph_version="t", target=str(PLATFORM), findings=[finding("f1")])
    run = triage(result, AIConfig(), PLATFORM)
    assert run.triaged == 1
    ins = result.findings[0].ai
    assert ins is not None
    assert ins.verdict.value == "true_positive"
    assert "allowlist" in ins.remediation
    assert run.cost_usd == 0.01


def test_triage_writes_attack_narrative(ai_ready: None, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake(monkeypatch, narrative="An attacker can reach the S3 bucket.")
    ag = AttackGraphSummary(
        paths=[
            AttackPathView(
                target="S3 bucket",
                target_kind="datastore",
                score=14.0,
                confidence="high",
                length=5,
                gating=True,
                steps=[AttackStep(src="Internet", dst="pod", dst_kind="workload", kind="exposes")],
            )
        ]
    )
    result = ScanResult(breachgraph_version="t", target=str(PLATFORM), findings=[finding()], attack_graph=ag)
    run = triage(result, AIConfig(), PLATFORM)
    assert run.narrative is True
    assert result.attack_graph.ai_narrative == "An attacker can reach the S3 bucket."


def test_triage_respects_budget(ai_ready: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # Budget below the (fake) running cost -> narrative skipped.
    install_fake(monkeypatch)
    ag = AttackGraphSummary(
        paths=[AttackPathView(target="S3", target_kind="datastore", score=1, confidence="high", length=1)]
    )
    result = ScanResult(breachgraph_version="t", target=str(PLATFORM), findings=[finding()], attack_graph=ag)
    run = triage(result, AIConfig(max_usd=0.001), PLATFORM)
    assert run.narrative is False
    assert any("budget" in w for w in run.warnings)


def test_triage_handles_bad_json(ai_ready: None, monkeypatch: pytest.MonkeyPatch) -> None:
    class BadClient(FakeClient):
        def _call(self, system, prompt, schema, max_tokens=2000):  # type: ignore[no-untyped-def]
            return "not json" if schema else "narrative"

    monkeypatch.setattr(ai_mod, "_Client", lambda cfg: BadClient(cfg))
    result = ScanResult(breachgraph_version="t", target=str(PLATFORM), findings=[finding()])
    run = triage(result, AIConfig(explain_paths=False), PLATFORM)
    assert run.triaged == 0
    assert any("invalid JSON" in w for w in run.warnings)


def test_triage_caps_findings(ai_ready: None, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class CapClient(FakeClient):
        def _call(self, system, prompt, schema, max_tokens=2000):  # type: ignore[no-untyped-def]
            captured["prompt"] = prompt
            return json.dumps({"findings": []})

    monkeypatch.setattr(ai_mod, "_Client", lambda cfg: CapClient(cfg))
    findings = [finding(f"f{i}") for i in range(20)]
    result = ScanResult(breachgraph_version="t", target=str(PLATFORM), findings=findings)
    triage(result, AIConfig(max_findings=3, explain_paths=False), PLATFORM)
    assert captured["prompt"].count("Finding id:") == 3


def test_prompts_are_defensive_and_grounded() -> None:
    f = finding()
    prompt = build_triage_prompt([f], PLATFORM)
    assert "f1" in prompt
    assert "requests.get" in prompt  # real code snippet pulled from disk
    ag = AttackGraphSummary(
        paths=[
            AttackPathView(
                target="S3 bucket",
                target_kind="datastore",
                score=14,
                confidence="high",
                length=2,
                steps=[
                    AttackStep(
                        src="Internet",
                        dst="route",
                        dst_kind="route",
                        kind="serves",
                        via="code_execution",
                        weakness_title="cmd injection",
                    )
                ],
            )
        ],
        choke_points=[
            ChokePointView(
                title="cmd injection", weakness="code_execution", paths_cut=1, path="app.py", line=30
            )
        ],
    )
    narrative = build_narrative_prompt(ag)
    assert "S3 bucket" in narrative and "code_execution" in narrative
    from breachgraph.ai.prompts import NARRATIVE_SYSTEM, TRIAGE_SYSTEM

    assert "exploit code" in TRIAGE_SYSTEM.lower() or "exploit" in TRIAGE_SYSTEM.lower()
    assert "defensive" in NARRATIVE_SYSTEM.lower()


def test_pipeline_ai_off_by_default() -> None:
    from breachgraph.config import Config

    assert Config().ai.enabled is False


def test_refusal_degrades_to_warning(ai_ready: None, monkeypatch: pytest.MonkeyPatch) -> None:
    from breachgraph.ai import Refused

    class RefusingClient(FakeClient):
        def _call(self, system, prompt, schema, max_tokens=2000):  # type: ignore[no-untyped-def]
            raise Refused("model declined to analyze (cyber)")

    monkeypatch.setattr(ai_mod, "_Client", lambda cfg: RefusingClient(cfg))
    result = ScanResult(breachgraph_version="t", target=str(PLATFORM), findings=[finding()])
    run = triage(result, AIConfig(explain_paths=False), PLATFORM)
    assert run.triaged == 0
    assert result.findings[0].ai is None
    assert any("declined" in w for w in run.warnings)


def test_pipeline_runs_ai_when_enabled(ai_ready: None, monkeypatch: pytest.MonkeyPatch) -> None:
    from breachgraph.config import Config
    from breachgraph.models import ToolRun, ToolStatus
    from breachgraph.pipeline import ScanOptions, process

    install_fake(
        monkeypatch,
        triage_json={
            "findings": [
                {
                    "id": "will-be-remapped",
                    "verdict": "needs_review",
                    "confidence": "low",
                    "summary": "s",
                    "reasoning": "r",
                    "remediation": "fix",
                }
            ]
        },
        narrative="Narrative.",
    )
    cfg = Config.model_validate({"ai": {"enabled": True}})
    result = process(
        [finding("f1")],
        [ToolRun(name="semgrep", status=ToolStatus.IMPORTED, findings=1)],
        cfg,
        PLATFORM,
        ScanOptions(offline=True),
    )
    assert "ai" in result.metadata
    assert result.metadata["ai"]["model"] == "claude-opus-5-5"


def test_pipeline_ai_unavailable_warns_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    from breachgraph.config import Config
    from breachgraph.models import ToolRun, ToolStatus
    from breachgraph.pipeline import ScanOptions, process

    monkeypatch.setattr(ai_mod, "available", lambda: (False, "no key"))
    cfg = Config.model_validate({"ai": {"enabled": True}})
    result = process(
        [finding("f1")],
        [ToolRun(name="semgrep", status=ToolStatus.IMPORTED, findings=1)],
        cfg,
        PLATFORM,
        ScanOptions(offline=True),
    )
    assert any("AI triage unavailable" in w for w in result.warnings)
    assert result.findings[0].ai is None
