"""Slack and Microsoft Teams alerts when a scan opens an attack path (or fails the gate).

Webhook URLs are secrets, so they come only from the environment, never from the config file:
BREACHGRAPH_SLACK_WEBHOOK (a Slack incoming webhook) and BREACHGRAPH_TEAMS_WEBHOOK (a Teams
Workflows webhook that accepts Adaptive Cards). Text from the repository is escaped, so a crafted
resource name can't mention a channel or inject links. A failed send is a warning, never a
failed scan.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx

from breachgraph.models import AttackPathView, ScanResult

SLACK_ENV = "BREACHGRAPH_SLACK_WEBHOOK"
TEAMS_ENV = "BREACHGRAPH_TEAMS_WEBHOOK"


def should_notify(result: ScanResult, when: str) -> bool:
    if when == "always":
        return True
    if when == "gate_failed":
        return not result.gate.passed
    return bool(new_paths(result))


def new_paths(result: ScanResult) -> list[AttackPathView]:
    """Paths this change opens: against the base branch when compared, else new and gating."""
    paths = result.attack_graph.paths if result.attack_graph else []
    if result.comparison is not None:
        opened = set(result.comparison.new_paths)
        return [p for p in paths if p.id in opened]
    return [p for p in paths if p.is_new and p.gating]


def _run_url() -> str | None:
    env = os.environ
    if all(k in env for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")):
        return f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
    return None


def _headline(result: ScanResult) -> str:
    project = str(result.metadata.get("project") or result.target)
    opened = new_paths(result)
    if opened:
        return f"breachgraph: {project}: {len(opened)} new attack path(s) to a crown-jewel asset"
    return f"breachgraph: {project}: security gate {'passed' if result.gate.passed else 'failed'}"


def _route(p: AttackPathView) -> str:
    return " → ".join(["Internet", *(s.dst for s in p.steps)])


_SLACK_ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}


def _slack(text: str) -> str:
    """Inert in Slack mrkdwn: no links, no @channel, no formatting from repository text."""
    text = re.sub(r"[&<>]", lambda m: _SLACK_ESC[m.group(0)], text)
    return re.sub(r"([*_~`@])", "​\\1", text)


def slack_payload(result: ScanResult) -> dict[str, Any]:
    lines = [f"*{_slack(_headline(result))}*"]
    for p in (new_paths(result) or (result.attack_graph.paths if result.attack_graph else []))[:3]:
        lines.append(f"• {_slack(_route(p))} ({p.confidence} confidence)")
    if result.gate.reasons:
        lines.append(_slack(result.gate.reasons[0]))
    if url := _run_url():
        lines.append(f"<{url}|Open the run>")
    text = "\n".join(lines)
    return {
        "text": _slack(_headline(result)),
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    }


def _teams(text: str) -> str:
    """Inert in Adaptive Card markdown."""
    return re.sub(r"([\\`*_{}\[\]()<>#+!|~@])", r"\\\1", text)


def teams_payload(result: ScanResult) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": _teams(_headline(result)), "weight": "Bolder", "wrap": True}
    ]
    for p in (new_paths(result) or (result.attack_graph.paths if result.attack_graph else []))[:3]:
        body.append(
            {"type": "TextBlock", "text": _teams(f"{_route(p)} ({p.confidence} confidence)"), "wrap": True}
        )
    if result.gate.reasons:
        body.append(
            {"type": "TextBlock", "text": _teams(result.gate.reasons[0]), "wrap": True, "isSubtle": True}
        )
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if url := _run_url():
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open the run", "url": url}]
    return {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
    }


def send(result: ScanResult, when: str, client: httpx.Client | None = None) -> list[str]:
    """Send to every configured webhook; returns one status line per destination."""
    targets = [
        (name, os.environ.get(env), build)
        for name, env, build in (("slack", SLACK_ENV, slack_payload), ("teams", TEAMS_ENV, teams_payload))
    ]
    targets = [t for t in targets if t[1]]
    if not targets or not should_notify(result, when):
        return []
    own = client is None
    http = client or httpx.Client(timeout=10)
    out = []
    try:
        for name, url, build in targets:
            try:
                resp = http.post(str(url), json=build(result))
                out.append(f"{name}: sent" if resp.status_code < 300 else f"{name}: HTTP {resp.status_code}")
            except httpx.HTTPError as exc:
                out.append(f"{name}: {type(exc).__name__}")
    finally:
        if own:
            http.close()
    return out
