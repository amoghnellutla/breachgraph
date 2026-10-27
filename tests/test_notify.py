"""Slack and Teams alerts: sent only when they should be, with repository text made inert."""

import json
from pathlib import Path

import httpx
import pytest

from breachgraph.integrations import notify
from tests.test_compare import run
from tests.test_pipeline_attackgraph import CMDI, SSRF


def capture() -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def test_alert_when_a_change_opens_a_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(notify.SLACK_ENV, "https://hooks.slack.test/x")
    monkeypatch.setenv(notify.TEAMS_ENV, "https://teams.test/y")
    for k, v in {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "a/b",
        "GITHUB_RUN_ID": "7",
    }.items():
        monkeypatch.setenv(k, v)
    base = run([CMDI])
    head = run([SSRF, CMDI], tmp_path, base)
    client, seen = capture()
    assert notify.send(head, "new_paths", client) == ["slack: sent", "teams: sent"]
    slack, teams = (json.loads(r.content) for r in seen)
    text = slack["blocks"][0]["text"]["text"]
    assert "1 new attack path(s)" in text and "GET /fetch" in text
    assert "<https://github.com/a/b/actions/runs/7|Open the run>" in text
    card = teams["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["actions"][0]["url"].endswith("/runs/7")

    same = run([SSRF, CMDI], tmp_path, head)  # nothing new
    client, seen = capture()
    assert notify.send(same, "new_paths", client) == [] and seen == []
    assert notify.send(same, "always", client) == ["slack: sent", "teams: sent"]


def test_no_webhook_no_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(notify.SLACK_ENV, raising=False)
    monkeypatch.delenv(notify.TEAMS_ENV, raising=False)
    client, seen = capture()
    assert notify.send(run([SSRF]), "always", client) == [] and seen == []


def test_repository_text_is_inert() -> None:
    hostile = "<!channel> *bold* <https://evil|click> @here"
    out = notify._slack(hostile)
    assert "<" not in out and ">" not in out and "​@here" in out and "​*bold" in out
    assert r"\<" in notify._teams("[x](https://evil) <b>")


def test_a_failed_send_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(notify.SLACK_ENV, "https://hooks.slack.test/x")
    monkeypatch.delenv(notify.TEAMS_ENV, raising=False)

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = httpx.Client(transport=httpx.MockTransport(boom))
    assert notify.send(run([SSRF]), "always", client) == ["slack: ConnectError"]
