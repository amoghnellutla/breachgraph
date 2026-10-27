"""GitLab merge-request notes: one sticky note, found by its marker and updated in place."""

import json

import httpx
import pytest

from breachgraph.integrations.gitlab import GitLabContext, upsert_mr_note
from breachgraph.reporters.markdown import MARKER

ENV = {
    "CI_API_V4_URL": "https://gitlab.example/api/v4",
    "CI_PROJECT_ID": "42",
    "CI_MERGE_REQUEST_IID": "7",
    "CI_SERVER_URL": "https://gitlab.example",
    "CI_PROJECT_PATH": "acme/shop",
    "CI_COMMIT_SHA": "abc",
    "BREACHGRAPH_GITLAB_TOKEN": "glpat-test",
}


def ctx(monkeypatch: pytest.MonkeyPatch) -> GitLabContext:
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    c = GitLabContext.from_env()
    assert c is not None
    return c


def client(notes: list[dict]) -> tuple[httpx.Client, list[httpx.Request]]:  # type: ignore[type-arg]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.headers["PRIVATE-TOKEN"] == "glpat-test"
        if request.method == "GET":
            return httpx.Response(200, json=notes)
        return httpx.Response(201, json={"id": 9})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def test_creates_then_updates_the_same_note(monkeypatch: pytest.MonkeyPatch) -> None:
    c = ctx(monkeypatch)
    assert c.link_base == "https://gitlab.example/acme/shop/-/blob/abc"
    http, seen = client([{"id": 1, "body": "LGTM", "system": False}])
    assert upsert_mr_note(c, f"{MARKER}\nhello", http) == "merge request note created"
    assert seen[-1].method == "POST" and seen[-1].url.path == "/api/v4/projects/42/merge_requests/7/notes"
    assert json.loads(seen[-1].content)["body"].endswith("hello")

    http, seen = client([{"id": 1, "body": "LGTM"}, {"id": 5, "body": f"{MARKER}\nold", "system": False}])
    assert upsert_mr_note(c, f"{MARKER}\nnew", http) == "merge request note updated"
    assert seen[-1].method == "PUT" and seen[-1].url.path.endswith("/notes/5")


def test_needs_a_token_and_a_merge_request(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx(monkeypatch)
    monkeypatch.delenv("BREACHGRAPH_GITLAB_TOKEN")
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    assert GitLabContext.from_env() is None
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    monkeypatch.delenv("CI_MERGE_REQUEST_IID")
    assert GitLabContext.from_env() is None
