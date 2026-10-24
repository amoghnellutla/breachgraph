import json
from pathlib import Path

import httpx
import pytest
import respx

from breachgraph.config import Config
from breachgraph.integrations.github import GitHubClient, GitHubContext
from breachgraph.models import Priority, ScanResult
from breachgraph.normalize import finalize
from breachgraph.reporters.markdown import MARKER
from breachgraph.scoring import score_all
from tests.conftest import make_vuln

API = "https://api.github.com"


@pytest.fixture
def ctx() -> GitHubContext:
    return GitHubContext(token="t", repo="o/r", sha="abc", pr_number=7)


def test_context_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 12, "head": {"sha": "headsha"}}}))
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_SHA", "mergesha")
    c = GitHubContext.from_env()
    assert c is not None
    assert c.pr_number == 12
    assert c.link_base == "https://github.com/o/r/blob/headsha"


def test_context_absent_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert GitHubContext.from_env() is None


@respx.mock
def test_comment_is_updated_not_duplicated(ctx: GitHubContext) -> None:
    respx.get(f"{API}/repos/o/r/issues/7/comments").mock(
        return_value=httpx.Response(
            200, json=[{"id": 1, "body": "hi"}, {"id": 2, "body": f"{MARKER}\nold"}]
        )
    )
    patch = respx.patch(f"{API}/repos/o/r/issues/comments/2").mock(
        return_value=httpx.Response(200, json={})
    )
    post = respx.post(f"{API}/repos/o/r/issues/7/comments")
    assert GitHubClient(ctx).upsert_pr_comment(f"{MARKER}\nnew") == "PR comment updated"
    assert patch.called and not post.called


@respx.mock
def test_comment_created_when_missing(ctx: GitHubContext) -> None:
    respx.get(f"{API}/repos/o/r/issues/7/comments").mock(return_value=httpx.Response(200, json=[]))
    post = respx.post(f"{API}/repos/o/r/issues/7/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    assert GitHubClient(ctx).upsert_pr_comment("x") == "PR comment created"
    assert post.called


def _result() -> ScanResult:
    items = finalize([make_vuln()])
    items[0].enrichment.kev = True
    score_all(items, Config())
    return ScanResult(breachgraph_version="t", target=".", findings=items)


@respx.mock
def test_issue_sync_creates_and_closes(ctx: GitHubContext) -> None:
    result = _result()
    respx.get(f"{API}/repos/o/r/issues").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"number": 5, "body": "<!-- breachgraph-fp:stale --> gone"},
            ],
        )
    )
    create = respx.post(f"{API}/repos/o/r/issues").mock(return_value=httpx.Response(201, json={}))
    comment = respx.post(f"{API}/repos/o/r/issues/5/comments").mock(
        return_value=httpx.Response(201, json={})
    )
    close = respx.patch(f"{API}/repos/o/r/issues/5").mock(return_value=httpx.Response(200, json={}))

    summary = GitHubClient(ctx).sync_issues(result, Priority.P1, close_fixed=True)
    assert summary == "issues: 1 created, 1 closed"
    body = json.loads(create.calls[0].request.content)
    assert f"breachgraph-fp:{result.findings[0].fingerprint}" in body["body"]
    assert "breachgraph" in body["labels"]
    assert comment.called and close.called


@respx.mock
def test_issue_sync_skips_existing(ctx: GitHubContext) -> None:
    result = _result()
    fp = result.findings[0].fingerprint
    respx.get(f"{API}/repos/o/r/issues").mock(
        return_value=httpx.Response(
            200, json=[{"number": 9, "body": f"<!-- breachgraph-fp:{fp} -->"}]
        )
    )
    create = respx.post(f"{API}/repos/o/r/issues")
    assert (
        GitHubClient(ctx).sync_issues(result, Priority.P1, close_fixed=True)
        == "issues: 0 created, 0 closed"
    )
    assert not create.called
