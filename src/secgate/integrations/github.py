"""GitHub feedback: sticky PR comment, P1 issue tracking, job summary.

Uses the standard Actions environment (GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH...).
Every call degrades to a warning: on fork PRs the token is read-only, and reporting must never
hide the scan result itself.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from secgate.models import Finding, Priority, ScanResult, Status
from secgate.reporters.markdown import MARKER, defang

ISSUE_LABEL = "secgate"
_FP_MARKER = "<!-- secgate-fp:{} -->"


@dataclass
class GitHubContext:
    token: str
    repo: str
    api_url: str = "https://api.github.com"
    server_url: str = "https://github.com"
    sha: str | None = None
    pr_number: int | None = None
    run_id: str | None = None

    @classmethod
    def from_env(cls) -> GitHubContext | None:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not token or not repo:
            return None
        ctx = cls(
            token=token,
            repo=repo,
            api_url=os.environ.get("GITHUB_API_URL", cls.api_url).rstrip("/"),
            server_url=os.environ.get("GITHUB_SERVER_URL", cls.server_url).rstrip("/"),
            sha=os.environ.get("GITHUB_SHA"),
            run_id=os.environ.get("GITHUB_RUN_ID"),
        )
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if event_path and Path(event_path).is_file():
            try:
                event = json.loads(Path(event_path).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                event = {}
            pr = event.get("pull_request") or {}
            if pr.get("number"):
                ctx.pr_number = int(pr["number"])
                ctx.sha = (pr.get("head") or {}).get("sha") or ctx.sha
        return ctx

    @property
    def link_base(self) -> str | None:
        return f"{self.server_url}/{self.repo}/blob/{self.sha}" if self.sha else None

    @property
    def run_url(self) -> str | None:
        return f"{self.server_url}/{self.repo}/actions/runs/{self.run_id}" if self.run_id else None


class GitHubClient:
    def __init__(self, ctx: GitHubContext, transport: httpx.BaseTransport | None = None) -> None:
        self.ctx = ctx
        self.http = httpx.Client(
            base_url=ctx.api_url,
            headers={
                "Authorization": f"Bearer {ctx.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "secgate",
            },
            timeout=30.0,
            transport=transport,
        )

    def close(self) -> None:
        self.http.close()

    def _paginate(self, url: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        page = 1
        while True:
            resp = self.http.get(url, params={**params, "per_page": 100, "page": page})
            resp.raise_for_status()
            items = resp.json()
            yield from items
            if len(items) < 100:
                return
            page += 1

    # -------------------------------------------------------------- PR comment

    def upsert_pr_comment(self, body: str) -> str:
        if not self.ctx.pr_number:
            return "not a pull_request event; PR comment skipped"
        url = f"/repos/{self.ctx.repo}/issues/{self.ctx.pr_number}/comments"
        existing = next(
            (c for c in self._paginate(url, {}) if MARKER in (c.get("body") or "")), None
        )
        if existing:
            resp = self.http.patch(
                f"/repos/{self.ctx.repo}/issues/comments/{existing['id']}", json={"body": body}
            )
        else:
            resp = self.http.post(url, json={"body": body})
        resp.raise_for_status()
        return f"PR comment {'updated' if existing else 'created'}"

    # -------------------------------------------------------------- issues

    def sync_issues(self, result: ScanResult, min_priority: Priority, close_fixed: bool) -> str:
        """One issue per finding at ``min_priority`` or above; reopened never, closed when fixed."""
        url = f"/repos/{self.ctx.repo}/issues"
        open_issues: dict[str, dict[str, Any]] = {}
        for issue in self._paginate(url, {"state": "open", "labels": ISSUE_LABEL}):
            body = issue.get("body") or ""
            if "<!-- secgate-fp:" in body and "pull_request" not in issue:
                fp = body.split("<!-- secgate-fp:", 1)[1].split(" -->", 1)[0]
                open_issues[fp] = issue

        current = {
            fp
            for f in result.findings
            if f.status is not Status.SUPPRESSED
            for fp in f.fingerprints
        }
        created = closed = 0
        for f in result.findings:
            if f.status is Status.SUPPRESSED or f.priority.rank < min_priority.rank:
                continue
            if any(fp in open_issues for fp in f.fingerprints):
                continue
            resp = self.http.post(
                url,
                json={
                    "title": defang(f"[secgate {f.priority.value}] {f.title}")[:250],
                    "body": self._issue_body(f),
                    "labels": [ISSUE_LABEL, f"priority:{f.priority.value}", f.category.value],
                },
            )
            resp.raise_for_status()
            created += 1
        if close_fixed:
            for fp, issue in open_issues.items():
                if fp in current:
                    continue
                self.http.post(
                    f"{url}/{issue['number']}/comments",
                    json={"body": "secgate no longer detects this finding. Closing as fixed."},
                ).raise_for_status()
                self.http.patch(
                    f"{url}/{issue['number']}",
                    json={"state": "closed", "state_reason": "completed"},
                ).raise_for_status()
                closed += 1
        return f"issues: {created} created, {closed} closed"

    def _issue_body(self, f: Finding) -> str:
        loc = f.location.path + (f":{f.location.start_line}" if f.location.start_line else "")
        link = loc
        if self.ctx.link_base and f.location.in_repo:
            anchor = f"#L{f.location.start_line}" if f.location.start_line else ""
            link = f"[`{loc}`]({self.ctx.link_base}/{f.location.path}{anchor})"
        lines = [
            _FP_MARKER.format(f.fingerprint),
            f"**Priority:** {f.priority.value} (risk {f.risk_score}/10): "
            + "; ".join(f.score_reasons),
            f"**Location:** {link}",
            f"**Rule:** `{f.tool}:{f.rule_id}`"
            + (f" (also: {', '.join(f.related_rules)})" if f.related_rules else ""),
        ]
        if f.cwe or f.owasp:
            lines.append(f"**Classification:** {', '.join(f.cwe + f.owasp)}")
        if f.package:
            lines.append(
                f"**Package:** {f.package.name} {f.package.version or ''}"
                + (f" → fixed in {f.package.fixed_version}" if f.package.fixed_version else "")
            )
        lines += ["", f.description[:3000]]
        if f.location.snippet and f.category.value != "secrets":
            lines += ["", "```", f.location.snippet[:1500], "```"]
        if f.remediation:
            lines += ["", "### Remediation", f.remediation]
        if f.references:
            lines += ["", "### References", *[f"- {r}" for r in f.references[:5]]]
        lines += [
            "",
            "_Opened automatically by secgate. Closed automatically when the finding is gone._",
        ]
        return lines[0] + "\n" + defang("\n".join(lines[1:]))


def write_step_summary(markdown: str) -> bool:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(markdown.replace("\n" + MARKER, "").replace(MARKER + "\n", "") + "\n")
    return True
