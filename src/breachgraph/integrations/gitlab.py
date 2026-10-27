"""GitLab merge-request comments: one sticky note per merge request, updated on every pipeline.

GitLab's CI_JOB_TOKEN cannot write notes, so this needs a project (or group) access token with
the `api` scope in a masked CI/CD variable, BREACHGRAPH_GITLAB_TOKEN (GITLAB_TOKEN also works).
Everything else comes from GitLab's predefined variables. The note body is the same Markdown as
the GitHub comment; GitLab renders its Mermaid diagrams and collapsible sections.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from breachgraph.reporters.markdown import MARKER


@dataclass
class GitLabContext:
    api: str  # e.g. https://gitlab.com/api/v4
    project: str  # numeric id or URL-encoded path
    mr_iid: str
    token: str
    server: str = ""
    project_path: str = ""
    sha: str = ""

    @classmethod
    def from_env(cls) -> GitLabContext | None:
        env = os.environ
        token = env.get("BREACHGRAPH_GITLAB_TOKEN") or env.get("GITLAB_TOKEN")
        if not (
            token
            and env.get("CI_API_V4_URL")
            and env.get("CI_PROJECT_ID")
            and env.get("CI_MERGE_REQUEST_IID")
        ):
            return None
        return cls(
            api=env["CI_API_V4_URL"],
            project=env["CI_PROJECT_ID"],
            mr_iid=env["CI_MERGE_REQUEST_IID"],
            token=token,
            server=env.get("CI_SERVER_URL", ""),
            project_path=env.get("CI_PROJECT_PATH", ""),
            sha=env.get("CI_COMMIT_SHA", ""),
        )

    @property
    def link_base(self) -> str | None:
        """Where file:line links in the note point (the merge request's commit)."""
        if self.server and self.project_path and self.sha:
            return f"{self.server}/{self.project_path}/-/blob/{self.sha}"
        return None

    @property
    def job_url(self) -> str | None:
        return os.environ.get("CI_JOB_URL")


def upsert_mr_note(ctx: GitLabContext, body: str, client: httpx.Client | None = None) -> str:
    own = client is None
    http = client or httpx.Client(timeout=30)
    headers = {"PRIVATE-TOKEN": ctx.token}
    notes_url = f"{ctx.api}/projects/{ctx.project}/merge_requests/{ctx.mr_iid}/notes"
    try:
        existing: dict[str, Any] | None = None
        page = 1
        while existing is None:
            resp = http.get(notes_url, headers=headers, params={"per_page": 100, "page": page, "sort": "asc"})
            resp.raise_for_status()
            batch = resp.json()
            existing = next(
                (n for n in batch if MARKER in (n.get("body") or "") and not n.get("system")), None
            )
            if len(batch) < 100:
                break
            page += 1
        if existing:
            resp = http.put(f"{notes_url}/{existing['id']}", headers=headers, json={"body": body})
        else:
            resp = http.post(notes_url, headers=headers, json={"body": body})
        resp.raise_for_status()
        return f"merge request note {'updated' if existing else 'created'}"
    finally:
        if own:
            http.close()
