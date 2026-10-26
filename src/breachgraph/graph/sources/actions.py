"""GitHub Actions -> CI jobs an outsider can start, and the credentials those jobs hold.

A job triggered by `pull_request_target`, `issue_comment`, `issues`, `discussion*` or
`workflow_run` runs with the repository's secrets and token, yet anyone with a GitHub account can
start it. Such a job is an entry point. Its credentials are reachable only through code execution
in the job (script injection, a pwn request), so every credential edge requires it:

- cloud identities assumed over OIDC, linked only when the identity's trust (AWS `sub` condition,
  Azure federated credential subject) admits this workflow's token;
- repository secrets the job references;
- a GITHUB_TOKEN that can push code or publish packages.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any

from breachgraph.cicd import PRIVILEGED_TRIGGERS, gated
from breachgraph.cicd.workflows import Job, Step, Workflow, job_secrets, load_workflows
from breachgraph.graph.model import (
    CONTROL,
    INTERNET_ID,
    Confidence,
    Edge,
    EdgeKind,
    Evidence,
    Graph,
    Node,
    NodeKind,
    internet,
)
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.kubernetes import ROLE_ARN_RE

# Token scopes that compromise the software supply chain: (permission, node label, value).
WRITE_SCOPES = {
    "contents": ("push code and create releases in this repository", 8),
    "packages": ("publish packages and images as this repository", 8),
    "actions": ("rewrite workflow caches and runs of this repository", 7),
}


def repository_slug(root: Path) -> str | None:
    """owner/repo when scanning the checked-out repository inside GitHub Actions."""
    slug, workspace = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_WORKSPACE")
    if slug and workspace and Path(workspace).resolve() == root.resolve():
        return slug
    return None


def oidc_suffixes(wf: Workflow, job: Job) -> list[str]:
    """The `sub` claim GitHub issues to this job when an outsider triggers it, minus `repo:owner/name:`."""
    if job.environment:
        return [f"environment:{job.environment}"]  # an environment replaces the ref in `sub`
    outsider = wf.triggers & PRIVILEGED_TRIGGERS
    out = ["pull_request"] if "pull_request_target" in outsider else []
    if outsider - {"pull_request_target"}:
        # issue_comment, issues, discussion and workflow_run run on the default branch.
        out += ["ref:refs/heads/main", "ref:refs/heads/master"]
    return out


def admits(patterns: list[str], slug: str | None, suffixes: list[str]) -> bool:
    for p in patterns:
        if p == "*":
            return True
        for suffix in suffixes:
            if slug and fnmatch.fnmatchcase(f"repo:{slug}:{suffix}", p):
                return True
            parts = p.split(":", 2)
            if slug or parts[0] != "repo":
                continue
            # Repository unknown: judge the context part only (e.g. `ref:refs/heads/main`).
            if len(parts) == 3 and fnmatch.fnmatchcase(suffix, parts[2]):
                return True
            if len(parts) == 2 and parts[1].endswith("*"):
                return True  # `repo:org/*` covers every ref of the matching repositories
    return False


def _subs(node: Node) -> list[str]:
    raw = node.attrs.get("github_oidc_subs")
    return [str(x) for x in raw] if isinstance(raw, list) else []


class ActionsSource:
    name = "github-actions"

    def collect(self, ctx: SourceContext, graph: Graph) -> None:
        workflows, skipped = load_workflows(ctx.root, ctx.exclude)
        ctx.skipped.extend(skipped)
        self.slug = repository_slug(ctx.root)
        self.ctx = ctx
        for wf in workflows:
            for job in wf.jobs:
                self._job(graph, wf, job)

    def _job(self, graph: Graph, wf: Workflow, job: Job) -> None:
        outsider = sorted(wf.triggers & PRIVILEGED_TRIGGERS)
        if not outsider:
            return  # only people with write access can start it
        ev = Evidence(path=wf.path, line=job.line, detail=f"job {job.id}", source="github-actions")
        nid = f"gha:job:{wf.path}:{job.id}"
        graph.add_node(
            Node(
                id=nid,
                kind=NodeKind.WORKLOAD,
                name=f"GitHub Actions job {wf.name} / {job.id}",
                attrs={"platform": "github-actions", "tf_range": [wf.path, job.line, job.end_line]},
                evidence=[ev],
            )
        )
        gate = gated(wf, job)
        trigger = outsider[0]
        graph.add_node(internet())
        graph.add_edge(
            Edge(
                src=INTERNET_ID,
                dst=nid,
                kind=EdgeKind.EXPOSES,
                evidence=[ev],
                confidence=Confidence.LOW
                if gate
                else Confidence.MEDIUM
                if trigger == "workflow_run"
                else Confidence.HIGH,
                note=f"`{trigger}`: anyone with a GitHub account can start this job"
                + (f" ({gate})" if gate else ""),
            )
        )
        perms = wf.job_permissions(job)
        id_token = perms == "write-all" or (isinstance(perms, dict) and perms.get("id-token") == "write")
        for step in job.steps:
            if step.action == "aws-actions/configure-aws-credentials" and id_token:
                self._cloud(graph, nid, wf, job, step, "aws", step.with_.get("role-to-assume"))
            elif step.action == "azure/login" and id_token:
                self._cloud(graph, nid, wf, job, step, "azure", None)
            elif step.action == "google-github-actions/auth" and id_token:
                self._gcp(graph, nid, step, wf)
        self._secrets(graph, nid, wf, job)
        self._token(graph, nid, wf, job, perms)

    def _grant(self, graph: Graph, src: str, dst: str, ev: Evidence, conf: Confidence, note: str) -> None:
        graph.add_edge(
            Edge(
                src=src,
                dst=dst,
                kind=EdgeKind.USES_IDENTITY,
                requires=CONTROL,
                evidence=[ev],
                confidence=conf,
                note=note,
            )
        )

    def _cloud(
        self, graph: Graph, nid: str, wf: Workflow, job: Job, step: Step, platform: str, role: Any
    ) -> None:
        ev = Evidence(path=wf.path, line=step.line, detail=step.uses, source="github-actions")
        suffixes = oidc_suffixes(wf, job)
        conf = Confidence.HIGH if self.slug else Confidence.MEDIUM
        trusted = {
            n.id: n
            for n in graph.nodes.values()
            if n.attrs.get("platform") == platform and isinstance(n.attrs.get("github_oidc_subs"), list)
        }
        m = ROLE_ARN_RE.search(role) if isinstance(role, str) and "${{" not in role else None
        if m:
            rid = f"aws:iam_role:{m.group(1)}"
            node = trusted.get(rid)
            if node is None and graph.nodes.get(rid) and graph.nodes[rid].attrs.get("tf"):
                self.ctx.skipped.append(f"{ev.label()}: role {m.group(1)} does not trust GitHub Actions OIDC")
                return
            if node is None:
                graph.add_node(
                    Node(
                        id=rid,
                        kind=NodeKind.IDENTITY,
                        name=f"IAM role {m.group(1)}",
                        attrs={"platform": "aws"},
                    )
                )
                self._grant(
                    graph,
                    nid,
                    rid,
                    ev,
                    Confidence.MEDIUM,
                    "assumed over OIDC (role defined outside this repo)",
                )
                return
            subs = _subs(node)
            if admits(subs, self.slug, suffixes):
                self._grant(graph, nid, rid, ev, conf, f"assumed over OIDC; trust admits sub {suffixes[0]}")
            else:
                self.ctx.skipped.append(
                    f"{ev.label()}: job {job.id} cannot assume {m.group(1)} when an outsider triggers it "
                    f"(trust only admits {', '.join(subs)})"
                )
            return
        # The role/client id comes from a secret or variable: link every identity whose trust
        # admits this workflow's token.
        for node in trusted.values():
            subs = _subs(node)
            if admits(subs, self.slug, suffixes):
                self._grant(
                    graph,
                    nid,
                    node.id,
                    ev,
                    Confidence.MEDIUM,
                    f"its OIDC trust admits this workflow ({suffixes[0]})",
                )

    def _gcp(self, graph: Graph, nid: str, step: Step, wf: Workflow) -> None:
        sa = step.with_.get("service_account")
        if not isinstance(sa, str) or "${{" in sa or "@" not in sa:
            return
        gid = f"gcp:service_account:{sa.split('@', 1)[0]}"
        graph.add_node(
            Node(id=gid, kind=NodeKind.IDENTITY, name=f"Service account {sa}", attrs={"platform": "gcp"})
        )
        ev = Evidence(path=wf.path, line=step.line, detail=step.uses, source="github-actions")
        self._grant(
            graph, nid, gid, ev, Confidence.MEDIUM, "impersonated through Workload Identity Federation"
        )

    def _secrets(self, graph: Graph, nid: str, wf: Workflow, job: Job) -> None:
        for name, line in job_secrets(wf, job).items():
            sid = f"gha:secret:{name}"
            ev = Evidence(path=wf.path, line=line, detail=f"secrets.{name}", source="github-actions")
            graph.add_node(
                Node(id=sid, kind=NodeKind.SECRET, name=f"GitHub secret {name}", value=7, evidence=[ev])
            )
            graph.add_edge(
                Edge(
                    src=nid,
                    dst=sid,
                    kind=EdgeKind.MOUNTS,
                    requires=CONTROL,
                    evidence=[ev],
                    note="the job's environment holds this secret",
                )
            )

    def _token(self, graph: Graph, nid: str, wf: Workflow, job: Job, perms: Any) -> None:
        ev = Evidence(path=wf.path, line=job.line, detail="GITHUB_TOKEN", source="github-actions")
        if perms is None:
            scopes, conf, how = (
                ["contents"],
                Confidence.LOW,
                "token permissions are not set, so the repository default applies",
            )
        elif perms == "write-all":
            scopes, conf, how = list(WRITE_SCOPES), Confidence.HIGH, "permissions: write-all"
        elif isinstance(perms, dict):
            scopes = [k for k in WRITE_SCOPES if perms.get(k) == "write"]
            conf, how = Confidence.HIGH, "permissions grant write"
        else:
            return
        for scope in scopes:
            label, value = WRITE_SCOPES[scope]
            tid = f"gha:token:{scope}"
            graph.add_node(
                Node(
                    id=tid,
                    kind=NodeKind.IDENTITY,
                    name=f"GITHUB_TOKEN that can {label}",
                    value=value,
                    evidence=[ev],
                )
            )
            graph.add_edge(
                Edge(
                    src=nid,
                    dst=tid,
                    kind=EdgeKind.USES_IDENTITY,
                    requires=CONTROL,
                    evidence=[ev],
                    confidence=conf,
                    note=f"{how} ({scope}: write)",
                )
            )
