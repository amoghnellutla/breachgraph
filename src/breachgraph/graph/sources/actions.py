"""GitHub Actions -> CI jobs an outsider can start, and the credentials those jobs hold.

A job triggered by `pull_request_target`, `issue_comment`, `issues`, `discussion*` or
`workflow_run` runs with the repository's secrets and token, yet anyone with a GitHub account can
start it. Such a job is an entry point. Its credentials are reachable only through code execution
in the job (script injection, a pwn request), so every credential edge requires it:

- cloud identities assumed over OIDC, linked only when the identity's trust (AWS `sub` condition,
  Azure federated credential subject) admits this workflow's token;
- repository secrets the job references;
- a GITHUB_TOKEN that can push code or publish packages.

That token also reaches production later. Code pushed with it runs in the deploy jobs of the next
push, and an image pushed with it runs as the workloads that pull it. See `ActionsSource.delivery`.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

from breachgraph.cicd import PRIVILEGED_TRIGGERS, follows_only_trusted, gated, same_repository_only
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
    WeaknessClass,
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


BRANCH_ID = "gha:branch:default"
_DEPLOY_JOB = re.compile(r"deploy|release|publish|prod|rollout", re.I)
_DOCKER_PUSH = re.compile(r"\bdocker\s+(?:image\s+)?push\s+(\S+)")
_EXPR = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
_TAG = re.compile(r":[^/]*$")
_INHERITED = (EdgeKind.USES_IDENTITY, EdgeKind.MOUNTS, EdgeKind.CONNECTS_TO)


def _deploys(wf: Workflow, job: Job) -> bool:
    return bool(job.environment or _DEPLOY_JOB.search(f"{wf.name} {wf.path} {job.id}"))


def _later(confidence: Confidence) -> Confidence:
    """Nothing happens until the next run, so a delivery step is at best medium."""
    return Confidence.LOW if confidence is Confidence.LOW else Confidence.MEDIUM


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


def oidc_deploy_suffixes(job: Job) -> list[str]:
    """The `sub` claim of a job a push starts."""
    if job.environment:
        return [f"environment:{job.environment}"]
    return ["ref:refs/heads/main", "ref:refs/heads/master"]


def _cloud_steps(wf: Workflow, job: Job) -> list[tuple[Step, str, Any]]:
    """Cloud logins over OIDC in a job, with their platform and role."""
    perms = wf.job_permissions(job)
    if perms != "write-all" and not (isinstance(perms, dict) and perms.get("id-token") == "write"):
        return []
    out: list[tuple[Step, str, Any]] = []
    for step in job.steps:
        if step.action == "aws-actions/configure-aws-credentials":
            out.append((step, "aws", step.with_.get("role-to-assume")))
        elif step.action == "azure/login":
            out.append((step, "azure", None))
    return out


def _lines(value: Any) -> list[str]:
    return [x.strip() for x in re.split(r"[\n,]", value) if x.strip()] if isinstance(value, str) else []


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
        self.workflows = workflows
        by_name = {wf.name: wf for wf in workflows}
        for wf in workflows:
            for job in wf.jobs:
                self._job(graph, wf, job, by_name)

    def _job(self, graph: Graph, wf: Workflow, job: Job, by_name: dict[str, Workflow]) -> None:
        outsider = sorted(wf.triggers & PRIVILEGED_TRIGGERS)
        if outsider == ["workflow_run"] and follows_only_trusted(wf, by_name):
            return  # it only runs after workflows an outsider can't start
        if not outsider or same_repository_only(job):
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

    def delivery(self, graph: Graph) -> None:
        """What a write token in an outsider's job reaches on the way to production. Runs once every
        workload is known. Each route starts with the job's token, which needs a weapon in that job."""
        holders = [e for e in graph.edges if e.src.startswith("gha:job:")]
        self._default_branch(graph, [e for e in holders if e.dst == "gha:token:contents"])
        self._registry(graph, [e for e in holders if e.dst == "gha:token:packages"])

    def _default_branch(self, graph: Graph, writers: list[Edge]) -> None:
        jobs = [(wf, j) for wf in self.workflows if wf.default_push for j in wf.jobs if _deploys(wf, j)]
        held = [(wf, j) for wf, j in jobs if job_secrets(wf, j) or _cloud_steps(wf, j)]
        if not writers or not held:
            return
        graph.add_node(
            Node(
                id=BRANCH_ID,
                kind=NodeKind.ENTRYPOINT,
                name="Default branch of this repository",
                attrs={"stage": True},
            )
        )
        for e in writers:
            graph.add_edge(
                Edge(
                    src=e.src,
                    dst=BRANCH_ID,
                    kind=EdgeKind.COMPROMISES,
                    requires=CONTROL,
                    evidence=e.evidence,
                    confidence=_later(e.confidence),
                    note="its token can change the code on this branch",
                )
            )
        for wf, job in held:
            did = f"gha:deploy:{wf.path}:{job.id}"
            ev = Evidence(path=wf.path, line=job.line, detail=f"job {job.id}", source="github-actions")
            graph.add_node(
                Node(
                    id=did,
                    kind=NodeKind.ENTRYPOINT,
                    name=f"Deploy job {wf.name} / {job.id}",
                    evidence=[ev],
                )
            )
            graph.add_edge(
                Edge(
                    src=BRANCH_ID,
                    dst=did,
                    kind=EdgeKind.COMPROMISES,
                    evidence=[ev],
                    # An environment can require a reviewer, which the repository doesn't show.
                    confidence=Confidence.LOW if job.environment else Confidence.MEDIUM,
                    note="runs the branch's code on the next push"
                    + (f", in environment {job.environment}" if job.environment else ""),
                )
            )
            self._secrets(graph, did, wf, job, requires=[])
            suffixes = oidc_deploy_suffixes(job)
            for step, platform, role in _cloud_steps(wf, job):
                self._cloud(graph, did, wf, job, step, platform, role, suffixes, requires=[])

    def _registry(self, graph: Graph, publishers: list[Edge]) -> None:
        pushed = self._pushed_images() if publishers else set()
        for node in list(graph.of_kind(NodeKind.WORKLOAD)):
            raw = node.attrs.get("images")
            for image in [str(i) for i in raw] if isinstance(raw, list) else []:
                # A digest can't be replaced, whatever the token can do.
                name = _TAG.sub("", image.lower())
                if "@" in image or not any(fnmatch.fnmatchcase(name, p) for p in pushed):
                    continue
                iid = f"image:{image}"
                graph.add_node(Node(id=iid, kind=NodeKind.IMAGE, name=image, evidence=node.evidence))
                graph.nodes[iid].attrs["stage"] = True
                for e in publishers:
                    graph.add_edge(
                        Edge(
                            src=e.src,
                            dst=iid,
                            kind=EdgeKind.COMPROMISES,
                            requires=CONTROL,
                            evidence=e.evidence,
                            confidence=_later(e.confidence),
                            note="its token can replace this image, since the tag isn't pinned to a digest",
                        )
                    )
                for edge in [e for e in graph.edges if e.src == node.id and e.kind in _INHERITED]:
                    graph.add_edge(
                        Edge(
                            src=iid,
                            dst=edge.dst,
                            kind=edge.kind,
                            evidence=edge.evidence,
                            confidence=edge.confidence,
                            note=f"{node.name} runs this image the next time it starts",
                        )
                    )

    def _pushed_images(self) -> set[str]:
        """GitHub Packages images this repository's workflows publish, as lowercase name patterns."""
        found: set[str] = set()
        for wf in self.workflows:
            for job in wf.jobs:
                for step in job.steps:
                    raw = _DOCKER_PUSH.findall(step.run)
                    if step.action == "docker/build-push-action":
                        raw += _lines(step.with_.get("tags"))
                    elif step.action == "docker/metadata-action":
                        raw += _lines(step.with_.get("images"))
                    for text in raw:
                        name = self._resolve(text, {**wf.env, **job.env, **step.env})
                        if name and name.lower().startswith("ghcr.io/"):
                            found.add(_TAG.sub("", name.lower()))
        return found

    def _resolve(self, text: str, env: dict[str, Any]) -> str | None:
        """A name with its expressions filled in; None when one depends on the run."""
        repo = self.slug or f"*/{self.ctx.root.resolve().name}"
        known = {"github.repository": repo, "github.repository_owner": repo.split("/")[0]}
        for _ in range(3):
            for m in _EXPR.finditer(text):
                expr = m.group(1)
                value = known.get(expr) or (env.get(expr[4:]) if expr.startswith("env.") else None)
                if value is None:
                    return None
                text = text.replace(m.group(0), str(value))
        return None if "${{" in text else text

    def _grant(
        self,
        graph: Graph,
        src: str,
        dst: str,
        ev: Evidence,
        conf: Confidence,
        note: str,
        requires: list[WeaknessClass] = CONTROL,
    ) -> None:
        graph.add_edge(
            Edge(
                src=src,
                dst=dst,
                kind=EdgeKind.USES_IDENTITY,
                requires=requires,
                evidence=[ev],
                confidence=conf,
                note=note,
            )
        )

    def _cloud(
        self,
        graph: Graph,
        nid: str,
        wf: Workflow,
        job: Job,
        step: Step,
        platform: str,
        role: Any,
        suffixes: list[str] | None = None,
        requires: list[WeaknessClass] = CONTROL,
    ) -> None:
        ev = Evidence(path=wf.path, line=step.line, detail=step.uses, source="github-actions")
        suffixes = suffixes or oidc_suffixes(wf, job)
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
                    requires,
                )
                return
            subs = _subs(node)
            if admits(subs, self.slug, suffixes):
                note = f"assumed over OIDC; trust admits sub {suffixes[0]}"
                self._grant(graph, nid, rid, ev, conf, note, requires)
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
                    requires,
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

    def _secrets(
        self,
        graph: Graph,
        nid: str,
        wf: Workflow,
        job: Job,
        requires: list[WeaknessClass] = CONTROL,
    ) -> None:
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
                    requires=requires,
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
