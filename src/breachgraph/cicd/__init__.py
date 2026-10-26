"""CI/CD and supply-chain checks that need no external tool.

Each check targets one attack that is actually used against real projects, and stays quiet
otherwise:

- script injection: text an outsider controls (an issue title, a comment, a branch name) expanded
  by ``${{ }}`` into a shell script or ``github-script``, in a workflow an outsider can trigger;
- pwn request: a ``pull_request_target`` / ``workflow_run`` job that checks out the pull request's
  code and then runs it, with the base repository's secrets and token;
- dependency confusion: pip's ``--extra-index-url``, which merges a private index with PyPI and
  installs whichever has the higher version, so anyone can publish a same-named package on PyPI.

Broader GitHub Actions hygiene (unpinned actions, credential persistence, ...) comes from zizmor
when it is installed.
"""

from __future__ import annotations

import re
from pathlib import Path

from breachgraph.cicd.workflows import Job, Step, Workflow, job_secrets, load_workflows
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.paths import iter_files

TOOL = "cicd"

# Triggers that run with the base repository's secrets and token but can be started by anyone
# with a GitHub account.
PRIVILEGED_TRIGGERS = {
    "pull_request_target",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "workflow_run",
}
# Fork pull requests can start these too, but with a read-only token and no secrets.
FORK_TRIGGERS = {"pull_request", "pull_request_review", "pull_request_review_comment"}

# Contexts an outsider controls (GitHub Security Lab's list of untrusted input).
UNTRUSTED_CONTEXT = re.compile(
    r"github\.event\.(?:"
    r"(?:issue|pull_request|discussion)\.(?:title|body)"
    r"|(?:comment|review|review_comment)\.body"
    r"|pages\.[^.\s}]+\.page_name"
    r"|(?:commits\.[^.\s}]+|head_commit)\.(?:message|author\.(?:email|name))"
    r"|pull_request\.head\.(?:ref|label|repo\.default_branch)"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name))"
    r"|pull_requests\.[^.\s}]+\.head\.ref)"
    r")"
    r"|github\.head_ref"
)
_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
# `if:` conditions that limit a job to people who already have write access.
_MAINTAINER_GATE = re.compile(
    r"author_association|github\.actor\s*==|sender\.login\s*==|github\.triggering_actor\s*==",
    re.I,
)
_LABEL_GATE = re.compile(r"labels|label\.name", re.I)
_UNTRUSTED_REF = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/"
    r"|github\.event\.workflow_run\.head_(?:sha|branch)|pull_request\.head\.repo\.full_name"
    r"|github\.event\.number|github\.event\.pull_request\.number|merge_commit_sha"
)


def analyze(target: Path, exclude: list[str]) -> tuple[list[Finding], list[str]]:
    """All native CI/CD findings for a repository, and anything that could not be parsed."""
    workflows, skipped = load_workflows(target, exclude)
    findings: list[Finding] = []
    for wf in workflows:
        for job in wf.jobs:
            findings += _script_injection(wf, job)
            findings += _untrusted_checkout(wf, job)
    findings += dependency_confusion(target, exclude)
    return findings, skipped


def gated(wf: Workflow, job: Job, step: Step | None = None) -> str:
    """Why outsiders cannot start this job/step, or "" if they can."""
    conds = " ".join([job.if_, step.if_ if step else ""])
    if _MAINTAINER_GATE.search(conds):
        return "only runs for users with write access (if: condition)"
    if _LABEL_GATE.search(conds) and "pull_request_target" in wf.triggers:
        return "runs once a maintainer adds a label (anyone can push new code after that)"
    return ""


def _finding(
    wf: Workflow,
    line: int,
    end: int,
    rule: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    description: str,
    remediation: str,
    references: list[str],
    snippet: str,
) -> Finding:
    return Finding(
        tool=TOOL,
        rule_id=rule,
        title=title,
        description=description,
        severity=severity,
        category=Category.CICD,
        confidence=confidence,
        location=Location(path=wf.path, start_line=line, end_line=end, snippet=snippet),
        cwe=["CWE-94"],
        remediation=remediation,
        references=references,
    )


def _script_injection(wf: Workflow, job: Job) -> list[Finding]:
    privileged = wf.triggers & PRIVILEGED_TRIGGERS
    forks = wf.triggers & FORK_TRIGGERS
    if not privileged and not forks:
        return []  # push/schedule/dispatch: only people with write access control the inputs
    out: list[Finding] = []
    for step in job.steps:
        sinks: list[tuple[str, str, int]] = []
        if step.run:
            sinks.append(("run", step.run, step.run_line or step.line))
        if step.action == "actions/github-script" and isinstance(step.with_.get("script"), str):
            sinks.append(("github-script", step.with_["script"], step.line))
        for kind, script, line in sinks:
            contexts = sorted(
                {m.group(0) for e in _EXPR.findall(script) for m in UNTRUSTED_CONTEXT.finditer(e)}
            )
            if not contexts:
                continue
            gate = gated(wf, job, step)
            if privileged:
                severity, why = (
                    Severity.HIGH,
                    f"`{sorted(privileged)[0]}` runs with this repository's secrets",
                )
            else:
                severity, why = Severity.MEDIUM, "fork pull requests run it with a read-only token"
            if gate:
                severity = Severity.MEDIUM if severity is Severity.HIGH else Severity.LOW
            offset = next((i for i, ln in enumerate(script.splitlines()) if contexts[0] in ln), 0)
            at = line + (1 if kind == "run" and "\n" in script else 0) + offset
            out.append(
                _finding(
                    wf,
                    at,
                    at,
                    "cicd/script-injection",
                    f"Script injection in GitHub Actions job `{job.id}` via `{contexts[0]}`",
                    severity,
                    Confidence.MEDIUM if gate else Confidence.HIGH,
                    f"`{', '.join(contexts)}` is expanded into the {kind} script of step "
                    f"`{step.name or step.index + 1}` before the shell runs it. Anyone who can set that "
                    f"text (open an issue, comment, name a branch) can run commands in the job; {why}."
                    + (f" Mitigation in place: {gate}." if gate else ""),
                    "Pass the value through an environment variable and quote it in the script, e.g. "
                    '`env: TITLE: ${{ github.event.issue.title }}` then `echo "$TITLE"`. Never expand '
                    "untrusted contexts inside `run:` or `script:`.",
                    [
                        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/"
                        "security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
                        "https://securitylab.github.com/resources/github-actions-untrusted-input/",
                    ],
                    "\n".join(script.splitlines()[offset : offset + 3]),
                )
            )
    return out


def _untrusted_checkout(wf: Workflow, job: Job) -> list[Finding]:
    trigger = next((t for t in ("pull_request_target", "workflow_run") if t in wf.triggers), None)
    if trigger is None:
        return []
    for i, step in enumerate(job.steps):
        if step.action != "actions/checkout":
            continue
        ref = " ".join(str(step.with_.get(k, "")) for k in ("ref", "repository"))
        if not _UNTRUSTED_REF.search(ref):
            continue
        runs = [s for s in job.steps[i + 1 :] if s.run or s.uses.startswith("./")]
        if not runs:
            continue  # checked out but never executed (e.g. only read by a linter action)
        secrets = sorted(job_secrets(wf, job))
        perms = wf.job_permissions(job)
        write = perms == "write-all" or (isinstance(perms, dict) and "write" in perms.values())
        gate = gated(wf, job, step)
        severity = Severity.CRITICAL if (secrets or write) and not gate else Severity.HIGH
        if gate:
            severity = Severity.MEDIUM
        held_parts = [f"secrets {', '.join(secrets)}"] if secrets else []
        if write:
            held_parts.append("a token with write permissions")
        held = " and ".join(held_parts)
        first = runs[0]
        return [
            _finding(
                wf,
                step.line,
                first.end_line,
                "cicd/untrusted-checkout",
                f"`{trigger}` job `{job.id}` checks out and runs pull request code",
                severity,
                Confidence.MEDIUM if gate else Confidence.HIGH,
                f"The `{trigger}` trigger runs in the context of the base repository, with its secrets "
                f"and a token that can write. This job checks out the pull request's own code "
                f"(`{ref.strip()}`) and then runs it (step `{first.name or first.index + 1}`), so a pull "
                "request from any fork executes attacker code"
                + (f" holding {held}" if held else "")
                + "."
                + (f" Mitigation in place: {gate}." if gate else ""),
                "Use the `pull_request` trigger to build untrusted code (no secrets, read-only token). If "
                "privileged follow-up is needed, split it into a second `workflow_run` job that only "
                "consumes artifacts as data and never executes them.",
                ["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"],
                f"uses: {step.uses}\nwith:\n  ref: {step.with_.get('ref', '')}",
            )
        ]
    return []


# ------------------------------------------------------------------ dependency confusion

_EXTRA_INDEX = re.compile(
    r"(?:--extra-index-url[ =]|^\s*extra[-_]index[-_]url\s*=|PIP_EXTRA_INDEX_URL\s*[=:]|"
    r"--index-strategy[ =]unsafe-best-match|UV_INDEX_STRATEGY\s*[=:]\s*[\"']?unsafe-best-match)",
    re.I | re.M,
)
_DEP_FILES = re.compile(
    r"(?:^|/)(?:[^/]*requirements[^/]*\.(?:txt|in)|constraints[^/]*\.txt|pip\.(?:conf|ini)|"
    r"Dockerfile[^/]*|[^/]*\.dockerfile|tox\.ini|setup\.cfg|Makefile|[^/]*\.sh|"
    r"\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|Jenkinsfile)$",
    re.I,
)
_PYPI = re.compile(r"(?:^|[/.@])(?:pypi[.]org|pythonhosted[.]org)(?![\w.-])", re.I)
# Extra indexes that only host public builds of public packages: not a private name space.
_PUBLIC_EXTRA = re.compile(r"download\.pytorch\.org|pypi\.nvidia\.com|data\.pyg\.org|wheels\.", re.I)
_PRIMARY_INDEX = re.compile(
    r"(?:--index-url[ =]|-i\s+https?://|^\s*index[-_]url\s*=|PIP_INDEX_URL\s*[=:])", re.I | re.M
)


def dependency_confusion(target: Path, exclude: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for path, rel in iter_files(target, exclude):
        if not _DEP_FILES.search(rel) or path.stat().st_size > 1_000_000:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        # PyPI as the *extra* index behind a private primary is the classic confusion setup.
        private_primary = any(
            _PRIMARY_INDEX.search(ln) and not _PYPI.search(ln)
            for ln in lines
            if not ln.lstrip().startswith("#")
        )
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith("#") or not _EXTRA_INDEX.search(line):
                continue
            if "unsafe-best-match" not in line.lower():
                if _PUBLIC_EXTRA.search(line):
                    continue
                if _PYPI.search(line) and not private_primary:
                    continue  # PyPI as the only index: nothing to confuse it with
            out.append(
                Finding(
                    tool=TOOL,
                    rule_id="supply-chain/dependency-confusion",
                    title="Dependency confusion: pip merges an extra index with PyPI",
                    description=(
                        "`--extra-index-url` (or `unsafe-best-match`) makes the installer consider PyPI "
                        "and the extra index together and install whichever offers the highest version. "
                        "Anyone can publish a package on PyPI under the name of an internal package with "
                        "a higher version number, and it will be installed instead, running its code at "
                        "install time in CI and in the build."
                    ),
                    severity=Severity.MEDIUM,
                    category=Category.CICD,
                    confidence=Confidence.HIGH,
                    location=Location(path=rel, start_line=n, end_line=n, snippet=line.strip()[:200]),
                    cwe=["CWE-427"],
                    remediation=(
                        "Install internal packages from a single index that proxies PyPI (`--index-url`), "
                        "or use uv with the default `first-index` strategy, and pin hashes "
                        "(`--require-hashes`). Registering the internal names on PyPI also blocks the attack."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
                        "https://docs.astral.sh/uv/concepts/indexes/#searching-across-multiple-indexes",
                    ],
                )
            )
    return out
