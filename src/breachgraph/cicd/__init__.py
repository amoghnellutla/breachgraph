"""CI/CD and supply-chain checks that need no external tool.

Each check targets one attack that is actually used against real projects, and stays quiet
otherwise:

- script injection: text an outsider controls (an issue title, a comment, a branch name) expanded
  by ``${{ }}`` into a shell script or ``github-script``, in a workflow an outsider can trigger;
- pwn request: a ``pull_request_target`` / ``workflow_run`` job that checks out the pull request's
  code and then runs it, with the base repository's secrets and token;
- prompt injection: an AI agent reads text an outsider wrote, in a job holding secrets, a write
  token or a shell;
- dependency confusion: pip's ``--extra-index-url``, which merges a private index with PyPI and
  installs whichever has the higher version, so anyone can publish a same-named package on PyPI.

Broader GitHub Actions hygiene (unpinned actions, credential persistence, ...) comes from zizmor
when it is installed.
"""

from __future__ import annotations

import re
from pathlib import Path

from breachgraph.cicd.workflows import SECRET_RE, Job, Step, Workflow, job_secrets, load_workflows
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
# A required condition that the code comes from this repository, not a fork: forks can't run it.
_SAME_REPO = re.compile(
    r"(?:head\.repo\.full_name|head_repository\.full_name)\s*==\s*github\.repository"
    r"|github\.repository\s*==\s*github\.event\.(?:pull_request\.head\.repo|workflow_run\.head_repository)\.full_name"
    r"|head\.repo\.fork\s*==\s*false|!\s*github\.event\.pull_request\.head\.repo\.fork",
    re.I,
)
# Actions and API calls that fail a job unless the actor has write access to the repository.
_PERMISSION_CHECK = re.compile(
    r"check-user-permission|check-actor-permission|actor-permission|repository-permission|"
    r"team-membership|permission-check|collaborators/[^\s/]+/permission|"
    r"getCollaboratorPermissionLevel|checkCollaborator|checkMembership|github/command@|"
    r"slash-command-dispatch@|slash-command-action@",
    re.I,
)
# Triggers an outsider can cause in some workflow (a run of it can then trigger workflow_run).
_OUTSIDER = PRIVILEGED_TRIGGERS | FORK_TRIGGERS
_UNTRUSTED_REF = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/"
    r"|github\.event\.workflow_run\.head_(?:sha|branch)|pull_request\.head\.repo\.full_name"
    r"|github\.event\.number|github\.event\.pull_request\.number|merge_commit_sha"
)


def analyze(target: Path, exclude: list[str]) -> tuple[list[Finding], list[str]]:
    """All native CI/CD findings for a repository, and anything that could not be parsed."""
    workflows, skipped = load_workflows(target, exclude)
    findings: list[Finding] = []
    by_name = {wf.name: wf for wf in workflows}
    for wf in workflows:
        for job in wf.jobs:
            if same_repository_only(job):
                continue  # forks can't start it; only people who can push branches can
            findings += _script_injection(wf, job)
            findings += _untrusted_checkout(wf, job, by_name)
            findings += _agent_prompt_injection(wf, job)
    findings += dependency_confusion(target, exclude)
    return findings, skipped


def follows_only_trusted(wf: Workflow, by_name: dict[str, Workflow]) -> bool:
    """A `workflow_run` workflow is outside an outsider's reach when every workflow it follows is
    known and none of them can be started by one."""
    known = [by_name[n] for n in wf.run_after if n in by_name]
    return bool(known) and len(known) == len(wf.run_after) and not any(w.triggers & _OUTSIDER for w in known)


def same_repository_only(job: Job) -> bool:
    """The job's `if:` requires code from this repository: a required (top-level `&&`) term,
    not one side of an `||`."""
    return any(_SAME_REPO.search(term) for term in _required_terms(job.if_))


def _required_terms(cond: str) -> list[str]:
    """Top-level `&&` terms of an expression; the whole thing if it has a top-level `||`."""
    cond = cond.strip().removeprefix("${{").removesuffix("}}")
    terms, depth, start, i = [], 0, 0, 0
    while i < len(cond):
        ch = cond[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and cond.startswith("||", i):
            return []  # an alternative: no term is required
        elif depth == 0 and cond.startswith("&&", i):
            terms.append(cond[start:i])
            start, i = i + 2, i + 1
        i += 1
    return [*terms, cond[start:]]


def gated(wf: Workflow, job: Job, step: Step | None = None) -> str:
    """Why outsiders cannot start this job/step, or "" if they can."""
    conds = " ".join([job.if_, step.if_ if step else ""])
    if _MAINTAINER_GATE.search(conds):
        return "only runs for users with write access (if: condition)"
    if _LABEL_GATE.search(conds) and "pull_request_target" in wf.triggers:
        return "runs once a maintainer adds a label (anyone can push new code after that)"
    if checker := _permission_job(wf, job):
        return f"needs job `{checker}`, which fails unless the actor has write access"
    if checker := _permission_step(job, step):
        return f"step `{checker}` fails the job unless the actor has write access"
    if job.environment:
        return (
            f"runs in environment `{job.environment}`; if that environment requires reviewers "
            "(a repository setting breachgraph can't see), a maintainer approves each run"
        )
    return ""


def _permission_job(wf: Workflow, job: Job) -> str:
    """A job this one needs that checks the actor's permission, so this one is skipped for outsiders."""
    needs = job.raw.get("needs")
    names = [needs] if isinstance(needs, str) else [str(n) for n in needs or []]
    by_id = {j.id: j for j in wf.jobs}
    for name in names:
        dep = by_id.get(name)
        if dep and any(_checks_permission(s) for s in dep.steps):
            return name
    return ""


def _checks_permission(step: Step) -> bool:
    return bool(_PERMISSION_CHECK.search(f"{step.uses} {step.run} {step.with_.get('script', '')}"))


def _permission_step(job: Job, step: Step | None) -> str:
    """A step that runs first and stops the job for outsiders. A step of its own `if: always()`
    still runs after such a failure, so it isn't covered."""
    for s in job.steps:
        if s is step:
            return ""
        if _checks_permission(s):
            return s.name or s.uses or str(s.index + 1)
    return ""


# Commands that build or run the code in the directory they run in.
_BUILDS = re.compile(
    r"^(?:make|gmake|cmake|ninja|npm|npx|pnpm|yarn|bun|deno|node|pip3?|uv|poetry|pipx|pytest|tox|nox|"
    r"cargo|go|mvn|mvnw|gradle|gradlew|ant|bundle|rake|composer|dotnet|lake|docker|docker-compose|"
    r"source|\.)$"
)
_INTERPRETERS = re.compile(r"^(?:python3?|ruby|perl|php|bash|sh|zsh|node|pwsh)$")


def _executes_from(path: str, steps: list[Step]) -> str:
    """How steps use a checkout placed at ``path``: "runs" (code from it is built or executed),
    "inside" (commands run in it, but only ones that read it, such as git or a trusted tool given
    by absolute path), or "" (only passed around as data)."""
    p = re.escape(path.strip().removeprefix("./").rstrip("/"))
    direct = re.compile(
        rf"(?:^|[\s;&|(\"'])(?:\./)?{p}/\S+\.(?:sh|bash|py|js|mjs|cjs|ts|rb|pl|ps1)\b"
        rf"|(?:^|[;&|(][ \t]*)(?:make|gmake)(?:[ \t]+[^\s;&|]+)*?[ \t]+-C[ \t]+(?:\./)?{p}\b"
        rf"|--prefix[ =](?:\./)?{p}\b"
        rf"|(?:pip3?|uv pip|npm|pnpm|yarn)\s+(?:install|ci)\b[^\n]*(?:\./)?{p}\b",
        re.M,
    )
    enters = re.compile(rf"(?:^|[\s;&|(])(?:cd|pushd)\s+[\"']?(?:\./)?{p}(?:/|\b)", re.M)
    verdict = ""
    for s in steps:
        if s.uses.startswith(f"./{path.strip().removeprefix('./')}") or direct.search(s.run):
            return "runs"
        wd = s.working_directory.strip().removeprefix("./")
        inside = bool(wd and re.match(rf"{p}(?:/|$)", wd)) or bool(enters.search(s.run))
        if inside:
            if _builds_here(s.run):
                return "runs"
            verdict = "inside"
    return verdict


def _builds_here(script: str) -> bool:
    """Whether a script runs a build tool or a relative program (code from the current directory)."""
    for segment in re.split(r"\n|;|&&|\|\||\||\$\(|`", script):
        words = [w for w in segment.strip().split() if not re.match(r"^\w+=", w)]
        if not words:
            continue
        cmd = words[0].strip("\"'")
        if cmd.startswith("./") or _BUILDS.match(cmd):
            return True
        if _INTERPRETERS.match(cmd):
            target = next((w.strip("\"'") for w in words[1:] if not w.startswith("-")), "")
            if "-m" in words[1:] or (target and not target.startswith(("$", "/", "~"))):
                return True  # a relative script, or a module resolved from here
    return False


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


def _untrusted_checkout(wf: Workflow, job: Job, by_name: dict[str, Workflow] | None = None) -> list[Finding]:
    trigger = next((t for t in ("pull_request_target", "workflow_run") if t in wf.triggers), None)
    if trigger is None:
        return []
    # head_sha is attacker code only if an outsider can start a workflow this one follows.
    only_workflow_run = trigger == "workflow_run" and "pull_request_target" not in wf.triggers
    if only_workflow_run and by_name is not None and follows_only_trusted(wf, by_name):
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
        path = str(step.with_.get("path") or "").strip()
        use = "runs" if path in ("", ".", "./") else _executes_from(path, job.steps[i + 1 :])
        if not use:
            continue  # checked out to a side directory and only read as data
        secrets = sorted(job_secrets(wf, job))
        perms = wf.job_permissions(job)
        write = perms == "write-all" or (isinstance(perms, dict) and "write" in perms.values())
        gate = gated(wf, job, step)
        if not gate and use == "inside":
            gate = (
                f"commands run inside the checkout at `{path}` but appear only to read it (git, or tools "
                "from outside it); check that nothing there builds or runs the pull request's code"
            )
        severity = Severity.CRITICAL if (secrets or write) and not gate else Severity.HIGH
        if gate or not (secrets or write):
            # Gated, or the job holds nothing worth stealing: what remains for an attacker is
            # mostly writing to the Actions cache that privileged workflows restore.
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


# ------------------------------------------------------------------ AI agents

# Agent actions -> name. Agents read issue and pull request text as instructions, so that text is
# a prompt injection when an outsider wrote it.
_AGENT_ACTIONS = {
    "anthropics/claude-code-action": "Claude Code",
    "anthropics/claude-code-base-action": "Claude Code",
    "google-github-actions/run-gemini-cli": "Gemini CLI",
    "google-gemini/gemini-cli-action": "Gemini CLI",
    "openai/codex-action": "Codex",
    "actions/ai-inference": "GitHub AI Inference",
}
# These refuse to run for users without write access unless an input opens them up.
_WRITE_CHECK_BYPASS = {
    "anthropics/claude-code-action": ("allowed_non_write_users", "allowed_bots"),
    "openai/codex-action": ("allow-users",),
}
# This one reads the triggering issue or pull request itself, with nothing in the workflow saying so.
_READS_EVENT = {"anthropics/claude-code-action"}
_AGENT_CLI = re.compile(
    r"(?:^|[\s;&|(])(?:npx\s+(?:-y\s+)?)?(?P<cli>claude|@anthropic-ai/claude-code|gemini|@google/gemini-cli|"
    r"codex|@openai/codex|aider|opencode)(?:@\S+)?\s+(?:[^\n]*\s)?"
    r"(?:-p|--print|--prompt|exec|run|--message|--yolo|--dangerously-skip-permissions)(?:\s|=|$)",
    re.M,
)
# Settings that let an agent run any command. `Bash(gh issue view:*)` is one command, not a shell.
_AGENT_SHELL = re.compile(
    r"--dangerously-skip-permissions|--yolo|\bbypassPermissions\b|danger-full-access|"
    r"safety-strategy['\"]?[:,]\s*['\"]?unsafe|--full-auto|"
    r"\bBash\b(?!\()|\bBash\(\*|\bBash\(:\*|run_shell_command(?!\()",
)
# Token scopes that reach code, releases or other workflows. `issues: write` alone is what a
# triage bot needs: an attacker gains spam, and the action's own docs recommend that setup.
_AGENT_STRONG_SCOPES = {"contents", "packages", "actions", "workflows", "deployments", "pull-requests"}
# `id-token: write` is routine for agent actions; it matters when the job logs in to a cloud.
_CLOUD_LOGIN = {"aws-actions/configure-aws-credentials", "azure/login", "google-github-actions/auth"}
# Inputs and variables that hold the model's own key, whatever the secret behind them is called.
_MODEL_INPUT = re.compile(r"api[-_]?key|oauth_token|^ANTHROPIC_|^OPENAI_|^GEMINI_", re.I)
_DENIED_TOOLS = re.compile(r"--disallowed-?tools[ =](?:\"[^\"]*\"|'[^']*'|\\\"[^\"]*\"|\S+)", re.I)
# What the agent needs to run at all: not extra access an attacker gains.
_MODEL_KEY = re.compile(r"ANTHROPIC|CLAUDE|OPENAI|GEMINI|GOOGLE_API_KEY|CODEX", re.I)


def _agent(step: Step) -> str:
    if name := _AGENT_ACTIONS.get(step.action):
        return name
    if m := _AGENT_CLI.search(step.run):
        return m.group("cli").removeprefix("@").split("/")[-1]
    return ""


def _agent_secrets(wf: Workflow, job: Job, step: Step) -> list[str]:
    """Secrets the agent's own step can see, beyond the model's key. Another step's are out of
    its reach: GitHub passes them to that step's process only."""
    model = {
        m.group(1)
        for values in (step.with_, step.env)
        for key, value in values.items()
        if _MODEL_INPUT.search(key)
        for m in SECRET_RE.finditer(str(value))
    }
    seen = {m.group(1) for m in SECRET_RE.finditer(repr((step.with_, step.env, step.run, job.env, wf.env)))}
    return sorted(s for s in seen - model if s != "GITHUB_TOKEN" and not _MODEL_KEY.search(s))


def _agent_prompt_injection(wf: Workflow, job: Job) -> list[Finding]:
    """An agent reads text an outsider wrote, in a job holding something worth stealing."""
    privileged = wf.triggers & PRIVILEGED_TRIGGERS
    if not privileged:
        return []  # fork pull requests get no secrets and a read-only token
    out: list[Finding] = []
    for step in job.steps:
        agent = _agent(step)
        bypass = _WRITE_CHECK_BYPASS.get(step.action, ())
        if not agent or (bypass and not any(str(step.with_.get(k, "")).strip() == "*" for k in bypass)):
            continue
        given = repr((step.with_, step.env, step.run, job.env, wf.env))
        contexts = sorted({m.group(0) for e in _EXPR.findall(given) for m in UNTRUSTED_CONTEXT.finditer(e)})
        if not contexts and step.action not in _READS_EVENT:
            continue
        perms = wf.job_permissions(job)
        scopes = perms if isinstance(perms, dict) else {}
        granted = {k for k, v in scopes.items() if v == "write"}
        if not any(s.action in _CLOUD_LOGIN for s in job.steps):
            granted.discard("id-token")
        write = perms == "write-all" or bool(granted & (_AGENT_STRONG_SCOPES | {"id-token"}))
        secrets = _agent_secrets(wf, job, step)
        shell = bool(_AGENT_SHELL.search(_DENIED_TOOLS.sub(" ", repr((step.with_, step.run)))))
        if not (shell or secrets or write or granted):
            continue  # it can be talked into a wrong answer, and nothing more
        gate = gated(wf, job, step)
        severity = Severity.CRITICAL if shell and (secrets or write) else Severity.HIGH
        if gate or not (shell or secrets or write):
            severity = Severity.MEDIUM
        text = f"`{', '.join(contexts)}`" if contexts else "the text of the triggering issue or pull request"
        held = [f"secrets {', '.join(secrets)}"] if secrets else []
        held += ["a token with write permissions"] if write else []
        held += [f"a token limited to {', '.join(sorted(granted))}"] if granted and not write else []
        power = "it can run any command" if shell else "it can use whatever tools it was given"
        out.append(
            Finding(
                tool=TOOL,
                rule_id="cicd/agent-prompt-injection",
                title=f"{agent} in `{job.id}` reads text an outsider controls",
                description=(
                    f"`{sorted(privileged)[0]}` lets anyone with a GitHub account start this job, and "
                    f"{agent} receives {text}. The model can't tell that text from its instructions, so "
                    f"a crafted issue or comment can steer the agent: {power}"
                    + (f", in a job holding {' and '.join(held)}" if held else "")
                    + "."
                    + (f" Mitigation in place: {gate}." if gate else "")
                ),
                severity=severity,
                category=Category.CICD,
                confidence=Confidence.MEDIUM if gate or not shell else Confidence.HIGH,
                location=Location(
                    path=wf.path,
                    start_line=step.line,
                    end_line=step.end_line,
                    snippet=step.uses or step.run[:200],
                ),
                # With a shell this is code execution in the job, so it can start an attack path.
                cwe=["CWE-1427", "CWE-94"] if shell else ["CWE-1427"],
                remediation=(
                    "Run the agent only for people with write access (`if:` on `author_association`, or "
                    "keep the action's own write check). If outsiders must reach it, remove shell tools, "
                    "give the job a read-only token and no secrets beyond the model key, and post results "
                    "from a separate job that treats the agent's output as untrusted."
                ),
                references=[
                    "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents",
                    "https://github.com/anthropics/claude-code-action/blob/main/docs/security.md",
                    "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                ],
            )
        )
    return out


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
