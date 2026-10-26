# CI/CD and supply chain

A CI pipeline holds the keys to production: cloud deploy roles, package-publishing tokens, and a
token that can push code. Attackers know this. Script injection and "pwn request" bugs in GitHub
Actions have led to stolen credentials and backdoored releases in well-known open-source projects.
breachgraph checks for these attacks and shows what an attacker reaches through them.

## What is checked

| Check | Rule | What it catches |
|---|---|---|
| Script injection | `cicd/script-injection` | Text an outsider controls (`github.event.issue.title`, `comment.body`, `pull_request.head.ref`, `github.head_ref`, commit messages, …) expanded with `${{ }}` inside `run:` or `actions/github-script`. The shell runs whatever the text says. **High** when the workflow runs with secrets (`issue_comment`, `issues`, `pull_request_target`, `discussion*`, `workflow_run`); **medium** on `pull_request`, where fork PRs get a read-only token. Not reported for `push`/`schedule`/`workflow_dispatch`, where only people with write access control the input. |
| Pwn request | `cicd/untrusted-checkout` | A `pull_request_target` or `workflow_run` job that checks out the pull request's code (`ref: ${{ github.event.pull_request.head.sha }}`, `github.head_ref`, `refs/pull/…`) **and then runs it**. Any fork then executes code with the base repository's secrets and token. **Critical** when the job holds secrets or a write token. |
| Dependency confusion | `supply-chain/dependency-confusion` | pip `--extra-index-url` (in requirements files, `pip.conf`, Dockerfiles, CI scripts) or uv `--index-strategy unsafe-best-match`. The installer then takes whichever index has the higher version, so anyone can publish an internal package's name on PyPI and get code execution in your build. Extra public indexes such as PyTorch's are not reported. |
| GitHub Actions hygiene | zizmor audits | Unpinned actions, credential persistence via `actions/checkout`, dangerous triggers, cache poisoning, excessive permissions, known-vulnerable actions (online, with a token), and more. From [zizmor](https://docs.zizmor.sh), which the Docker image bundles. |

A job or step whose `if:` limits it to maintainers (`author_association`, `github.actor == …`) is
still reported, with lower severity and the mitigation stated. A label gate on
`pull_request_target` counts as a weaker mitigation, because new code pushed after the label is
added still runs.

When zizmor and the built-in checks report the same injection, they merge into one finding listing
both tools.

## CI in the attack graph

A finding in a workflow matters in proportion to what that job can reach. breachgraph models every
job that an outsider can start as an entry point from the internet and links it to:

- **Cloud identities over OIDC.** For `aws-actions/configure-aws-credentials`, the role is linked
  only if its Terraform trust policy admits the token this job gets. An `issue_comment` workflow
  runs on the default branch, so a role trusted only for `repo:org/app:ref:refs/heads/main` still
  admits it. That is a common blind spot. For `azure/login`, managed identities are linked when a
  federated credential subject matches. For `google-github-actions/auth`, the named service
  account is linked.
- **Secrets the job references** (`secrets.NPM_TOKEN`, …).
- **The `GITHUB_TOKEN`** when it can push code, publish packages or write workflow caches. If
  permissions aren't set, the repository default applies. That edge is low confidence, because new
  repositories default to read-only.

Every one of these edges requires code execution in the job, which is what script injection and
pwn requests give. A trust policy that names no repository (no `sub` condition, or `repo:*`) is
different: any GitHub user can assume that role from their own repository, so it is reachable from
the internet with no weakness at all.

The repository name comes from `GITHUB_REPOSITORY` when breachgraph runs inside GitHub Actions on
the checked-out repository. Elsewhere, trust is matched on the branch, environment or event part of
`sub` only, and the edge is medium confidence.

## Limitations

- GitHub Actions only (GitLab CI and others are not parsed).
- Reusable workflows called with `secrets: inherit` are not followed into the called workflow.
- The default branch is assumed to be `main` or `master` when matching OIDC `sub` conditions.
- Trust policies outside Terraform (created in the console or another repository) cannot be
  checked. A role used by a workflow but not defined in the scanned Terraform is linked with
  medium confidence.
