# CI/CD checks on real projects

The benchmark measures breachgraph on projects that are vulnerable on purpose. This page is the
other half: its GitHub Actions checks run on the workflows of popular, well-maintained projects,
where a false alarm costs a real team's time.

## Method

`benchmarks/ci_survey.py` fetches only the workflow files of each repository through the GitHub
API (never the code) and runs the built-in CI/CD checks: script injection, pwn requests
(`pull_request_target` or `workflow_run` jobs that check out and run pull request code), and
dependency confusion. Every finding was then reviewed by hand against the full workflow.

Three samples, taken on 2026-10-27:

1. The 100 most-starred public repositories (1,354 workflows).
2. Popular repositories (500 stars or more) whose workflows use `pull_request_target`, the
   trigger behind most CI takeovers: 70 repositories, 1,117 workflows.
3. Popular repositories (500 stars or more) whose workflows use `issue_comment`: 117
   repositories, 1,188 workflows.

Findings in other people's projects are reported to their maintainers privately before anything
about them is published, so only counts are given here and no project is named.

## Results

| | Top 100 | `pull_request_target` | `issue_comment` |
|---|---:|---:|---:|
| Workflows | 1,354 | 1,117 | 1,188 |
| Findings before review | 4 (2 critical, 1 medium, 1 low) | 26 (11 critical, 12 high, 3 medium) | 9 (5 critical, 4 medium) |
| Exploitable by an outsider with no maintainer step | 0 | 0 | 1 |
| Findings after the fixes below | 1, low | 24, all medium | 7: 1 critical, 6 medium |
| Critical or high after the fixes | 0 | 0 | 1, the real one |

The one real finding is a pwn request: an external contributor's pull request can change files
that a privileged `pull_request_target` job builds, because the job's guard only protects the
workflow files. Details are withheld until its maintainers have fixed it.

The popular projects that use risky triggers mostly do so carefully: a permission-check job the
others depend on, an environment that needs approval, a label a maintainer must add, a job that
holds no secrets, or a checkout of the pull request into a side directory that is only read as
data. breachgraph did not recognize several of these and rated them too high.

## What changed in breachgraph

Each wrong call became a rule and a regression test (`tests/test_cicd_precision.py`):

- A job whose `if:` requires code from this repository (`head.repo.full_name ==
  github.repository`, `head.repo.fork == false`, or the `workflow_run` equivalent) can't be
  started from a fork, and is not reported. The condition has to be required; one side of an `||`
  doesn't count.
- A `workflow_run` job that checks out the triggering commit is reported only when a workflow it
  follows can be started by an outsider. Following a workflow that only runs on pushes to the
  default branch is safe.
- A job that `needs` a permission-check job, or runs in an `environment` (which may require
  reviewers), is reported as gated, at medium, with the gate named.
- A pull request checked out into a side directory and only passed to trusted scripts as data is
  not reported. Running anything from that directory still is.
- A job with no secrets and a read-only token is medium, not high: what remains is mostly writing
  to the Actions cache.
- What runs inside a side checkout decides: building or running it (`make`, `npm`, `pip install`,
  `./script`, `python -m`) is critical; commands that only read it (git, or a trusted tool given by
  absolute path) are medium, with what to verify; passing it around as data is not reported.

## Limits

Two samples of popular projects are not a random sample of all repositories; less-maintained
projects likely have more real problems. Settings that live outside the repository (environment
protection rules, branch protection, who has write access) can't be seen, so a gated finding
says what to check rather than declaring the job safe.

Reproduce:

```bash
GH_TOKEN=... python benchmarks/ci_survey.py --top 100
GH_TOKEN=... python benchmarks/ci_survey.py --uses-trigger pull_request_target --min-stars 500 --limit 300
```

Results go to `.tmp/ci-survey/` and are not committed.
