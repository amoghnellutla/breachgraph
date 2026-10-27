"""False positives found by running the CI/CD checks on the 100 most-starred repositories."""

from pathlib import Path

from breachgraph.cicd import analyze
from tests.test_entry_points import write


def rules(tmp: Path) -> list[str]:
    return [f.rule_id for f in analyze(tmp, [])[0]]


PR_INJECTION = """on:
  pull_request:
jobs:
  bump:
    if: {cond}
    runs-on: ubuntu-latest
    steps:
      - run: git push origin HEAD:${{{{ github.head_ref }}}}
"""


def test_same_repository_guard_keeps_forks_out(tmp_path: Path) -> None:
    """A job that only runs for branches in this repository can't be started from a fork."""
    write(
        tmp_path,
        ".github/workflows/v.yml",
        PR_INJECTION.format(cond="github.event.pull_request.head.repo.full_name == github.repository"),
    )
    assert rules(tmp_path) == []
    write(
        tmp_path,
        ".github/workflows/v.yml",
        PR_INJECTION.format(cond="github.event.pull_request.head.repo.fork == false"),
    )
    assert rules(tmp_path) == []


def test_guard_on_one_side_of_an_or_is_not_a_guard(tmp_path: Path) -> None:
    cond = "github.event.pull_request.head.repo.full_name == github.repository || github.event_name == 'pull_request'"
    write(tmp_path, ".github/workflows/v.yml", PR_INJECTION.format(cond=cond))
    assert rules(tmp_path) == ["cicd/script-injection"]


RELEASE = """name: Release
on:
  push:
    branches: [main]
"""
CI = """name: CI
on:
  pull_request:
"""
PUBLISH = """on:
  workflow_run:
    workflows: [{after}]
    types: [completed]
jobs:
  publish:
    {cond}runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.workflow_run.head_sha }}}}
      - run: make release
"""


def test_workflow_run_after_a_push_only_workflow_is_trusted(tmp_path: Path) -> None:
    write(tmp_path, ".github/workflows/release.yml", RELEASE + "jobs: {}\n")
    write(tmp_path, ".github/workflows/ci.yml", CI + "jobs: {}\n")
    write(tmp_path, ".github/workflows/publish.yml", PUBLISH.format(after="Release", cond=""))
    assert rules(tmp_path) == []  # only maintainers' pushes run Release
    write(tmp_path, ".github/workflows/publish.yml", PUBLISH.format(after="CI", cond=""))
    assert rules(tmp_path) == ["cicd/untrusted-checkout"]  # CI runs for fork pull requests
    guard = "if: github.event.workflow_run.head_repository.full_name == github.repository && github.event.workflow_run.event == 'push'\n    "
    write(tmp_path, ".github/workflows/publish.yml", PUBLISH.format(after="CI", cond=guard))
    assert rules(tmp_path) == []
    write(tmp_path, ".github/workflows/publish.yml", PUBLISH.format(after="Unknown", cond=""))
    assert rules(tmp_path) == ["cicd/untrusted-checkout"]  # can't tell what triggers it: still reported
