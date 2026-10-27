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


PWN = """on: pull_request_target
jobs:
{extra}  test:
    {opts}runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
{path}      - run: {run}
"""
CHECK_JOB = """  check-actor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions-cool/check-user-permission@v2
        with:
          require: write
"""


def found(tmp: Path, **kw: str) -> list[tuple[str, str]]:
    args = {"extra": "", "opts": "", "path": "", "run": "npm test", **kw}
    write(tmp, ".github/workflows/t.yml", PWN.format(**args))
    return [(f.rule_id, f.severity.value) for f in analyze(tmp, [])[0]]


def test_pwn_request_baseline(tmp_path: Path) -> None:
    assert found(tmp_path) == [("cicd/untrusted-checkout", "critical")]


def test_permission_check_job_is_a_gate(tmp_path: Path) -> None:
    assert found(tmp_path, extra=CHECK_JOB, opts="needs: [check-actor]\n    ") == [
        ("cicd/untrusted-checkout", "medium")
    ]


def test_environment_is_named_as_a_possible_approval_gate(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".github/workflows/t.yml",
        PWN.format(extra="", opts="environment: external\n    ", path="", run="npm test"),
    )
    (f,) = analyze(tmp_path, [])[0]
    assert f.severity.value == "medium" and "environment `external`" in f.description


def test_side_checkout_read_as_data_is_not_reported(tmp_path: Path) -> None:
    side = "          path: pr\n"
    assert found(tmp_path, path=side, run="python3 tools/check.py --head pr") == []
    assert found(tmp_path, path=side, run="cd pr && npm test") == [("cicd/untrusted-checkout", "critical")]
    assert found(tmp_path, path=side, run="bash pr/build.sh") == [("cicd/untrusted-checkout", "critical")]


def test_no_secrets_and_read_only_is_medium(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".github/workflows/t.yml",
        PWN.format(extra="", opts="", path="", run="cargo fmt --check").replace(
            "contents: write", "contents: read"
        ),
    )
    assert [(f.rule_id, f.severity.value) for f in analyze(tmp_path, [])[0]] == [
        ("cicd/untrusted-checkout", "medium")
    ]


def test_what_runs_inside_a_side_checkout_decides(tmp_path: Path) -> None:
    """From the issue_comment survey: reading the checkout is not running it; building it is."""
    side = "          path: pr\n"
    # Only git and an echo that mentions make: data (OpenTelemetry's codeowners check).
    run = "|\n          make gen ARGS=-folder=pr\n          git -C pr diff || (echo 'run \"make gen\" in this PR' && git -C pr diff)"
    assert found(tmp_path, path=side, run=run) == []
    # Commands inside it that only read it: reported, but as something to verify (mathlib4).
    run = '|\n          cd pr\n          git merge origin/master --no-commit\n          python "${CI}/count.py" Mathlib/'
    assert found(tmp_path, path=side, run=run) == [("cicd/untrusted-checkout", "medium")]
    # Building or running it from inside: the real thing (logchimp).
    for run in (
        "|\n          cd pr\n          npm ci",
        "|\n          cd pr && python -m pytest",
        "|\n          cd pr\n          ./build.sh",
    ):
        assert found(tmp_path, path=side, run=run) == [("cicd/untrusted-checkout", "critical")], run
