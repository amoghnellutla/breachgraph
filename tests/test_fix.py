"""`breachgraph fix`: safe, deterministic fixes for choke points, and one pull request per fix."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from breachgraph import fix as fixer
from breachgraph.cicd import analyze
from breachgraph.models import Category, Confidence, Finding, Location, Package, ScanResult, Severity
from tests.test_entry_points import write


def dep(path: str, name: str, version: str, fixed: str) -> Finding:
    return Finding(
        tool="trivy",
        rule_id="CVE-2099-1",
        title=f"CVE-2099-1 in {name}",
        severity=Severity.CRITICAL,
        category=Category.SCA,
        confidence=Confidence.HIGH,
        location=Location(path=path),
        package=Package(name=name, version=version, fixed_version=fixed),
        fingerprint=f"fp-{name}",
    )


def injection(path: str, line: int) -> Finding:
    return Finding(
        tool="cicd",
        rule_id="cicd/script-injection",
        title="Script injection",
        severity=Severity.HIGH,
        category=Category.CICD,
        confidence=Confidence.HIGH,
        location=Location(path=path, start_line=line),
        fingerprint="fp-inj",
    )


def test_dependency_upgrades(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "flask==2.0.1\nRequests[socks] == 2.25.1  # http\n")
    out = fixer.fix_finding(dep("requirements.txt", "requests", "2.25.1", "2.32.0, 2.31.1"), tmp_path)
    assert out.files["requirements.txt"] == "flask==2.0.1\nRequests[socks] == 2.31.1  # http\n"

    write(tmp_path, "web/package.json", '{\n  "dependencies": {"lodash": "^4.17.15", "react": "18.2.0"}\n}\n')
    out = fixer.fix_finding(dep("web/package-lock.json", "lodash", "4.17.15", "4.17.21"), tmp_path)
    assert '"lodash": "^4.17.21"' in out.files["web/package.json"] and out.notes

    write(tmp_path, "svc/go.mod", "module x\n\nrequire (\n\tgolang.org/x/net v0.7.0\n)\n")
    out = fixer.fix_finding(dep("svc/go.mod", "golang.org/x/net", "v0.7.0", "0.23.0"), tmp_path)
    assert "\tgolang.org/x/net v0.23.0\n" in out.files["svc/go.mod"]


def test_dependency_cases_that_need_a_person(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "requests==2.25.1 \\\n    --hash=sha256:abc\n")
    assert (
        "hash-pinned"
        in fixer.fix_finding(dep("requirements.txt", "requests", "2.25.1", "2.32.0"), tmp_path).reason
    )
    write(tmp_path, "web/package.json", '{"dependencies": {"express": "4.17.1"}}')
    out = fixer.fix_finding(dep("web/package-lock.json", "qs", "6.5.2", "6.5.3"), tmp_path)
    assert not out.files and "transitive" in out.reason
    assert (
        "no fixed version"
        in fixer.fix_finding(dep("web/package.json", "express", "4.17.1", ""), tmp_path).reason
    )


WORKFLOW = """on: issue_comment
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Greet
        env:
          TOKEN: ${{ secrets.T }}
        run: |
          echo "Hi ${{ github.event.comment.body }}"
          echo '${{ github.event.issue.title }}' ${{ github.sha }}
      - run: git checkout ${{ github.head_ref }}
"""


def test_script_injection_moves_into_env(tmp_path: Path) -> None:
    write(tmp_path, ".github/workflows/bot.yml", WORKFLOW)
    first = fixer.fix_finding(injection(".github/workflows/bot.yml", 10), tmp_path)
    second = fixer.fix_finding(injection(".github/workflows/bot.yml", 12), tmp_path)
    text = first.files[".github/workflows/bot.yml"]
    assert 'echo "Hi ${COMMENT_BODY}"' in text and "echo ''\"${ISSUE_TITLE}\"'' ${{ github.sha }}" in text
    step = yaml.safe_load(text)["jobs"]["triage"]["steps"][0]
    assert step["env"] == {
        "TOKEN": "${{ secrets.T }}",
        "COMMENT_BODY": "${{ github.event.comment.body }}",
        "ISSUE_TITLE": "${{ github.event.issue.title }}",
    }
    step2 = yaml.safe_load(second.files[".github/workflows/bot.yml"])["jobs"]["triage"]["steps"][1]
    assert step2 == {"run": 'git checkout "${HEAD_REF}"', "env": {"HEAD_REF": "${{ github.head_ref }}"}}


def test_fixed_workflow_is_no_longer_flagged(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".github/workflows/bot.yml",
        WORKFLOW.replace("      - run: git checkout ${{ github.head_ref }}\n", ""),
    )
    assert [f.rule_id for f in analyze(tmp_path, [])[0]] == ["cicd/script-injection"]
    out = fixer.fix_finding(injection(".github/workflows/bot.yml", 10), tmp_path)
    write(tmp_path, ".github/workflows/bot.yml", out.files[".github/workflows/bot.yml"])
    assert analyze(tmp_path, [])[0] == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_one_branch_per_fix(tmp_path: Path) -> None:
    remote, repo = tmp_path / "remote.git", tmp_path / "repo"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    for k, v in (("user.name", "t"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
        subprocess.run(["git", "-C", str(repo), "config", k, v], check=True)
    write(repo, "requirements.txt", "requests==2.25.1\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", str(remote)], check=True)
    f = dep("requirements.txt", "requests", "2.25.1", "2.32.0")
    fx = fixer.fix_finding(f, repo)
    with pytest.raises(fixer.FixError, match="not a GitHub repository"):
        fixer.open_pull_requests([fx], ScanResult(breachgraph_version="t", target=str(repo)), repo, None)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "set-url", "origin", "https://github.com/acme/app.git"], check=True
    )
    subprocess.run(["git", "-C", str(repo), "remote", "set-url", "--push", "origin", str(remote)], check=True)
    urls = fixer.open_pull_requests([fx], ScanResult(breachgraph_version="t", target=str(repo)), repo, None)
    assert urls == ["https://github.com/acme/app/compare/main...breachgraph/fix-fp-request?expand=1"]
    assert (repo / "requirements.txt").read_text(encoding="utf-8") == "requests==2.25.1\n"  # back on main
    pushed = subprocess.run(
        ["git", "--git-dir", str(remote), "show", "breachgraph/fix-fp-request:requirements.txt"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    assert pushed == "requests==2.32.0\n"
