"""CI/CD and supply-chain checks, the zizmor adapter, and CI jobs in the attack graph."""

import json
from pathlib import Path

from breachgraph.cicd import analyze, dependency_confusion
from breachgraph.cicd.workflows import parse_workflow
from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.model import INTERNET_ID, Confidence, EdgeKind, Graph
from breachgraph.graph.sources.actions import ActionsSource, admits
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.hcl import decode_policy
from breachgraph.graph.sources.terraform import TerraformSource
from breachgraph.models import Category, Severity
from breachgraph.scanners.base import ScanContext
from breachgraph.scanners.zizmor import ZizmorScanner
from tests.conftest import FIXTURES

PLATFORM = Path(__file__).parent.parent / "examples" / "vulnerable-platform"


def wf(tmp: Path, text: str, name: str = "ci.yml") -> Path:
    p = tmp / ".github" / "workflows" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return tmp


def rules(tmp: Path) -> list[tuple[str, Severity]]:
    findings, _ = analyze(tmp, [])
    return [(f.rule_id, f.severity) for f in findings]


INJECT = """
on: {trigger}
jobs:
  bot:
    runs-on: ubuntu-latest
    {cond}
    steps:
      - run: echo "${{{{ github.event.{field} }}}}"
"""


def test_parser_keeps_on_key_and_lines(tmp_path: Path) -> None:
    w = parse_workflow(INJECT.format(trigger="issues", cond="", field="issue.title"), "x.yml")
    assert w is not None and w.triggers == {"issues"}
    step = w.jobs[0].steps[0]
    assert step.line == 8 and "issue.title" in step.run


def test_script_injection_on_privileged_trigger(tmp_path: Path) -> None:
    wf(tmp_path, INJECT.format(trigger="issue_comment", cond="", field="comment.body"))
    findings, _ = analyze(tmp_path, [])
    assert [(f.rule_id, f.severity) for f in findings] == [("cicd/script-injection", Severity.HIGH)]
    f = findings[0]
    assert f.category is Category.CICD and f.cwe == ["CWE-94"] and f.location.start_line == 8
    assert "env:" in (f.remediation or "")


def test_script_injection_on_fork_pr_is_medium(tmp_path: Path) -> None:
    wf(tmp_path, INJECT.format(trigger="pull_request", cond="", field="pull_request.title"))
    assert rules(tmp_path) == [("cicd/script-injection", Severity.MEDIUM)]


def test_no_injection_for_push_or_env_indirection(tmp_path: Path) -> None:
    wf(tmp_path, INJECT.format(trigger="push", cond="", field="head_commit.message"))
    assert rules(tmp_path) == []
    safe = """
on: issues
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
"""
    wf(tmp_path, safe)
    assert rules(tmp_path) == []


def test_maintainer_gate_lowers_severity(tmp_path: Path) -> None:
    cond = "if: github.event.comment.author_association == 'MEMBER'"
    wf(tmp_path, INJECT.format(trigger="issue_comment", cond=cond, field="comment.body"))
    findings, _ = analyze(tmp_path, [])
    assert findings[0].severity is Severity.MEDIUM and "write access" in findings[0].description


def test_github_script_injection(tmp_path: Path) -> None:
    wf(
        tmp_path,
        """
on: pull_request_target
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.pull_request.head.ref }}")
""",
    )
    assert rules(tmp_path) == [("cicd/script-injection", Severity.HIGH)]


PWN = """
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    {cond}
    steps:
      - uses: actions/checkout@v4
        with:
          {ref}
      {after}
"""


def test_pwn_request_with_secret_is_critical(tmp_path: Path) -> None:
    after = "- run: npm test\n        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"
    wf(tmp_path, PWN.format(cond="", ref="ref: ${{ github.event.pull_request.head.sha }}", after=after))
    findings, _ = analyze(tmp_path, [])
    assert [(f.rule_id, f.severity) for f in findings] == [("cicd/untrusted-checkout", Severity.CRITICAL)]
    assert "NPM_TOKEN" in findings[0].description


def test_pwn_request_needs_untrusted_ref_and_execution(tmp_path: Path) -> None:
    wf(tmp_path, PWN.format(cond="", ref="fetch-depth: 0", after="- run: npm test"))
    assert rules(tmp_path) == []  # checks out the base branch
    wf(tmp_path, PWN.format(cond="", ref="ref: ${{ github.head_ref }}", after=""))
    assert rules(tmp_path) == []  # checked out, never run


def test_pwn_request_behind_label_is_medium(tmp_path: Path) -> None:
    cond = "if: contains(github.event.pull_request.labels.*.name, 'safe to test')"
    wf(
        tmp_path,
        PWN.format(cond=cond, ref="ref: ${{ github.event.pull_request.head.sha }}", after="- run: make"),
    )
    assert rules(tmp_path) == [("cicd/untrusted-checkout", Severity.MEDIUM)]


def test_dependency_confusion(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://pkgs.internal.example/simple\nflask==3.0.0\n", encoding="utf-8"
    )
    (tmp_path / "requirements-gpu.txt").write_text(
        "--extra-index-url https://download.pytorch.org/whl/cu121\n# --extra-index-url https://x\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "RUN uv pip install --index-strategy unsafe-best-match -r requirements.txt\n", encoding="utf-8"
    )
    found = dependency_confusion(tmp_path, [])
    assert sorted((f.location.path, f.location.start_line) for f in found) == [
        ("Dockerfile", 1),
        ("requirements.txt", 1),
    ]
    assert all(f.cwe == ["CWE-427"] for f in found)


def test_zizmor_parser(tmp_path: Path) -> None:
    ctx = ScanContext(target=tmp_path, work_dir=tmp_path, config=Config())
    raw = json.loads((FIXTURES / "zizmor.json").read_text(encoding="utf-8"))
    findings = ZizmorScanner().parse(raw, ctx)
    assert len(findings) == 7
    inj = next(f for f in findings if f.rule_id == "template-injection")
    assert inj.location.path == ".github/workflows/triage.yml" and inj.location.start_line == 21
    assert inj.cwe == ["CWE-94"] and inj.severity is Severity.HIGH and inj.category is Category.CICD
    assert all(f.references and f.references[0].startswith("https://docs.zizmor.sh") for f in findings)


def test_zizmor_and_native_injection_merge() -> None:
    from breachgraph.normalize import dedupe, finalize

    ctx = ScanContext(target=PLATFORM, work_dir=PLATFORM, config=Config())
    zz = ZizmorScanner().parse(json.loads((FIXTURES / "zizmor.json").read_text(encoding="utf-8")), ctx)
    native, _ = analyze(PLATFORM, [])
    merged = dedupe(finalize(zz + native))
    injection = [f for f in merged if "CWE-94" in f.cwe and f.location.path.endswith("triage.yml")]
    assert len(injection) == 1 and set(injection[0].sources) == {"cicd", "zizmor"}


def test_quoted_keys_in_jsonencode_policies() -> None:
    doc = decode_policy(
        '${jsonencode({ Statement = [{ Condition = { StringLike = { "a.b:sub" = "repo:o/r:*" } } }] })}'
    )
    assert doc == {"Statement": [{"Condition": {"StringLike": {"a.b:sub": "repo:o/r:*"}}}]}


# ------------------------------------------------------------------ attack graph

TRUST = """
resource "aws_iam_role" "deploy" {{
  name = "deploy"
  assume_role_policy = jsonencode({{
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Federated = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" }}
      Action    = "sts:AssumeRoleWithWebIdentity"
      {condition}
    }}]
  }})
}}
"""
BOT = """
on: issue_comment
permissions:
  id-token: write
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: {role}
          aws-region: us-east-1
"""


def graph(tmp: Path, tf: str, workflow: str) -> tuple[Graph, list[str]]:
    (tmp / "main.tf").write_text(tf, encoding="utf-8")
    wf(tmp, workflow)
    g = Graph()
    ctx = SourceContext(root=tmp, exclude=[])
    TerraformSource().collect(ctx, g)
    ActionsSource().collect(ctx, g)
    return g, ctx.skipped


JOB = "gha:job:.github/workflows/ci.yml:bot"
ROLE = "aws:iam_role:deploy"


def has(g: Graph, src: str, dst: str, kind: EdgeKind | None = None) -> bool:
    return any(e.src == src and e.dst == dst and (kind is None or e.kind is kind) for e in g.edges)


def test_admits_matches_sub_patterns() -> None:
    assert admits(["repo:o/r:ref:refs/heads/main"], "o/r", ["ref:refs/heads/main"])
    assert not admits(["repo:o/r:environment:prod"], "o/r", ["ref:refs/heads/main"])
    assert admits(["repo:o/r:*"], None, ["pull_request"])
    assert not admits(["repo:other/r:*"], "o/r", ["pull_request"])


def test_oidc_role_linked_when_trust_admits_the_job(tmp_path: Path) -> None:
    cond = 'Condition = { StringLike = { "token.actions.githubusercontent.com:sub" = "repo:o/r:ref:refs/heads/main" } }'
    g, _ = graph(tmp_path, TRUST.format(condition=cond), BOT.format(role="arn:aws:iam::1:role/deploy"))
    assert has(g, INTERNET_ID, JOB, EdgeKind.EXPOSES)
    edge = next(e for e in g.edges if e.src == JOB and e.dst == ROLE)
    assert edge.requires and edge.confidence is Confidence.MEDIUM  # repo name unknown outside Actions
    assert not has(g, INTERNET_ID, ROLE)


def test_oidc_role_not_linked_when_trust_excludes_the_job(tmp_path: Path) -> None:
    cond = 'Condition = { StringEquals = { "token.actions.githubusercontent.com:sub" = "repo:o/r:environment:prod" } }'
    g, skipped = graph(tmp_path, TRUST.format(condition=cond), BOT.format(role="arn:aws:iam::1:role/deploy"))
    assert not has(g, JOB, ROLE)
    assert any("cannot assume deploy" in s for s in skipped)


def test_oidc_trust_without_sub_is_open_to_any_repo(tmp_path: Path) -> None:
    cond = (
        'Condition = { StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" } }'
    )
    g, _ = graph(tmp_path, TRUST.format(condition=cond), BOT.format(role="${{ secrets.ROLE }}"))
    edge = next(e for e in g.edges if e.src == INTERNET_ID and e.dst == ROLE)
    assert not edge.requires and "any" in edge.note  # no weakness needed: any GitHub repo can assume it
    assert has(g, JOB, ROLE)  # role from a secret, matched by trust


def test_job_secrets_and_token(tmp_path: Path) -> None:
    flow = """
on: pull_request_target
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - run: ./publish.sh
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
          GH: ${{ secrets.GITHUB_TOKEN }}
"""
    g, _ = graph(tmp_path, "", flow)
    assert has(g, JOB, "gha:secret:PYPI_TOKEN", EdgeKind.MOUNTS)
    assert "gha:secret:GITHUB_TOKEN" not in g.nodes
    token = next(e for e in g.edges if e.src == JOB and e.dst == "gha:token:contents")
    assert token.confidence is Confidence.LOW  # permissions unset: repository default


def test_push_workflows_are_not_entry_points(tmp_path: Path) -> None:
    g, _ = graph(
        tmp_path, "", BOT.format(role="arn:aws:iam::1:role/deploy").replace("on: issue_comment", "on: push")
    )
    assert JOB not in g.nodes


def test_azure_federated_github_identity(tmp_path: Path) -> None:
    tf = """
resource "azurerm_user_assigned_identity" "ci" {
  name = "ci"
}
resource "azurerm_federated_identity_credential" "gh" {
  name      = "gh"
  parent_id = azurerm_user_assigned_identity.ci.id
  issuer    = "https://token.actions.githubusercontent.com"
  subject   = "repo:o/r:pull_request"
}
"""
    flow = """
on: pull_request_target
permissions:
  id-token: write
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
"""
    g, _ = graph(tmp_path, tf, flow)
    assert has(g, JOB, "azure:identity:ci", EdgeKind.USES_IDENTITY)


def test_demo_ci_path_to_customer_data() -> None:
    findings, _ = analyze(PLATFORM, [])
    for f in findings:
        f.fingerprint = f.rule_id
    res = build_attack_graph(PLATFORM, findings, Config())
    chains = [p.nodes for p in res.paths]
    assert [
        "internet",
        "gha:job:.github/workflows/triage.yml:triage",
        "aws:iam_role:ci-deploy",
        "aws:s3_bucket:shop-customer-data-prod",
    ] in chains
    assert any(
        p.nodes[-1] == "gha:token:contents" and p.weaknesses == ["cicd/untrusted-checkout"] for p in res.paths
    )


def test_semgrep_actions_rules_merge_with_native_findings() -> None:
    from breachgraph.models import Confidence as FConfidence
    from breachgraph.models import Finding, Location
    from breachgraph.normalize import dedupe, finalize

    semgrep = [
        Finding(
            tool="semgrep",
            rule_id=f"yaml.github-actions.security.{rid}.{rid}",
            title=rid,
            severity=Severity.HIGH,
            category=Category.CICD,
            confidence=FConfidence.HIGH,
            location=Location(path=path, start_line=start, end_line=end),
            cwe=[cwe],
        )
        for rid, path, start, end, cwe in [
            ("run-shell-injection", ".github/workflows/triage.yml", 20, 21, "CWE-78"),
            ("pull-request-target-code-checkout", ".github/workflows/preview.yml", 16, 18, "CWE-829"),
        ]
    ]
    native, _ = analyze(PLATFORM, [])
    merged = dedupe(finalize(semgrep + native))
    assert len(merged) == 2
    assert all(set(f.sources) == {"cicd", "semgrep"} for f in merged)


def test_zizmor_skipped_without_workflows(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    ctx = ScanContext(target=tmp_path, work_dir=tmp_path, config=Config())
    outcome = ZizmorScanner().run(ctx)
    assert outcome.run.status.value == "skipped" and "no GitHub Actions" in (outcome.run.message or "")


# ------------------------------------------------------------------ review regressions


def test_role_stub_outside_terraform_still_linked(tmp_path: Path) -> None:
    """A role known only from a reference (e.g. an IRSA annotation) is not "untrusting"."""
    tf = 'resource "aws_iam_role_policy_attachment" "x" {\n  role       = "deploy"\n  policy_arn = "arn"\n}\n'
    g = Graph()
    from breachgraph.graph.model import Node, NodeKind

    g.add_node(Node(id=ROLE, kind=NodeKind.IDENTITY, name="IAM role deploy", attrs={"platform": "aws"}))
    (tmp_path / "main.tf").write_text(tf, encoding="utf-8")
    wf(tmp_path, BOT.format(role="arn:aws:iam::1:role/deploy"))
    ctx = SourceContext(root=tmp_path, exclude=[])
    ActionsSource().collect(ctx, g)
    edge = next(e for e in g.edges if e.src == JOB and e.dst == ROLE)
    assert edge.confidence is Confidence.MEDIUM and not any("does not trust" in s for s in ctx.skipped)


def test_org_wide_trust_admitted_without_slug() -> None:
    assert admits(["repo:my-org/*"], None, ["ref:refs/heads/main"])


def test_mixed_triggers_get_every_sub(tmp_path: Path) -> None:
    from breachgraph.graph.sources.actions import oidc_suffixes

    w = parse_workflow("on: [pull_request_target, issue_comment]\njobs:\n  a:\n    steps: []\n", "x.yml")
    assert w is not None
    assert oidc_suffixes(w, w.jobs[0]) == ["pull_request", "ref:refs/heads/main", "ref:refs/heads/master"]


def test_pwn_request_sees_job_level_secrets(tmp_path: Path) -> None:
    flow = PWN.format(
        cond="env:\n      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}",
        ref="ref: ${{ github.event.pull_request.head.sha }}",
        after="- run: npm install",
    )
    wf(tmp_path, flow)
    findings, _ = analyze(tmp_path, [])
    assert findings[0].severity is Severity.CRITICAL and "NPM_TOKEN" in findings[0].description


def test_pypi_as_extra_behind_private_primary(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://pkgs.corp.example/simple\n--extra-index-url https://pypi.org/simple\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements-dev.txt").write_text(
        "--extra-index-url https://pypi.org/simple\n", encoding="utf-8"
    )
    found = dependency_confusion(tmp_path, [])
    assert [(f.location.path, f.location.start_line) for f in found] == [("requirements.txt", 2)]


def test_broken_symlink_does_not_abort(tmp_path: Path) -> None:
    import pytest

    wf(tmp_path, INJECT.format(trigger="issues", cond="", field="issue.title"))
    try:
        (tmp_path / "deploy.sh").symlink_to(tmp_path / "missing.sh")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted here")
    assert [r for r, _ in rules(tmp_path)] == ["cicd/script-injection"]
