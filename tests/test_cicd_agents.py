"""AI agents in workflows: reported when an outsider's text reaches one that holds something."""

from pathlib import Path

from breachgraph.cicd import analyze
from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.models import Finding, Severity
from tests.test_entry_points import write

GEMINI = """on:
  issues:
    types: [opened]
{permissions}
jobs:
  triage:
    {condition}
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        env:
          ISSUE_BODY: ${{{{ github.event.issue.body }}}}
          DEPLOY_KEY: ${{{{ secrets.DEPLOY_KEY }}}}
        with:
          gemini_api_key: ${{{{ secrets.GEMINI_API_KEY }}}}
          settings: '{settings}'
          prompt: Label this issue
"""
CLAUDE = """on:
  issue_comment:
    types: [created]
permissions:
  contents: write
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
{inputs}
"""


def agents(tmp: Path) -> list[Finding]:
    return [f for f in analyze(tmp, [])[0] if f.rule_id == "cicd/agent-prompt-injection"]


def gemini(tmp: Path, permissions: str = "", condition: str = "", settings: str = "{{}}") -> None:
    text = GEMINI.format(
        permissions=permissions, condition=condition or "timeout-minutes: 5", settings=settings
    )
    write(tmp, ".github/workflows/t.yml", text)


def test_agent_with_a_shell_and_a_secret_is_critical(tmp_path: Path) -> None:
    gemini(tmp_path, settings='{{"coreTools": ["run_shell_command"]}}')
    [f] = agents(tmp_path)
    assert f.severity is Severity.CRITICAL
    assert "CWE-94" in f.cwe and "secrets DEPLOY_KEY" in f.description
    assert "GEMINI_API_KEY" not in f.description  # the model key is not extra access


def test_one_allowed_command_is_not_a_shell(tmp_path: Path) -> None:
    gemini(tmp_path, settings='{{"coreTools": ["run_shell_command(gh issue edit)"]}}')
    [f] = agents(tmp_path)
    assert f.severity is Severity.HIGH and f.cwe == ["CWE-1427"]


def test_maintainer_only_job_is_medium(tmp_path: Path) -> None:
    gemini(tmp_path, condition="if: github.event.issue.author_association == 'OWNER'")
    [f] = agents(tmp_path)
    assert f.severity is Severity.MEDIUM and "Mitigation in place" in f.description


def test_agent_given_no_outsider_text_is_quiet(tmp_path: Path) -> None:
    gemini(tmp_path)
    text = (tmp_path / ".github/workflows/t.yml").read_text(encoding="utf-8")
    write(tmp_path, ".github/workflows/t.yml", text.replace("github.event.issue.body", "github.repository"))
    assert agents(tmp_path) == []


def test_push_workflows_are_quiet(tmp_path: Path) -> None:
    gemini(tmp_path)
    text = (tmp_path / ".github/workflows/t.yml").read_text(encoding="utf-8")
    write(tmp_path, ".github/workflows/t.yml", text.replace("issues:\n    types: [opened]", "push:"))
    assert agents(tmp_path) == []


def test_write_check_keeps_outsiders_out_of_claude_code(tmp_path: Path) -> None:
    write(tmp_path, ".github/workflows/c.yml", CLAUDE.format(inputs=""))
    assert agents(tmp_path) == []
    named = '          allowed_non_write_users: "alice,bob"'
    write(tmp_path, ".github/workflows/c.yml", CLAUDE.format(inputs=named))
    assert agents(tmp_path) == []


def test_opening_claude_code_to_everyone_is_reported(tmp_path: Path) -> None:
    inputs = "          allowed_non_write_users: '*'\n          claude_args: --allowedTools Bash"
    write(tmp_path, ".github/workflows/c.yml", CLAUDE.format(inputs=inputs))
    [f] = agents(tmp_path)
    assert f.severity is Severity.CRITICAL  # reads the event itself, shell and a write token
    assert "triggering issue or pull request" in f.description


def test_read_only_agent_without_secrets_is_quiet(tmp_path: Path) -> None:
    text = """on: issues
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/ai-inference@v1
        with:
          prompt: Summarize ${{ github.event.issue.body }}
"""
    write(tmp_path, ".github/workflows/t.yml", text)
    assert agents(tmp_path) == []


def test_a_token_limited_to_issues_is_medium(tmp_path: Path) -> None:
    text = """on: issues
permissions:
  issues: write
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
"""
    write(tmp_path, ".github/workflows/t.yml", text)
    [f] = agents(tmp_path)
    assert f.severity is Severity.MEDIUM and "limited to issues" in f.description


def triage(with_lines: str, extra_steps: str = "", scopes: str = "issues: write") -> str:
    return f"""on: issues
permissions:
  {scopes}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
{with_lines}
{extra_steps}
"""


def test_a_denied_shell_is_not_a_shell(tmp_path: Path) -> None:
    args = '          claude_args: --disallowedTools "Bash,WebFetch"'
    write(tmp_path, ".github/workflows/t.yml", triage(args))
    [f] = agents(tmp_path)
    assert f.severity is Severity.MEDIUM and "CWE-94" not in f.cwe


def test_a_secret_in_another_step_is_out_of_reach(tmp_path: Path) -> None:
    other = "      - run: ./report.sh\n        env:\n          STATS: ${{ secrets.STATS_KEY }}"
    write(tmp_path, ".github/workflows/t.yml", triage("", other))
    [f] = agents(tmp_path)
    assert f.severity is Severity.MEDIUM and "STATS_KEY" not in f.description


def test_a_model_key_under_any_name_is_not_extra_access(tmp_path: Path) -> None:
    key = "          anthropic_api_key: ${{ secrets.LLM_GATEWAY_TOKEN }}"
    write(tmp_path, ".github/workflows/t.yml", triage(key))
    [f] = agents(tmp_path)
    assert f.severity is Severity.MEDIUM and "LLM_GATEWAY_TOKEN" not in f.description


def test_id_token_counts_only_with_a_cloud_login(tmp_path: Path) -> None:
    scopes = "issues: write\n  id-token: write"
    write(tmp_path, ".github/workflows/t.yml", triage("", scopes=scopes))
    assert agents(tmp_path)[0].severity is Severity.MEDIUM
    login = "      - uses: aws-actions/configure-aws-credentials@v4"
    write(tmp_path, ".github/workflows/t.yml", triage("", login, scopes))
    assert agents(tmp_path)[0].severity is Severity.HIGH


def test_cli_in_a_run_step_counts(tmp_path: Path) -> None:
    text = """on: issue_comment
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: npx -y @anthropic-ai/claude-code -p "$BODY" --dangerously-skip-permissions
        env:
          BODY: ${{ github.event.comment.body }}
          TOKEN: ${{ secrets.RELEASE_TOKEN }}
"""
    write(tmp_path, ".github/workflows/t.yml", text)
    [f] = agents(tmp_path)
    assert f.severity is Severity.CRITICAL


def test_words_that_look_like_a_cli_are_not_one(tmp_path: Path) -> None:
    text = """on: issue_comment
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$BODY" | grep codex
        env:
          BODY: ${{ github.event.comment.body }}
          TOKEN: ${{ secrets.RELEASE_TOKEN }}
"""
    write(tmp_path, ".github/workflows/t.yml", text)
    assert agents(tmp_path) == []


def test_an_agent_with_a_shell_starts_an_attack_path(tmp_path: Path) -> None:
    gemini(tmp_path, settings='{{"coreTools": ["run_shell_command"]}}')
    findings, _ = analyze(tmp_path, [])
    res = build_attack_graph(tmp_path, findings, Config())
    job = next(n for n in res.graph.nodes.values() if n.id.startswith("gha:job:"))
    assert any(w.cls.value == "code_execution" for w in job.weaknesses)
    assert any(e.src == job.id and "DEPLOY_KEY" in e.dst for e in res.graph.edges)
