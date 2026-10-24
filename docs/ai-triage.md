# AI-assisted triage (bring your own key)

breachgraph can use an LLM to explain findings and attack paths in plain language, give each
finding a **true-positive / likely-false-positive / needs-review** verdict with reasoning, and
suggest a concrete fix. It is **optional and advisory** — it never changes the gate.

**You bring your own Anthropic API key. breachgraph never spends tokens on your behalf.** The
feature is off unless you turn it on *and* a key is present.

## Setup (one minute)

1. Get an API key at <https://console.anthropic.com/>.
2. Set it:
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...       # Windows: setx ANTHROPIC_API_KEY sk-ant-...
   ```
3. Install the optional dependency (already in the Docker image):
   ```bash
   pip install 'breachgraph[ai]'
   ```
4. Run with `--ai`:
   ```bash
   breachgraph scan . --ai
   ```

If the key or package is missing, breachgraph prints exactly what to do and runs the scan normally
without AI — it never fails because of AI.

## What you get

- **Attack-path narrative** — a short briefing on what an attacker could reach, why it matters, and
  the one or two highest-leverage fixes. Shown in the console, the PR comment and the HTML report.
- **Per-finding triage** — a verdict, reasoning grounded in the actual code snippet, and a fix,
  on the top findings (gating first, then highest risk). Shown in the report and the PR comment.

## Controlling cost

| Lever | Flag / config | Default |
|---|---|---|
| Cheaper model | `--ai-model claude-haiku-5-5` / `ai.model` | `claude-opus-5-5` |
| Spend cap | `--ai-budget 0.50` / `ai.max_usd` | `1.0` USD |
| Fewer findings | `ai.max_findings` | `10` |
| Less reasoning | `ai.effort: low` | `low` |

breachgraph tracks real token usage from the API and reports the estimated cost after the run
(`AI triage: N finding(s), ~$0.0x`). A whole scan with the defaults is typically a few cents on
Haiku, more on Opus.

## How it stays safe and trustworthy

- **Defensive only.** The model is instructed to explain and remediate — never to produce exploit
  code, payloads, or attack instructions.
- **Advisory.** AI output is shown alongside findings but **does not change the gate**. The pass/fail
  decision is always the deterministic policy.
- **Grounded.** Verdicts are based on the real code snippet, the scanner metadata, and the attack
  graph — not guesswork.
- **Untrusted input.** Repository content could contain prompt-injection text. breachgraph delimits
  the evidence, tells the model it is data to analyze (not instructions to follow), and validates
  the model's output against a strict schema.
- **Refusals handled.** If the model declines (safety classifier), breachgraph records a warning and
  the scan continues.
- **Your data.** Snippets of your code and config are sent to Anthropic's API under your own key and
  account. Review Anthropic's data-use terms; disable the feature if that is not acceptable for a repo.
