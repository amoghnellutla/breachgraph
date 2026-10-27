# AI-assisted triage (bring your own key)

Scanners are noisy. For your top findings, breachgraph can ask Claude the question a reviewer asks
first: **is this real in this code, and what exactly do I change?** Each triaged finding gets a
verdict (**real**, **likely false positive** or **needs review**), the reasoning with line numbers,
and a concrete fix with corrected code where a code change applies.

It is **optional and advisory**: it never changes the gate.

**You bring your own Anthropic API key. breachgraph never spends tokens on your behalf.** The
feature is off unless you turn it on *and* a key is present.

## Setup

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

If the key or package is missing, breachgraph says what to do and runs the scan without AI.

## What the model sees

A verdict is only as good as its evidence, and three lines around a regex match are not enough.
For each finding, breachgraph sends what a reviewer would open:

| Finding | Evidence sent |
|---|---|
| Code (SAST) | The **whole enclosing function** (tree-sitter, Python/JS/TS/Java/Go), with flagged lines marked, and the **HTTP route** that runs it (e.g. `GET /fetch`, Flask handler `fetch`) |
| Dependency CVE | Package, installed and fixed versions, advisory ids, reachability, and the **first-party lines that use the package**, so the model can tell whether the vulnerable API is the one your code calls |
| IaC / config | The reported block, e.g. the whole Terraform resource or Kubernetes object. For Terraform, also **the module's other resources that reference it** (is there a separate public access block or encryption config?) and **the resources it references** (e.g. the role a policy attaches to, with its trust policy). Small files reported without a line (a Dockerfile rule) are sent whole |
| Every finding | Whether it is a step on an **internet-to-crown-jewel attack path** (and how many paths fixing it breaks). A misconfiguration that is not a step itself, such as `hostNetwork: true` on the exposed pod or an over-broad policy on the role a path uses, gets the paths that run through its resource. Plus the risk factors breachgraph scored |

Example: a `requests` advisory that affects only callers of `extract_zipped_paths()`, in a service
whose only call is `requests.get(url)`, comes back as *likely false positive* with that reason.
An SSRF in a route handler that is a step on a path to the customer-data bucket comes back as
*real*, with an allowlist fix for that handler.

Findings are chosen in this order: steps on attack paths, then gating findings, then new (not
baselined) findings, then highest risk, up to `ai.max_findings`. One finding per location (file and
line, or package) goes first, so five rules firing on the same Terraform block don't use five slots.
Suppressed findings are skipped. Requests run four at a time.

## Where results appear

- **PR comment / job summary:** the verdict and a one-line reason next to each finding, plus a
  collapsed *AI triage: verdicts and fixes* section with the reasoning and the fix.
- **HTML report:** a verdict pill in the findings table; reasoning, fix and corrected code in each
  finding's details.
- **JSON report:** `findings[].ai` (`verdict`, `confidence`, `summary`, `reasoning`, `remediation`,
  `fix_code`, `model`) and run totals in `metadata.ai`.
- **Console:** the verdict in the findings table and the run's cost.

## Controlling cost

| Lever | Flag / config | Default |
|---|---|---|
| Model | `--ai-model claude-haiku-5-5` / `ai.model` | `claude-opus-5-5` |
| Spend cap | `--ai-budget 0.50` / `ai.max_usd` | `1.0` USD |
| Findings per run | `ai.max_findings` | `10` |
| Reasoning depth | `ai.effort`: `low` · `medium` · `high` · `xhigh` · `max` | `low` |

The cap is enforced **before** each request: breachgraph reserves the request's worst case (its
input plus the maximum answer length) and skips the finding if that could exceed `max_usd`, then
records the real cost from the API's token counts. Findings skipped for budget are listed in the
warnings. Costs use Anthropic's list prices. For a model breachgraph has no price for, it uses the
highest Claude price and labels the cost an upper bound. Prices change, so they can be set in
config: `ai.prices: {claude-opus-5-5: [4, 20]}` (USD per million input and output tokens) overrides
or adds a model's price. At the defaults, a finding typically costs
a few cents on Opus and a fraction of a cent on Haiku.

## Failure handling

AI never fails a scan. Each case becomes a warning:

- **No key / package:** the scan runs without AI.
- **Invalid key, unknown model, rejected request:** triage stops after the first error rather than
  repeating it for every finding.
- **Transient API errors:** retried by the SDK; a finding that still fails is skipped, the rest continue.
- **Safety refusal:** security code can trip the model's safety filter. On models that support it
  (Opus 5.5, Opus 5, Fable 5.1, Sonnet 5.5) breachgraph enables server-side fallback, so the API
  retries on a suitable model within the same call; otherwise the finding is left without a verdict.
- **Cut-off or malformed answer:** discarded, never shown half-parsed.

## Safety and trust

- **Advisory.** The gate is always the deterministic policy. AI output never changes it.
- **Defensive only.** The model is instructed to explain and fix, never to write exploit code,
  payloads or attack instructions.
- **Secrets stay local.** Secret findings are never read from disk; only a scanner-redacted match is
  sent. In all code sent, known token formats and random-looking string literals are replaced with
  `<redacted>`, and for hardcoded-credential findings every string literal on the flagged line is.
- **Prompt injection.** Repository content is untrusted. It is wrapped in a tag it cannot close, the
  model is told to analyze it and never follow it, and the answer must match a strict JSON schema.
  In the PR comment, AI prose is escaped so it cannot add links, images, HTML or mentions, and fix
  code goes in a code block it cannot break out of.
- **Your data.** Code snippets are sent to Anthropic's API under your own key and account. Review
  Anthropic's data-use terms, and leave the feature off for repositories where that is not acceptable.
