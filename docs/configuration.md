# Configuration reference

breachgraph reads `.breachgraph.yml` (or `.breachgraph.yaml`) from the scanned directory, or the file passed
with `--config`. Every key is optional, and an empty file is valid. Unknown keys are rejected,
so a typo such as `priorty` fails loudly instead of being silently ignored.

Run `breachgraph init` to generate a commented starter file.

```yaml
version: 1

scanners:
  semgrep:
    enabled: true
    config: ["p/default"]        # registry rulesets or local paths: ["p/owasp-top-ten", "./rules"]
    timeout: 900                 # seconds (default: top-level `timeout`)
    extra_args: []               # passed straight to the tool
  gitleaks:
    enabled: true
    scan_history: false          # true = every commit (finds secrets that were "deleted")
  trivy:
    enabled: true
    scanners: [vuln, misconfig]  # add "license" for license compliance
    sbom: true                   # CycloneDX SBOM written to the output dir
    ignore_unfixed: false        # hide CVEs that have no fixed version yet
    offline_scan: false          # skip registry lookups (air-gapped CI); used automatically
                                 # as a fallback when Maven Central etc. rate-limit (HTTP 429)
    images: []                   # container images to scan, e.g. ["myapp:latest"]
  checkov:
    enabled: true
    frameworks: []               # default: auto-detect (terraform, kubernetes, dockerfile, ...)
  zizmor:
    enabled: true                # GitHub Actions audits; online audits run when GH_TOKEN is set
  cicd:
    enabled: true                # built-in CI/CD and supply-chain checks (no binary needed)

vex:                             # OpenVEX output (--format openvex), see docs/vex.md
  author: breachgraph            # who issues the statements (a team email or IRI is best)
  product: null                  # product purl; default: the manifest's root component
  not_affected: true             # false: never claim not_affected from import-level reachability

exclude_paths:                   # dropped entirely (gitignore-style globs)
  - node_modules/
  - "**/vendor/"

deprioritize_paths:              # still reported, but scored 2 points lower
  - tests/
  - "**/*_test.go"
  - docs/

fail_on:
  priority: P1                   # fail on P1 findings (P2 for a stricter gate); null to disable
  severity: null                 # alternatively gate on raw severity: critical|high|medium|low
  kev: true                      # any CVE in CISA's Known Exploited Vulnerabilities catalog
  secrets: true                  # any hardcoded secret
  new_only: true                 # with a baseline, only new findings can fail the gate
  scanner_errors: false          # true = a crashed scanner fails the run (exit code 3)

suppressions:                    # accepted risk. Every entry needs a reason (and an expiry)
  - rule: CKV_AWS_18             # rule id ("tool:rule" also works)
    path: infra/logs/**          # optional glob narrowing the match
    reason: "This bucket is the access-log target itself"
    expires: 2027-03-31          # after this date the finding counts again
    owner: platform-team
  - vuln: CVE-2023-12345         # a CVE/GHSA in any package
    reason: "Vulnerable function is not reachable; tracked in JIRA-123"
    expires: 2026-12-31
  - fingerprint: 3f2a9c...       # one exact finding (from the report)
    reason: "False positive: input is a constant"
    expires: 2027-01-01

require_suppression_expiry: true

severity_overrides:              # re-rate a rule for your context
  - rule: semgrep:python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
    severity: low

enrich:
  kev: true
  epss: true
  cache_hours: 24

reachability:                 # does first-party code actually import the vulnerable package?
  enabled: true
  deprioritize_unused: true   # lower the score of CVEs in packages nothing uses: not imported by
                              # first-party code, nor by a package it uses (needs a lockfile or
                              # pip-compile `# via` lines; otherwise reachability is `unknown`)
  gate_on_unused: false       # an unused-dependency CVE alone won't fail the gate

ai:                           # optional AI triage — bring your own Anthropic API key
  enabled: false              # off by default; also enable with `--ai`
  model: claude-opus-5-5      # any Anthropic model id; set a cheaper one (e.g. claude-haiku-5-5) to save
  max_findings: 10            # triage at most this many top findings (attack-path steps first)
  max_usd: 1.0                # never start a request whose worst case could push spend past this
  effort: low                 # low | medium | high | xhigh | max: reasoning depth vs cost
  prices: {}                  # override list prices, USD per 1M tokens: {model-id: [input, output]}

attack_graph:
  enabled: true
  crown_value: 7            # a node at/above this value (0-10) is a crown jewel
  crown_jewels:             # raise the value of assets that match (name or id)
    - match: "customer"
      value: 10
    - match: "*prod*"
      kind: datastore       # optional: datastore|secret|identity|...
      value: 9
  fail_on_new_path: true    # a new internet->crown-jewel path fails the gate
  min_confidence: medium    # high, medium or low; paths below this don't gate
  entry_points: [internet]  # add "credentials" (Terraform-managed access keys assumed leaked)
                            # or "cluster" (an attacker already inside the Kubernetes network)
  max_depth: 12
  max_paths: 40

timeout: 900
```

See [attack-graph.md](attack-graph.md) for how paths are built and ranked.

## How the priority is calculated

Each finding gets a 0–10 risk score, and the priority comes from that score:

| Signal | Effect |
|---|---|
| Base | CVSS for dependency CVEs. Otherwise severity: critical 9, high 7, medium 4.5, low 2, info 0.5 |
| CISA KEV | +3, and the finding is **always P1** |
| EPSS ≥ 10% | + up to 2.5 (5 × EPSS) |
| EPSS < 1% | −0.5 |
| Low confidence | −1.5 |
| Reported by ≥ 2 tools | +0.5 |
| High-confidence credential | +1 |
| Test/docs path | −2 |
| Dependency reachable from an HTTP entry point | +1 |
| Dependency not imported by first-party code (likely unreachable) | −3 |

P1 ≥ 9, P2 ≥ 7, P3 ≥ 4, P4 < 4. The reasons behind each score are listed in every report.

## Baselines

A baseline lets you adopt breachgraph on an existing codebase without fixing everything first:

```bash
breachgraph scan --write-baseline .breachgraph-baseline.json   # accept today's findings
git add .breachgraph-baseline.json
```

When `.breachgraph-baseline.json` exists in the scanned directory it is applied automatically.
Findings in it are marked `baseline`, and with `fail_on.new_only: true` only **new** findings
can fail the build. Fingerprints are based on code content rather than line numbers, so editing
other parts of a file does not turn old findings into new ones.

## Inline suppressions

Use each tool's native mechanism when a suppression belongs next to the code:

| Tool | Syntax |
|---|---|
| Semgrep | `# nosemgrep: rule-id` |
| Gitleaks | `# gitleaks:allow` |
| Checkov | `# checkov:skip=CKV_AWS_20: reason` |
| Trivy | `#trivy:ignore:AVD-AWS-0086` or `.trivyignore` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Gate passed (or `--no-fail`) |
| 1 | Gate failed |
| 2 | Usage or configuration error |
| 3 | A scanner failed and `fail_on.scanner_errors` is true |
