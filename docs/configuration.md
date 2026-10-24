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
  zap:
    enabled: false               # DAST is opt-in: it needs a running application
    target_url: null             # or pass --dast-url
    mode: baseline               # baseline | full | api
    api_definition: null         # OpenAPI URL for mode=api
    docker_image: ghcr.io/zaproxy/zaproxy:stable

exclude_paths:                   # dropped entirely (gitignore-style globs)
  - node_modules/
  - "**/vendor/"

deprioritize_paths:              # still reported, but scored 2 points lower
  - tests/
  - "**/*_test.go"
  - docs/

fail_on:
  priority: P2                   # fail on findings at P2 or more urgent; null to disable
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

timeout: 900
```

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
