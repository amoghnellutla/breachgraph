# What leaves your machine

breachgraph has no telemetry and no server. It never sends your source code anywhere unless you
turn on AI triage. These are all the connections a scan makes.

| Destination | What is sent | When | Turn it off |
|---|---|---|---|
| `cisa.gov` | Nothing: downloads the KEV list | Each scan, cached | `--offline` or `enrich.kev: false` |
| `api.first.org` | CVE ids from your dependency findings | Each scan, cached | `--offline` or `enrich.epss: false` |
| `api.osv.dev` | Names and versions of vulnerable Go modules | Go projects with CVEs, cached a week | `--offline` |
| `ghcr.io` and mirrors | Nothing: Trivy downloads its vulnerability database | When its cache is stale | Mirror it with `TRIVY_DB_REPOSITORY`, or disable Trivy |
| Package registries | Trivy may look up package metadata | Dependency scans | `scanners.trivy.offline_scan: true` |
| `api.github.com` | zizmor checks the actions your workflows use, if a token is set | Each scan with a token | Unset the token, or add `--offline` to zizmor's `extra_args` |

Semgrep runs breachgraph's own rules, which ship in the package, so a default scan doesn't contact
semgrep.dev. Its metrics are off. Checkov runs with `--skip-download`, so it doesn't contact its
vendor either.

## Only if you turn it on

| Feature | Destination | What is sent |
|---|---|---|
| `p/default` in `scanners.semgrep.config` | `semgrep.dev` | Downloads rules. If it can't be reached, the scan continues with breachgraph's rules and says so. |
| `--ai` | `api.anthropic.com`, with your key | The code around each top finding, with token-like values redacted. Secrets are never read from disk. See [ai-triage.md](ai-triage.md). |
| `--github-comment`, `--github-issues`, `--pr` | Your GitHub | Finding titles, locations and paths. |
| `--gitlab-comment` | Your GitLab | The same. |
| `slack-webhook`, `teams-webhook` | Your webhook | A summary of new attack paths. |

## Behind a firewall

Allow `ghcr.io` and its Trivy database mirrors, or set `TRIVY_DB_REPOSITORY` to an internal mirror.
Everything else is optional: `--offline` skips KEV, EPSS and OSV, and those findings are still
reported, without that risk signal. If a scanner can't run, the report says **incomplete** and the
exit code is 3, so a blocked network never looks like a clean result.
