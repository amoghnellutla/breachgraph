<div align="center">

# 🛡️ breachgraph

**Find the attack paths that matter — from code to cloud.**

breachgraph runs the open-source scanners you already trust (Semgrep, Gitleaks, Trivy, Checkov,
ZAP), then does what they can't: it builds one **code-to-cloud graph** and finds the real
**attack paths** — the chains where an internet-facing route, a vulnerability, a container and an
over-broad IAM role line up so an outsider can reach your crown-jewel data. It ranks findings by
whether they actually lie on such a path, so you fix the ten things that can hurt you, not the
three hundred that can't.

[![ci](https://github.com/OWNER/breachgraph/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/breachgraph/actions/workflows/ci.yml)
[![self-scan](https://github.com/OWNER/breachgraph/actions/workflows/self-scan.yml/badge.svg)](https://github.com/OWNER/breachgraph/actions/workflows/self-scan.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

</div>

---

## Why this is different

Most tools hand you a list. A big security team already has Snyk, CodeQL and a cloud scanner —
what they lack is the *connection between layers*. A medium-severity SSRF is boring on its own.
SSRF on an internet-facing route, in a pod with host networking, whose node role can read the
customer-data bucket, is a breach. No single scanner sees that chain, because each one looks at
only one layer.

breachgraph joins the layers — **code → container → Kubernetes → cloud IAM → data** — into one
graph and asks the question that matters: *what can an attacker actually reach, and how?*

**It is not a gimmick:** every step that represents gaining control requires a real weakness.
Being reachable on the network is not the same as being owned. With zero code vulnerabilities,
breachgraph reports **no path** to your data even if the pod is public and its role is over-broad
— you can [see that guarantee as a test](tests/test_graph_paths.py). Fix the one cheapest link
(the "choke point") and the whole path disappears.

<p align="center"><img src="docs/img/attack-paths.png" alt="breachgraph attack paths" width="860"></p>

## What you get

| | |
|---|---|
| 🎯 **Attack-path analysis** | Joins code, containers, Kubernetes and Terraform/AWS into one graph and finds every chain from the internet to a crown-jewel asset. Each independent entry point surfaces separately; each path names the cheapest fix |
| ☁️ **Real cloud reasoning** | Evaluates IAM policies (scoping, managed policies, explicit-Deny-wins, **privilege-escalation** primitives), EKS **IRSA** and node roles, public exposure (LBs, security groups, public buckets/DBs, unauth Lambda URLs), Kubernetes RBAC and container escape |
| 🔍 **Coverage** | SAST (Semgrep) · secrets (Gitleaks) · dependency CVEs, IaC, container images, licenses (Trivy) · IaC (Checkov) · DAST (ZAP) · plus **any SARIF** tool (CodeQL, Bandit, gosec…) via `--import` |
| 🧹 **Deduplication** | Cross-tool clustering (e.g. Trivy `AVD-DS-0002` ≡ Checkov `CKV_DOCKER_3`) and same-tool rule overlap — at most one finding per tool in each cluster |
| 📊 **Risk-based priority** | CVSS/severity adjusted by **CISA KEV** (actively exploited → always P1), **FIRST EPSS**, confidence, multi-tool agreement and reachability to crown jewels. Every score explains itself |
| 🚦 **Gate that teams keep on** | Content-based fingerprints + **baselines**, so only *new* findings and *new* attack paths fail the build. **Suppressions require a reason and an expiry date** |
| 💬 **Feedback where developers are** | Sticky PR comment with the attack-path diagram · inline code-scanning annotations (SARIF) · job summary · auto-managed GitHub issues |
| 📦 **Reports** | SARIF 2.1.0 · JSON · self-contained HTML (interactive attack-path flows) · Markdown · JUnit · CycloneDX SBOM |
| 🔒 **Trustworthy itself** | Scanner binaries pinned and SHA-256 verified · actions pinned to commit SHAs · signed images with SBOM + provenance · secrets always redacted · untrusted scanner output escaped |

<p align="center"><img src="docs/img/html-report.png" alt="breachgraph findings report" width="820"></p>

## Quick start

### GitHub Actions

```yaml
# .github/workflows/breachgraph.yml
name: breachgraph
on: [pull_request, push]
permissions:
  contents: read
  security-events: write   # code scanning upload
  pull-requests: write     # PR comment
jobs:
  breachgraph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: OWNER/breachgraph@v0
```

More recipes (baselines, DAST, container images, issue tracking) are in [docs/github-action.md](docs/github-action.md).

### Docker (any CI, or your laptop)

```bash
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/breachgraph scan .
open breachgraph-report/breachgraph.html
```

### pip

```bash
pip install breachgraph
breachgraph doctor          # shows which scanners are on PATH
breachgraph scan .
```

The pip package only orchestrates. It runs whichever scanners are installed and skips the rest.
The Docker image bundles all of them at pinned versions.

### GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/OWNER/breachgraph/v0/templates/gitlab-ci.yml
```

## Try it on the demo app

[`examples/vulnerable-app`](examples/vulnerable-app) is an intentionally vulnerable Flask app
with Terraform, Kubernetes and Dockerfile misconfigurations, fake secrets and Log4Shell:

```bash
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/breachgraph scan examples/vulnerable-app
```

```
      ok gitleaks     2 findings     0.7s
      ok checkov     50 findings     8.2s
      ok semgrep     26 findings     9.2s
      ok trivy      149 findings    25.5s
| Prio | Risk | Finding                                                      | Location     | Tools            | Status     |
| P1   | 10.0 | CVE-2021-44228 in log4j-core 2.14.1: Remote code exec  KEV   | pom.xml:11   | trivy            | BLOCKS new |
| P1   | 10.0 | Hardcoded secret: Identified a Private Key                   | settings.py:6| gitleaks,semgrep | BLOCKS new |
...
Gate failed: 104 finding(s) at or above the threshold (priority >= P2, any KEV, any secret)
```

## Adopting it on an existing codebase

```bash
# 1. Accept what exists today
breachgraph scan --write-baseline .breachgraph-baseline.json && git add .breachgraph-baseline.json

# 2. Turn the gate on. From now on only NEW findings fail PRs.
# 3. Burn down the baseline over time; accepted risks go into .breachgraph.yml with an expiry:
```

```yaml
# .breachgraph.yml
fail_on:
  priority: P2        # new P1/P2 findings fail the build
  kev: true           # so does anything actively exploited
  secrets: true       # and any hardcoded secret
suppressions:
  - vuln: CVE-2023-12345
    reason: "Vulnerable code path not reachable; tracked in SEC-142"
    expires: 2026-12-31
```

Full reference: [docs/configuration.md](docs/configuration.md).

## Attack paths

[`examples/vulnerable-platform`](examples/vulnerable-platform) is a small microservice (Flask API
on EKS with IRSA, plus Terraform) with a real internet-to-S3 path. breachgraph reports:

```
🎯 2 attack path(s) to crown-jewel assets
  1. [high] risk 14.0 BLOCKS
     Internet → Ingress api → Deployment shop/api → GET /thumbnail
       → ServiceAccount shop/api (code_execution) → IAM role api-pod-role
       → S3 bucket shop-customer-data-prod
  2. [high] risk 12.73 BLOCKS
     Internet → Ingress api → Deployment shop/api → GET /fetch
       → IAM role eks-node-role (ssrf → node metadata) → S3 bucket shop-customer-data-prod
  Fix first:
    • Command injection via os.popen (services/api/app.py:30) — breaks 1 path(s)
    • SSRF via requests.get (services/api/app.py:23) — breaks 1 path(s)
```

Two independent ways in (command injection gives the pod role; SSRF steals the node role via the
metadata endpoint) surface separately, because fixing one does not fix the other. Run it yourself:

```bash
breachgraph scan examples/vulnerable-platform     # scanners + attack graph
breachgraph graph examples/vulnerable-platform    # attack graph only
```

How reachability and IAM are modeled: [docs/attack-graph.md](docs/attack-graph.md).

## How it works

```mermaid
flowchart LR
    A[Semgrep · Gitleaks · Trivy · Checkov · ZAP · SARIF] --> B[Normalize<br/>CWE · OWASP · fingerprint]
    B --> C[Dedupe] --> D[Enrich<br/>KEV · EPSS] --> E[Score P1–P4]
    E --> G2[Attack graph<br/>code→cloud paths]
    CFG[Kubernetes · Terraform · routes] --> G2
    G2 --> F[Baseline ·<br/>suppressions]
    F --> GATE{Gate}
    GATE --> H[SARIF · PR comment · HTML · issues]
```

Design notes and how to add a scanner: [docs/architecture.md](docs/architecture.md).

## CLI

```
breachgraph scan [PATH]      Scan and gate
  -c, --config FILE        .breachgraph.yml (auto-detected)
  -b, --baseline FILE      accepted findings (auto-detected .breachgraph-baseline.json)
  --write-baseline FILE    accept all current findings
  -f, --format LIST        json,sarif,html,md,junit
  --only / --skip LIST     choose scanners
  --import TOOL=FILE       ingest existing reports (semgrep, gitleaks, trivy, checkov, zap, sarif)
  --fail-on P1..P4|none    override the threshold
  --dast-url URL           run ZAP against a running app
  --image REF              scan a container image
  --github-comment         sticky PR comment
  --github-issues P1       open/close issues per finding
  --offline                skip KEV/EPSS
  --no-fail                report only
breachgraph graph [PATH]          build the attack graph only (--findings a prior scan)
breachgraph report results.json   re-render reports, optionally with a new policy
breachgraph doctor                show installed scanners
breachgraph init                  write a starter .breachgraph.yml and workflow
```

Exit codes: `0` pass · `1` gate failed · `2` usage/config error · `3` scanner error (opt-in).

## Roadmap

- [ ] **Reachability** for dependency CVEs: call-graph analysis to confirm the vulnerable function is actually reachable from an entry point (Python/JS first)
- [ ] **Bring-your-own-key AI triage**: an optional layer where *you* attach your own Anthropic API key, and an agent explains each attack path and proposes a fix, grounded in the graph evidence. No key is required to use breachgraph, and the project never spends tokens on your behalf
- [ ] Azure and GCP in the attack graph (AWS and Kubernetes ship today)
- [ ] CI/CD pipeline hardening (GitHub Actions injection, unpinned actions) and malicious-package detection
- [ ] OSV-Scanner and Grype adapters; GitLab merge-request notes; trend history across runs

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in
breachgraph itself, see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). The bundled scanners keep their own licenses: Semgrep CE (LGPL-2.1),
Gitleaks (MIT), Trivy (Apache-2.0), Checkov (Apache-2.0), ZAP (Apache-2.0).
