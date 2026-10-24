# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Attack-path analysis**: a code-to-cloud graph (Kubernetes, Terraform/AWS, HTTP routes in
  Python/JS/TS/Java/Go) that finds chains from the internet to crown-jewel assets. Every
  control step requires a real weakness, so network exposure alone never reaches credentials.
- Real AWS IAM evaluation (scoping, managed policies, explicit-Deny-wins, privilege escalation),
  EKS IRSA and node roles, Kubernetes RBAC and container-escape detection, exposure analysis.
- Choke-point analysis: the cheapest fixes that break the most paths.
- Attack paths render in the HTML report (flow diagram), the PR comment and the console; the gate
  can fail on new attack paths (`attack_graph.fail_on_new_path`).
- `breachgraph graph` command to build the graph standalone.
- `examples/vulnerable-platform` demo with a real internet-to-S3 path.
- **AI-assisted triage (bring your own key)**: optional, off by default. With your own
  `ANTHROPIC_API_KEY`, breachgraph explains findings and attack paths, gives each finding a
  true/false-positive verdict with reasoning and a fix, and writes a plain-English attack-path
  narrative. Advisory only (never changes the gate), defensive only (no exploit generation),
  grounded in the code and graph evidence, with a spend cap and graceful handling of a missing
  key or a safety refusal. Enable with `--ai`; see docs/ai-triage.md.
- **Reachability analysis**: for each dependency CVE, checks whether first-party code actually
  imports the package (Python/JS/TS/Java/Go via tree-sitter) and whether the importing module is
  reachable from an HTTP entry point. Unused (transitive-only) CVEs are deprioritized and don't
  gate by default; reachable ones are flagged. Also decides which dependency CVEs can be weapons
  in the attack graph.

## [0.1.0] - 2026-10-23

### Added

- `breachgraph scan` orchestrating Semgrep (SAST), Gitleaks (secrets), Trivy (SCA, IaC, images,
  licenses, CycloneDX SBOM), Checkov (IaC) and OWASP ZAP (DAST) in parallel.
- `--import` for existing reports from any supported tool or any SARIF 2.1.0 producer.
- Normalized finding model with CWE and OWASP Top 10 (2021) mapping and content-based fingerprints.
- Two-stage deduplication (same-tool rule overlap and cross-tool clustering, at most one finding
  per tool in each cluster).
- CISA KEV and FIRST EPSS enrichment with on-disk caching and offline fallback.
- Risk score (0–10) and P1–P4 priority with an explanation for every score.
- Policy as code (`.breachgraph.yml`): thresholds, path excludes and deprioritization, suppressions
  with mandatory reason and expiry, severity overrides.
- Baselines (`--write-baseline`) so only new findings fail the gate.
- Reports: SARIF (GitHub code scanning), JSON, HTML, Markdown, JUnit.
- GitHub integration: sticky PR comment, job summary, automatic issues for P1 findings.
- Composite GitHub Action, GitLab CI template, Docker image with pinned and checksum-verified scanners.
- `breachgraph report`, `breachgraph doctor`, `breachgraph init`.
