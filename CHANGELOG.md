# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-23

### Added

- `triagegate scan` orchestrating Semgrep (SAST), Gitleaks (secrets), Trivy (SCA, IaC, images,
  licenses, CycloneDX SBOM), Checkov (IaC) and OWASP ZAP (DAST) in parallel.
- `--import` for existing reports from any supported tool or any SARIF 2.1.0 producer.
- Normalized finding model with CWE and OWASP Top 10 (2021) mapping and content-based fingerprints.
- Two-stage deduplication (same-tool rule overlap and cross-tool clustering, at most one finding
  per tool in each cluster).
- CISA KEV and FIRST EPSS enrichment with on-disk caching and offline fallback.
- Risk score (0–10) and P1–P4 priority with an explanation for every score.
- Policy as code (`.triagegate.yml`): thresholds, path excludes and deprioritization, suppressions
  with mandatory reason and expiry, severity overrides.
- Baselines (`--write-baseline`) so only new findings fail the gate.
- Reports: SARIF (GitHub code scanning), JSON, HTML, Markdown, JUnit.
- GitHub integration: sticky PR comment, job summary, automatic issues for P1 findings.
- Composite GitHub Action, GitLab CI template, Docker image with pinned and checksum-verified scanners.
- `triagegate report`, `triagegate doctor`, `triagegate init`.
