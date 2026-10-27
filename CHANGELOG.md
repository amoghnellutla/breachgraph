# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **OpenVEX output** (`--format openvex`, on by default in the GitHub Action): `not_affected` /
  `affected` / `under_investigation` statements built from reachability, scoped so Trivy and
  Grype can apply them (`trivy fs --vex breachgraph.vex.json`). See docs/vex.md.
- Dependency graphs from Trivy (lockfiles, pom.xml, go.mod) and pip-compile / uv `# via`
  annotations; packages carry their purl and the packages that depend on them.
- **"This change opens / closes an attack path"** as the headline of every PR comment, with each
  new path drawn as a Mermaid diagram. `--compare base/breachgraph.json` treats the base branch's
  findings and paths as pre-existing, so only what a change adds can fail it. The GitHub Action
  does this automatically through the Actions cache (`compare: true`). Attack paths now carry a
  stable `id`, and baselines record accepted paths.

### Fixed

- Reachability no longer calls a package "unused" when another dependency that the code imports
  needs it (Jinja2 under Flask). Without a dependency graph, a package the code doesn't import is
  now `unknown`, not `unused`, so it is no longer deprioritized on a guess.

## [0.1.0] - 2026-10-27

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

- **CI/CD and supply chain.** Built-in checks for the attacks that actually hit CI: script
  injection of outsider-controlled text (`issue.title`, `comment.body`, branch names) into `run:`
  and `github-script`; pwn requests (`pull_request_target`/`workflow_run` jobs that check out and
  run pull request code, critical when the job holds secrets or a write token); and dependency
  confusion via pip `--extra-index-url` / uv `unsafe-best-match`. Maintainer-only `if:` gates lower
  severity. zizmor runs too (bundled in the image) for broader Actions hygiene; its findings merge
  with the built-in ones.
- **CI jobs in the attack graph.** Jobs that outsiders can start are entry points; their OIDC
  cloud identities (checked against AWS trust `sub` conditions and Azure federated subjects),
  secrets and write-capable `GITHUB_TOKEN` are linked behind code execution. A role that trusts
  GitHub OIDC without naming a repository is flagged as reachable from the internet. The demo now
  includes an `issue_comment` injection that reaches the customer-data bucket through a deploy
  role scoped "safely" to `main`.

- **Azure and GCP in the attack graph** (Terraform). Azure: role assignments evaluated as
  Actions/NotActions/DataActions over their scope, custom roles, Key Vault RBAC and access
  policies, privilege escalation via `roleAssignments/write`, managed identities on VMs, App
  Service, Functions, Container Apps and AKS, NSG/public-IP exposure, public blob containers and
  database firewalls, AKS workload identity. GCP: IAM members/bindings/policies from organization
  to resource level, predefined and custom roles, service-account impersonation chains,
  `setIamPolicy` escalation, GCE/Cloud Run/Cloud Functions/GKE identities, firewall exposure,
  public invokers, buckets, datasets and Cloud SQL, GKE Workload Identity. SSRF to the Azure or
  GCP metadata endpoint is low confidence, because it needs a request header.

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
  `ANTHROPIC_API_KEY`, each top finding gets a real / likely-false-positive / needs-review verdict,
  reasoning with line numbers, and a concrete fix with corrected code. The model sees what a
  reviewer would open: the whole enclosing function and the HTTP route that runs it, the attack
  path the finding is a step on, and for dependency CVEs the lines that call the package. Advisory
  only (never changes the gate), defensive only, secrets redacted before sending, a spend cap
  enforced before each request, and every failure (no key, refusal, API error) is a warning, never
  a failed scan. Enable with `--ai`; see docs/ai-triage.md.
- **Reachability analysis**: for each dependency CVE, checks whether first-party code actually
  imports the package (Python/JS/TS/Java/Go via tree-sitter) and whether the importing module is
  reachable from an HTTP entry point. Unused (transitive-only) CVEs are deprioritized and don't
  gate by default; reachable ones are flagged. Also decides which dependency CVEs can be weapons
  in the attack graph.

[Unreleased]: https://github.com/amoghnellutla/breachgraph/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/amoghnellutla/breachgraph/releases/tag/v0.1.0
