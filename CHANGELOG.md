# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- IAM users, groups and their policies in the attack graph, and AssumeRole chains: a principal
  reaches a role when its policy allows `sts:AssumeRole` and the role's trust admits it.
- Committed login credentials as a way in: Azure VMs with a literal admin password and password
  login enabled, and EC2 instances whose key pair's private key is in the repository.
- `attack_graph.entry_points`: opt in to `credentials` (Terraform-managed access keys assumed
  leaked) and `cluster` (an attacker already inside the Kubernetes network).
- A coverage line in every report: how many routes, workloads, cloud resources, Kubernetes
  objects, CI jobs and crown jewels the attack graph modeled, and why a result is incomplete (a
  scanner that feeds weaknesses did not run, files that could not be parsed, no deployment
  configuration, no crown jewel). "No attack paths" is no longer silent about thin inputs.

### Changed

- Reports and PR comments use plain text instead of emoji icons.

### Fixed

- A privileged pod reachable from the internet reached its node with no code vulnerability: the
  escape edge now needs code execution in the pod as well as the disabled isolation.
- The benchmark harness wrote each report inside the scanned tree, so a rerun scanned its own
  previous report.
- The default gate fails on P1 findings instead of P2, alongside attack paths, known exploited CVEs
  and secrets. On the benchmark projects P2 blocked 1,497 findings, 131 of them on a healthy
  production-style repository. Set `fail_on.priority: P2` for the stricter gate.

## [0.2.0] - 2026-10-27

### Added

- **Public benchmark** (`benchmarks/`, docs/benchmark.md): breachgraph on TerraGoat, CloudGoat,
  Kubernetes Goat, AWS/Azure/GCP Goat, OWASP Juice Shop and Google's Online Boutique, each pinned
  to a commit. Every reported attack path is hand-labeled and every documented scenario it misses
  is listed; a test keeps the page in sync with the results and labels, and a manual workflow
  re-runs it.
- **Interactive attack-graph explorer** in the HTML report: the graph the paths run through,
  click any node for its evidence, weaknesses and what each step needs, and tick "assume fixed"
  on a finding to watch the paths it breaks disappear. Works offline, keyboard accessible, light
  and dark; the paths stay available as text. The JSON report carries the same graph
  (`attack_graph.graph`).
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

Found by running breachgraph on vulnerable-by-design projects (see benchmarks/):

- Terraform files with a heredoc terminator followed by a space (`EOF `) silently lost every
  block after it (python-hcl2). Trailing whitespace is now ignored, a file that fails to parse is
  parsed block by block, and any block that still can't be read is reported as a blind spot.
- Serverless code now maps to the function that deploys it (`data "archive_file"`, `filename`,
  S3/Blob/GCS objects), so a code vulnerability in a Lambda, Azure Function or Cloud Function
  reaches that function's identity.
- Azure: `azurerm_function_app` / `azurerm_app_service` (azurerm 3.x), Automation accounts,
  `identity.0.principal_id` references, resource groups named by a variable, and privilege
  escalation by running code on a VM, app or runbook in scope (Contributor -> Owner identity).
- Kubernetes worker nodes are crown jewels, so container-escape paths have a target.
- GCP: Cloud Run / Cloud Functions without a service account run as the default one (Editor by
  default; low confidence), and SSRF in serverless code reaches the metadata server; Semgrep's
  SSRF rules are recognized even when their CWE isn't CWE-918.
- API Gateway REST APIs (v1) now expose the Lambda functions they integrate (high confidence when
  the method has `authorization = "NONE"`), and SQL/NoSQL injection reaches every queryable store
  the service's identity can read (RDS, DynamoDB, Azure SQL/Cosmos DB, Cloud SQL, BigQuery), also
  from serverless handlers that have no framework routes.
- IAM policies read from files (`file("policies/x.json")`), and `jsonencode` policies with
  function calls or reference lists, are now evaluated instead of reported as blind spots.
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

[Unreleased]: https://github.com/amoghnellutla/breachgraph/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/amoghnellutla/breachgraph/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/amoghnellutla/breachgraph/releases/tag/v0.1.0
