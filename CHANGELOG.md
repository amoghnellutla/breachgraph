# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The image keeps Trivy's databases under its one cache directory
  (`/tmp/breachgraph-cache/trivy`), so a single mount keeps everything between local runs. The
  README's Docker command now mounts it: a repeat scan of the demo's dependencies takes 7 seconds
  instead of 23.
- In an incremental scan, a scanner that didn't need to run is shown as `reused` (with the number
  of findings it carried over) in the PR comment, console and HTML report, and no longer adds a
  warning.
- When scanners aren't installed, the scan says so once and gives the Docker command that has them.

## [0.5.0] - 2026-10-27

### Added

- Incremental pull-request scans (`--incremental` with `--compare`, on by default in the action
  and the GitLab template). Every report records a digest of each scanned file; a pull request
  rescans only what changed (Semgrep on changed files, Checkov on changed infrastructure files,
  Trivy, Gitleaks and zizmor only when a file they read changed) and reuses the default branch's
  findings for the rest. The attack graph is always rebuilt in full. Any doubt (no digests, a
  different version or different scanner settings) means a full scan.
  On a one-line change: 8 to 10 seconds, with the same findings and paths as a full rescan
  (docs/github-action.md).
- Several repositories scanned as one: `breachgraph scan app/ infra/`, and `path: ". infra"` in
  the action. Attack paths that cross an application repository and an infrastructure repository
  are found.
- GitLab merge-request notes (`--gitlab-comment`): one note per merge request, updated on every
  pipeline, with the attack-path diagram. The GitLab template compares each merge request with the
  default branch's last report and scans incrementally. Needs `BREACHGRAPH_GITLAB_TOKEN`.
- docs/ci-survey.md: the CI/CD checks run on 2,471 workflows from popular projects, with what
  that changed in breachgraph.
- Issue templates for wrong findings, bugs, and "I ran it on my repository".
- docs/comparison.md: breachgraph against running the scanners yourself and against commercial
  platforms, including when to pick something else.

### Fixed

- `breachgraph graph` with no `--findings` said "No attack path" in green. It now prints the
  coverage line, says the result is infrastructure only, and gives the `breachgraph scan` command;
  a scan with incomplete coverage says "No attack path found, but the result is incomplete".
- `breachgraph fix` with no report runs the scan itself instead of stopping with an error.
- Checkov renders Helm charts into a random temporary directory and reported findings there
  (`tmpab12cd/chart/...`), so every scan of a repository with Helm charts made them look new.
  They now point at the template in the repository and keep their identity across runs.
- A scan walked the repository once per source (about eight times). It now lists it once.
- CI/CD false positives found by running the checks on the 100 most-starred repositories (1,354
  workflows; 3 of the 4 findings were not exploitable): a job whose `if:` requires code from this
  repository (`head.repo.full_name == github.repository`, `head.repo.fork == false`, or the
  `workflow_run` equivalent, as a required term) is no longer reported, and a `workflow_run`
  checkout is reported only when a workflow it follows can be started by an outsider.
- More precision from a second survey (70 popular repositories that use `pull_request_target`,
  1,117 workflows; no finding was an open hole, several were overrated): a job that `needs` a
  permission-check job, or runs in an `environment` (which may require reviewers), is reported as
  gated at medium; a pull request checked out into a side directory and only read as data is not
  reported; a job with no secrets and a read-only token is medium, not high.

## [0.4.0] - 2026-10-27

### Added

- `breachgraph fix`: fixes for the choke points, most paths broken first. It upgrades a vulnerable
  dependency declared in requirements*.txt, package.json or go.mod to its fixed version, and moves
  untrusted `${{ }}` expressions in a workflow's `run:` script into `env:`, quoting them for the
  shell they land in. It shows a diff by default; `--apply` writes the changes and `--pr` commits
  each fix to its own branch and opens a pull request that lists the paths it breaks. Code
  vulnerabilities, transitive dependencies and hash-pinned locks get a reason, not a guess.
- Function-level reachability for Go. The vulnerable symbols come from the Go vulnerability
  database (through OSV, cached for a week, skipped with `--offline`), and first-party calls to
  them are evidence with file and line. No direct call lowers the priority a little but keeps the
  finding a weapon, since a dependency may still call the function; when the vulnerable package
  isn't imported directly, the report says so instead of guessing.
- Helm charts are rendered with `helm template` (default values, offline, empty Helm home) and
  analyzed like plain manifests, with evidence pointing at the template file. The image includes
  Helm, pinned and checksum-verified, and the weekly refresh keeps it current within its major
  version. A chart that fails to render is one blind spot with Helm's error.
- NetworkPolicy for the `cluster` entry point. A pod no ingress policy selects stays reachable
  from the foothold; an isolated pod is reachable only from the pods its rules admit, after
  taking control of one; default-deny cuts it off.
- Hosting platforms as entry points: Vercel, Netlify, Render, Fly.io, Procfile web processes and
  App Engine. The platform's config says what is public, so application repositories get a real,
  evidenced way in instead of the assumed internet-facing application.
- Slack and Microsoft Teams alerts when a change opens an attack path (or when the gate fails, or
  always: `notify.on`). Webhook URLs come only from the environment (`BREACHGRAPH_SLACK_WEBHOOK`,
  `BREACHGRAPH_TEAMS_WEBHOOK`, or the action's `slack-webhook` and `teams-webhook` inputs), and
  repository text in the message is escaped so it can't mention a channel or add links.
- `-f evidence`: an audit evidence pack. One zip with the JSON, SARIF and HTML reports, the SBOM
  and OpenVEX, the policy the gate ran with and every accepted risk, a plain summary (scan
  identity, gate decision, scanners and versions, attack paths, the controls this evidence is
  commonly used for), and a manifest with the SHA-256 of every file.
- A live demo on GitHub Pages: the HTML report for examples/vulnerable-platform, rebuilt from
  `main` on every change, linked first in the README.
- A weekly refresh workflow for what Dependabot can't update: the hash-pinned Python locks and
  the Trivy and Gitleaks binaries (version and SHA-256 from the release's checksums file). It
  takes only releases at least 14 days old, runs the tests, builds the image and checks the demo's
  attack paths, then pushes a branch and opens an issue to review. It never merges on its own.
- `--name` sets the project name in reports. By default it comes from the git remote (plus the
  subdirectory scanned), so reports from the Docker image no longer call every project "src".

### Changed

- A scan stops before running any scanner when its output directory isn't writable, with the
  `docker run --user` fix in the message, instead of failing with a traceback at the end.
- The benchmark was rerun with this version: same 15 paths, 14 real.

## [0.3.0] - 2026-10-27

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
- The application database as a crown jewel for repositories without infrastructure code. It is
  found from the drivers and ORMs the code imports (SQLAlchemy, Sequelize, Prisma, GORM, JDBC and
  others) or a connection setting such as `DATABASE_URL`, and only when no Terraform or Kubernetes
  source defines a database. SQL injection and code execution in the application reach it.
- An application that serves HTTP routes and has no deployment configuration is modeled as one
  workload assumed to be internet-facing, at medium confidence, and the coverage line says so.
- MITRE ATT&CK techniques on every attack-path step and path (T1190, T1552.005, T1078.004, T1530
  and others), linked in the PR comment and HTML report and added to SARIF results as
  `attack.<id>` tags.
- OWASP Top 10 CI/CD Security Risks labels (CICD-SEC-1 to 10) on CI/CD findings from the built-in
  checks and zizmor, shown next to the OWASP Top 10 category and tagged in SARIF.
- An OpenSSF Scorecard workflow.
- A threat model of breachgraph itself in docs/architecture.md.
- `breachgraph init` inspects the repository and says what the attack graph will model there
  (routes, workloads, cloud resources, Kubernetes, CI jobs, crown jewels) and which settings fit:
  the `credentials` or `cluster` entry point, crown-jewel overrides, rendering Helm charts. The
  workflow it writes pins `actions/checkout` to a commit and turns off credential persistence.
- Policy changes in the PR comment: every report records the settings that decide what fails, and
  a PR compared with the base branch is told which ones it changed (a lowered `fail_on`, a new
  suppression, a scanner turned off, an excluded path), so a PR can't quietly loosen its own gate.
- `ai.prices`: set or override a model's price per million tokens, so a price change or a new
  model doesn't need a release.
- Compose services that publish ports, or sit behind an nginx, Traefik, Caddy, HAProxy or Envoy
  service that does, are exposed to the internet at medium confidence.
- The action's `imports` input merges reports from earlier steps (ZAP, CodeQL, any SARIF).
- The benchmark also reports what the credentials and cluster entry points find on each project,
  apart from the hand-labeled results.

### Changed

- The default gate fails on P1 findings instead of P2, alongside attack paths, known exploited CVEs
  and secrets. On the benchmark projects 350 findings block, where P2 blocked 1,497 in the previous
  run; on the healthy control project, 10 where P2 blocked 131. Set `fail_on.priority: P2` for the
  stricter gate.
- Reports and PR comments use plain text instead of emoji icons.
- Findings in CI configuration, tests, fixtures, examples and docs no longer count as weaknesses
  of the service that ships the code. They remain findings; they just don't open attack paths.
  When a service has several matching weaknesses, the path cites its own source first.

### Removed

- breachgraph no longer runs OWASP ZAP. `--dast-url`, `scanners.zap` and the action's `dast-url`
  input are gone. Scanning a running application is a separate job from gating a change: run
  ZAP's own action and merge its report with `--import zap=report_json.json`, or with the action's
  new `imports` input, which takes any supported report including SARIF.

### Fixed

- A privileged pod reachable from the internet reached its node with no code vulnerability: the
  escape edge now needs code execution in the pod as well as the disabled isolation.
- The benchmark harness wrote each report inside the scanned tree, so a rerun scanned its own
  previous report.
- A compose service built from `.` or `../` was not mapped to its source code.
- A path that needed a weakness the graph derives itself (a committed password, a privileged pod)
  could replace a path to the same target that needed nothing, such as an anonymous storage
  container, because both looked like they used no scanner finding. Both are now reported.

### Security

- A symlink in the scanned repository that points outside it (to `~/.aws/credentials`, say) was
  read by the configuration parsers. Such links are now skipped.
- The Docker image and CI install every Python package from hash-pinned locks
  (`requirements/*.txt`, regenerated with `scripts/lock.py`), including the build backend.
- The intentionally vulnerable demo apps carry `osv-scanner.toml` ignore lists, so OSV-based
  checks don't report their pinned old dependencies as breachgraph's own.
- Wheels and source archives on GitHub releases are signed with Sigstore (`.sigstore.json` bundles
  next to each file), and release notes come from this changelog.

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

[Unreleased]: https://github.com/amoghnellutla/breachgraph/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/amoghnellutla/breachgraph/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/amoghnellutla/breachgraph/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/amoghnellutla/breachgraph/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/amoghnellutla/breachgraph/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/amoghnellutla/breachgraph/releases/tag/v0.1.0
