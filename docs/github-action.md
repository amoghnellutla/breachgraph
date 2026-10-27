# GitHub Action

## Minimal setup

```yaml
# .github/workflows/breachgraph.yml
name: breachgraph
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF -> code scanning
  pull-requests: write     # sticky PR comment

jobs:
  breachgraph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: amoghnellutla/breachgraph@v0
```

On each PR you get:

- **A PR comment**, updated in place on every push, listing the findings that block the merge.
- **Inline annotations** in the PR diff, through GitHub code scanning (SARIF).
- **A job summary** with the same table.
- **A `breachgraph-report` artifact** containing the HTML report, SARIF, JSON, JUnit and a CycloneDX SBOM.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `config` | | Path to `.breachgraph.yml` |
| `baseline` | | Baseline file (auto-detected at `<path>/.breachgraph-baseline.json`) |
| `fail-on` | | `P1`–`P4` or `none`; overrides config |
| `only` / `skip` | | Comma-separated scanner names |
| `slack-webhook` | | Slack incoming webhook URL, from a secret. Posts when a change opens an attack path (`notify.on` in the config changes when) |
| `teams-webhook` | | Microsoft Teams Workflows webhook URL, from a secret. Same alerts as Slack |
| `imports` | | Reports from earlier steps to merge, as `TOOL=PATH` (e.g. `zap=report_json.json,sarif=codeql.sarif`) |
| `images` | | Comma-separated container images for Trivy |
| `comment` | `true` | Sticky PR comment |
| `compare` | `true` | Compare each PR with the default branch's last report (kept in the Actions cache): findings and attack paths that already exist there don't fail the PR, and the comment leads with the attack paths the PR **opens** (drawn as a diagram) or **closes**, and lists any change the PR makes to the gate's own settings (a lowered threshold, a new suppression, a scanner turned off). Runs on the default branch save the report; nothing to commit |
| `issues` | | Open an issue per finding at this priority or above (e.g. `P1`). Issues are closed automatically when the finding disappears from the default branch |
| `upload-sarif` | `true` | Upload to code scanning |
| `output-dir` | `breachgraph-report` | Report directory |
| `version` / `image` | `v0` | Image tag / full image reference |
| `extra-args` | | Extra `breachgraph scan` arguments (e.g. `--no-fail`) |

Outputs: `passed`, `findings`, `gating`, `sarif`.

## What a pull request sees

With `compare` on (the default), the PR comment starts with the one thing a reviewer needs:

> ### This change opens 1 new attack path(s)
> **→ S3 bucket shop-customer-data-prod** · high confidence
> (Mermaid diagram: Internet → Ingress api → Deployment shop/api → GET /fetch → IAM role → bucket)

or `This change closes 2 attack path(s)` when a fix breaks paths, or `No change to attack paths`.
Attack paths are matched across runs by a stable id (entry point, target and the findings the path
needs), so moving code around does not make a path look new.

The first PR after adding the action has no base report yet. It then falls back to the baseline
file, if any, and to treating everything as new. Push to the default branch once to seed it.
Locally, the same comparison is `breachgraph scan . --compare base/breachgraph.json`.

## Pull-request speed

With a base report available, pull requests are scanned incrementally (`incremental`, on by
default): only changed files go through Semgrep and Checkov, Trivy, Gitleaks and zizmor run only
when a file they read changed, and the default branch's findings are reused for the rest. The
attack graph is always rebuilt from the whole tree. If anything about the base is in doubt (no
file digests, another breachgraph version, other scanner settings), the scan is full.

Measured in the release image on a one-line change, scanner caches warm:

| Project | Changed file | Incremental | Full rescan | Cold full scan |
|---|---|---:|---:|---:|
| OWASP Juice Shop | `routes/login.ts` | 8 s | 25 s | 73 s |
| Online Boutique | `src/frontend/handlers.go` | 9 s | 19 s | 47 s |
| TerraGoat | `terraform/aws/s3.tf` | 10 s | 9 s | 121 s |

In each case the incremental result had exactly the same findings, fingerprints and attack paths
as the full rescan. A change to infrastructure files reruns the infrastructure scanners, so it
gains little (TerraGoat).

## Recipes

**Adopt on a legacy repo.** Accept today's findings, then fail only on new ones:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" ghcr.io/amoghnellutla/breachgraph scan --write-baseline .breachgraph-baseline.json
git add .breachgraph-baseline.json && git commit -m "breachgraph baseline"
```

**Report-only mode** while you tune the policy:

```yaml
      - uses: amoghnellutla/breachgraph@v0
        with:
          extra-args: --no-fail
```

**Merge a ZAP scan of a preview environment.** breachgraph doesn't run ZAP itself; run ZAP's own
action first and import its JSON report:

```yaml
      - run: docker compose up -d && ./wait-for-it.sh localhost:8080
      - uses: zaproxy/action-baseline@v0.15.0
        with:
          target: http://localhost:8080
          allow_issue_writing: false
          fail_action: false
      - uses: amoghnellutla/breachgraph@v0
        with:
          imports: zap=report_json.json
```

The same input merges CodeQL, Bandit, gosec or any other SARIF report: `imports: sarif=codeql.sarif`.

**Code and infrastructure in separate repositories.** Check the infrastructure repository out
next to the code and pass both paths; they are scanned as one, so a path from a route in the app
to a bucket defined in the infra repository is found:

```yaml
      - uses: actions/checkout@v7
      - uses: actions/checkout@v7
        with:
          repository: your-org/infra
          path: infra
          token: ${{ secrets.INFRA_READ_TOKEN }}   # a read-only token for the private repo
      - uses: amoghnellutla/breachgraph@v0
        with:
          path: ". infra"
```

Locally the same is `breachgraph scan ../app ../infra`.

**Scan the image you just built:**

```yaml
      - run: docker build -t myapp:${{ github.sha }} .
      - uses: amoghnellutla/breachgraph@v0
        with:
          images: myapp:${{ github.sha }}
```

**Track P1 findings as issues** (on the default branch):

```yaml
    permissions:
      issues: write
    steps:
      - uses: amoghnellutla/breachgraph@v0
        with:
          issues: P1
```

## Notes

- **Fork PRs** get a read-only token, so the PR comment and SARIF upload are skipped with a
  warning. The gate result is not affected.
- **Private repositories** need GitHub Advanced Security for code scanning uploads. Everything
  else works without it.
- The Trivy vulnerability DB and the KEV/EPSS feeds are cached between runs with `actions/cache`.
