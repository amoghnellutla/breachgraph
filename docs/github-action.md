# GitHub Action

## Minimal setup

```yaml
# .github/workflows/secgate.yml
name: secgate
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF -> code scanning
  pull-requests: write     # sticky PR comment

jobs:
  secgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: OWNER/secgate@v0
```

On each PR you get:

- **A PR comment**, updated in place on every push, listing the findings that block the merge.
- **Inline annotations** in the PR diff, through GitHub code scanning (SARIF).
- **A job summary** with the same table.
- **A `secgate-report` artifact** containing the HTML report, SARIF, JSON, JUnit and a CycloneDX SBOM.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `config` | | Path to `.secgate.yml` |
| `baseline` | | Baseline file (auto-detected at `<path>/.secgate-baseline.json`) |
| `fail-on` | | `P1`–`P4` or `none`; overrides config |
| `only` / `skip` | | Comma-separated scanner names |
| `dast-url` | | Run a ZAP baseline scan against a running app |
| `images` | | Comma-separated container images for Trivy |
| `comment` | `true` | Sticky PR comment |
| `issues` | | Open an issue per finding at this priority or above (e.g. `P1`). Issues are closed automatically when the finding disappears from the default branch |
| `upload-sarif` | `true` | Upload to code scanning |
| `output-dir` | `secgate-report` | Report directory |
| `version` / `image` | `v0` | Image tag / full image reference |
| `extra-args` | | Extra `secgate scan` arguments (e.g. `--no-fail`) |

Outputs: `passed`, `findings`, `gating`, `sarif`.

## Recipes

**Adopt on a legacy repo.** Accept today's findings, then fail only on new ones:

```bash
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/secgate scan --write-baseline .secgate-baseline.json
git add .secgate-baseline.json && git commit -m "secgate baseline"
```

**Report-only mode** while you tune the policy:

```yaml
      - uses: OWNER/secgate@v0
        with:
          extra-args: --no-fail
```

**DAST against a preview environment:**

```yaml
      - run: docker compose up -d && ./wait-for-it.sh localhost:8080
      - uses: OWNER/secgate@v0
        with:
          dast-url: http://localhost:8080
```

**Scan the image you just built:**

```yaml
      - run: docker build -t myapp:${{ github.sha }} .
      - uses: OWNER/secgate@v0
        with:
          images: myapp:${{ github.sha }}
```

**Track P1 findings as issues** (on the default branch):

```yaml
    permissions:
      issues: write
    steps:
      - uses: OWNER/secgate@v0
        with:
          issues: P1
```

## Notes

- **Fork PRs** get a read-only token, so the PR comment and SARIF upload are skipped with a
  warning. The gate result is not affected.
- **Private repositories** need GitHub Advanced Security for code scanning uploads. Everything
  else works without it.
- The Trivy vulnerability DB and the KEV/EPSS feeds are cached between runs with `actions/cache`.
