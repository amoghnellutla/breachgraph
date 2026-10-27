# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems in breachgraph.

Report privately via GitHub: **Security → Report a vulnerability** on this repository
(private vulnerability reporting). You will get an acknowledgement within 3 business days and a
status update at least every 7 days until the issue is resolved.

Please include affected versions, a description of the impact, and reproduction steps or a
proof of concept.

## Scope

In scope:

- Code in this repository (the `breachgraph` package, the GitHub Action, the Docker image build).
- Ways that malicious repository content or scanner output could make breachgraph execute code,
  leak secrets, write outside the output directory, or inject content into PR comments, issues
  or HTML reports.

Vulnerabilities in the bundled scanners (Semgrep, Gitleaks, Trivy, Checkov, zizmor) should be
reported to those projects. We will bump the pinned version once a fix is released.

The intentionally vulnerable code in `examples/` is out of scope.

## Supported versions

Only the latest minor release receives security fixes.

## Hardening built in

- Scanner binaries are pinned and verified against SHA-256 values committed in the `Dockerfile`.
- Every Python package in the image and in CI is installed from a hash-pinned lock (`requirements/`).
- Files are read only inside the scanned tree: symlinks that point outside it are skipped.
- Release images are signed with cosign (keyless) and published with SBOM and provenance attestations.
- Third-party GitHub Actions are pinned to full commit SHAs.
- Secrets are redacted by Gitleaks and redacted again by breachgraph. Secret values are never written to reports.
- Scanner output is treated as untrusted: HTML is auto-escaped, only `http(s)` links are rendered,
  and `@` mentions are neutralized in GitHub comments and issues.

The threat model is in [docs/architecture.md](docs/architecture.md#threat-model).

## Verifying a release

Images are signed keylessly by the release workflow, so you can check that an image was built by
this repository's workflow, from a tag, and recorded in the public transparency log. Use cosign v3
or later; v2 cannot read the signature format:

```bash
cosign verify ghcr.io/amoghnellutla/breachgraph:v0.1.0   --certificate-identity-regexp 'https://github.com/amoghnellutla/breachgraph/.github/workflows/release.yml@refs/tags/v.*'   --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each GitHub release lists the image digest. Pin the digest (`@sha256:...`) in your workflows, and
let Dependabot or Renovate propose updates.
