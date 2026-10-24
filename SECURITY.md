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

Vulnerabilities in the bundled scanners (Semgrep, Gitleaks, Trivy, Checkov, ZAP) should be
reported to those projects. We will bump the pinned version once a fix is released.

The intentionally vulnerable code in `examples/vulnerable-app/` is out of scope.

## Supported versions

Only the latest minor release receives security fixes.

## Hardening built in

- Scanner binaries are pinned and verified against SHA-256 values committed in the `Dockerfile`.
- Release images are signed with cosign (keyless) and published with SBOM and provenance attestations.
- Third-party GitHub Actions are pinned to full commit SHAs.
- Secrets are redacted by Gitleaks and redacted again by breachgraph. Secret values are never written to reports.
- Scanner output is treated as untrusted: HTML is auto-escaped, only `http(s)` links are rendered,
  and `@` mentions are neutralized in GitHub comments and issues.
