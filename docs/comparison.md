# When to use breachgraph, and when to use something else

breachgraph is a free, self-hosted check that runs on a repository before a change merges. It
runs open-source scanners and then answers one question their lists don't: which findings line up
into a way for an attacker to reach your data. This page says what that buys you, what it
doesn't, and when another tool is the better choice.

## Compared with running the scanners yourself

breachgraph runs Semgrep, Gitleaks, Trivy, Checkov and zizmor, so this is the closest comparison.

| | Scanners on their own | breachgraph |
|---|---|---|
| Findings | Each tool's own list | The same findings, deduplicated across tools |
| Priority | Severity per finding | Exploitability: CISA KEV, EPSS, whether a vulnerable package is imported (and for Go, whether the vulnerable function is called), and whether the finding lies on an attack path |
| Connections between layers | None. Checkov's graph checks link Terraform resources to each other, but not to code findings | Code, containers, Kubernetes, Terraform IAM (AWS, Azure, GCP), GitHub Actions and hosting configs in one graph, with the paths from the internet to your data |
| Pull requests | A list of new findings | "This change opens one attack path", drawn, plus the findings that block |
| Noise on the benchmark | 7,447 raw findings across eight projects | 15 attack paths, 14 of them real ([benchmark](benchmark.md)) |
| Cost | Free | Free (Apache-2.0); the scanners keep their own licenses |

If you already run these scanners and their volume is the problem, breachgraph adds the most.
If you need one scanner's full output with nothing on top, run that scanner.

## Compared with commercial platforms

Cloud security platforms (often called CNAPP) and developer security platforms are mature
products. Where they and breachgraph overlap, here is the difference in kind:

| | Commercial platforms | breachgraph |
|---|---|---|
| What it reads | Usually the live cloud account (APIs, sometimes agents), plus repositories | Only the repository: code, manifests, Terraform, workflows |
| When it speaks | After deployment (runtime) and, increasingly, before | Before merge, in the pull request |
| Sees drift, manual changes, resources made outside code | Yes, from the live account | No. If it isn't in the repository, breachgraph doesn't know it |
| Code weaknesses on the path | Varies by product and tier | Yes: SSRF, injection, code execution from Semgrep are steps on the path |
| Where data goes | Vendor's cloud | Nowhere. It runs in your CI; optional AI triage uses your own key |
| Cost | Commercial licensing | Free |
| Support, SLAs, dashboards across many repositories | Yes | No: one scan, one repository (or a few scanned together) at a time |

## Pick something else when

- **You need to know what is actually deployed.** Resources created in the console, drift from
  Terraform, running workloads and their real network exposure need a tool that reads the live
  account.
- **You need deep data-flow analysis of your own code.** CodeQL and commercial SAST trace data
  through whole programs. breachgraph uses Semgrep's rules and treats a function call or an
  import as evidence. You can import CodeQL's SARIF into breachgraph to get both.
- **You need governance across hundreds of repositories**: dashboards, ownership, SLAs and
  reporting for a security team. breachgraph has no server.
- **Your infrastructure is described in a form the attack graph isn't built from**: Pulumi, CDK,
  CloudFormation, Bicep and ARM, Helm charts whose dependencies aren't vendored, or Kustomize
  overlays that pull remote bases. Checkov and Trivy still report findings in many of these files; they just don't become
  steps on a path.

## Use breachgraph when

- You want pull requests to fail on the few problems that lead somewhere, not on every finding.
- Your infrastructure is in the same repository as your code, or in a few repositories you can
  scan together (`breachgraph scan app/ infra/`).
- You want results inside GitHub or GitLab, with no vendor account and no code leaving CI.
- You want to see, for a given change, whether it opens or closes a way in, and fix the cheapest
  link first.

The rules and limits of the model are in [attack-graph.md](attack-graph.md).
