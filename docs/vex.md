# OpenVEX: tell other tools which CVEs don't affect you

A dependency scanner reports every CVE in every package you ship, including packages your code never
runs. VEX (Vulnerability Exploitability eXchange) is the standard way to say "this CVE is in our
dependency tree, but it does not affect our product", in a document that scanners, SBOM platforms
and customers can consume. breachgraph writes one from its reachability analysis:

```bash
breachgraph scan . -f json,openvex        # writes breachgraph-report/breachgraph.vex.json
trivy fs --vex breachgraph-report/breachgraph.vex.json .   # Trivy now hides the not-affected CVEs
```

The GitHub Action produces it by default as part of the report artifact.

## What each statement says

| breachgraph reachability | OpenVEX status | Details |
|---|---|---|
| Not imported by first-party code, **and** the dependency graph shows no imported package needs it | `not_affected`, justification `vulnerable_code_not_in_execute_path` | `impact_statement` with the evidence |
| Imported, or used through a dependency that is imported (e.g. Jinja2 under Flask) | `affected` | `action_statement` with the fixed version, `status_notes` with where it is used |
| Not imported, but no dependency graph to rule out indirect use | `under_investigation` | |

`not_affected` is only claimed when the manifest's dependency graph proves nothing that is used needs
the package. A plain `requirements.txt` has no graph, because it doesn't say that Flask needs Jinja2.
Three sources provide one:

- lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`;
- `pom.xml`, `go.mod`, `Cargo.lock`;
- pip-compile / uv `requirements.txt` files with `# via` annotations.

## Product scoping

Consumers apply a statement when its product matches a component in their scan:

- When the manifest has a root component (`pom.xml`, `go.mod`, `package.json`), each statement is
  "this package **inside this product**" (`products[].subcomponents`), the most precise form.
- A plain requirements file has no root, so the package purl itself is the product. The statement
  applies wherever the document is used, which is your own scans and SBOMs.
- Set `vex.product` to your product's purl (as it appears in your SBOM) to always use the nested form.

## Configuration

```yaml
vex:
  author: security@example.com   # who issues the statements
  product: null                  # e.g. pkg:github/acme/shop or pkg:oci/shop
  not_affected: true             # false: emit under_investigation instead of not_affected
```

## Limits

Reachability is **import-level**. "Not affected" means no first-party module, and no package that
first-party code uses, imports the vulnerable package. Code that loads modules dynamically
(`importlib`, reflection, plugin systems) can defeat this. If your project does that, set
`not_affected: false`, or review the statements before publishing them. Container OS packages
are not covered: reachability analyzes your source, not the base image.
