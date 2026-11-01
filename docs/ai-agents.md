# Checking code before a pull request

`breachgraph check` answers one question about your working tree: does this change open an attack
path? It works for you, for a git hook and for an AI coding assistant.

```bash
breachgraph check                 # the first run scans and saves a base
breachgraph check                 # later runs rescan what changed and compare
breachgraph check --update-base   # accept this tree as the new base
```

It exits 1 when the change opens a path, and prints the route and the code that causes it. Add
`--json` for tools. It skips KEV and EPSS lookups, and it writes only to breachgraph's cache
directory.

## With an AI coding assistant

`breachgraph mcp` is an [MCP](https://modelcontextprotocol.io) server. From the repository:

```bash
claude mcp add breachgraph -- breachgraph mcp
```

For other MCP clients, run the command `breachgraph mcp` in the repository's directory.

It offers two tools:

- `check_change`: whether the working tree opens a path, closes one, or widens what one bug could
  reach. An assistant can call it after writing a change and fix what it finds.
- `explain_finding`: why a finding at a file and line is or isn't on a path.
- `preview_fixes`: settings changes that remove paths, each with its diff and proof. It changes no
  files.
- `what_reaches`: what falls if a secret, role or workload is lost, and what can reach an asset.

To make this a habit, add a line to your assistant's instructions: "Before finishing a change, call
`check_change` and fix any path it opens."

## As a git hook

With [pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/amoghnellutla/breachgraph
    rev: v0.8.0
    hooks:
      - id: breachgraph
```

It runs on push, so commits stay fast. Install the scanners first with `breachgraph setup`.
