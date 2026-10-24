# Attack-path analysis

breachgraph builds a single graph linking your code, containers, Kubernetes and cloud, then finds
the paths an attacker could walk from the internet to a high-value ("crown-jewel") asset. This is
what separates a finding that matters from one that doesn't: a medium-severity SSRF on a route
whose pod can reach a data bucket is a breach; the same SSRF on an isolated internal job is noise.

## The model

**Nodes** are assets: the internet, entrypoints (load balancers, ingresses, open security groups),
workloads (pods, EC2, ECS, Lambda), container images, HTTP routes, identities (IAM roles, service
accounts), data stores and secrets, and hosts.

**Edges** are relationships extracted from your repo, each with evidence (`file:line`) and a
confidence. Some edges are **gated**: they can be crossed only if the source node carries a
*weakness* of a required class. This is the core idea — reaching a workload over the network is
not the same as controlling it.

| Weakness class | Comes from | Unlocks |
|---|---|---|
| `code_execution` | command injection, deserialization, template injection (CWE-77/78/94/502/917…) | full control of the workload → its identity, secrets, databases |
| `ssrf` | CWE-918 | the cloud metadata/credentials endpoint → the compute's role |
| `data_injection` | SQL/NoSQL/LDAP injection (CWE-89/943/90) | the database the workload connects to |
| `file_read` | path traversal, XXE (CWE-22/611…) | mounted secret files |
| `credential_exposure` | hardcoded/leaked secret (CWE-798) | the account the credential belongs to |
| `vulnerable_dependency` | a dependency/image CVE **in CISA KEV or high EPSS** | control of the workload |
| `container_escape` | privileged, hostPath, dangerous capabilities, hostPID | the node and its role |
| `metadata_reachable` | `hostNetwork`, EC2/ECS metadata | combined with SSRF, the node/instance role |

Only dependency CVEs with real exploitation signal (KEV, or EPSS ≥ 10% and CVSS ≥ 7) become a
weakness, so the graph is not flooded by every unreachable CVE.

## The "no free ride" guarantee

Structural privilege edges — a pod → its service account, a workload → its IAM role, a workload →
a mounted secret — all carry a `requires` gate. With **no** code vulnerability, an internet-facing
pod whose role can read a bucket produces **no path** to that bucket. A route only reaches the
pod's identity once a real weapon (code execution, SSRF, …) is present on it. This is enforced and
[tested](../tests/test_graph_paths.py) (`test_no_free_ride_without_a_weapon`).

## Finding and ranking paths

The engine enumerates paths from the internet to crown jewels (bounded DFS with a step budget, so
it always terminates), and keeps the best path **per distinct set of weapons**. That way two
independent entry points — say command injection and SSRF both reaching the same bucket — surface
as separate vectors, because fixing one does not fix the other.

Each path is scored by the target's value, the difficulty of each step, and the weakest edge's
confidence. **Choke points** are the weaknesses that appear on the most paths: fixing one breaks
every path through it, so they are the recommended fixes, cheapest first.

## What each source understands

**Kubernetes** (`sources/kubernetes.py`): Ingress / LoadBalancer / NodePort exposure (internal
annotations respected), container escape (privileged, host mounts, capabilities, hostPID),
`hostNetwork` → metadata, mounted secrets, RBAC (a token that can read secrets / exec pods /
create workloads), and IRSA service-account-to-role mapping. Unrendered Helm/Kustomize is reported
as a blind spot, not guessed.

**Terraform / AWS** (`sources/terraform.py`): IAM policies are actually evaluated — action/resource
matching with wildcards, scoping to specific resources, AWS-managed policies, **explicit Deny
wins**, and **privilege-escalation** primitives (e.g. a role that can `iam:AttachRolePolicy` can
make itself admin). Exposure from internet-facing load balancers, security groups open to
`0.0.0.0/0`, public EC2/RDS, and unauthenticated Lambda URLs. Compute: EC2 (incl. IMDSv1/v2), ECS
tasks, Lambda, EKS node groups. Values known only at apply time lower an edge's confidence instead
of being guessed.

**Routes** (`sources/routes.py`): HTTP routes and handler line ranges via tree-sitter for Python
(Flask, FastAPI, Django), JS/TS (Express, NestJS, Next.js), Java (Spring) and Go (net/http, Gin,
Echo, Chi). Findings inside a handler's line range attach to that route.

## Configuration

```yaml
attack_graph:
  enabled: true
  crown_value: 7            # a node at/above this value (0-10) is a crown jewel
  crown_jewels:             # raise the value of assets that match
    - match: "customer"     # substring/glob of the asset name or id
      value: 10
    - match: "*prod*"
      kind: datastore
      value: 9
  fail_on_new_path: true    # a new internet->crown-jewel path fails the gate
  min_confidence: medium    # paths below this confidence don't gate (high|medium|low)
  max_depth: 12
  max_paths: 40
```

Data stores and secrets get a default value of 6 even without a rule, so obvious targets are never
missed. Set `enabled: false` to turn the whole layer off.

## Honest limitations

- **Reachability is not yet proven for dependency CVEs** — a KEV CVE in an image is treated as a
  possible compromise of that workload; whether the vulnerable function is actually called is
  future work (see the roadmap).
- **AWS and Kubernetes only** today; Azure and GCP are planned, and the model has room for them.
- Static analysis can't see everything (apply-time values, admission controllers, runtime network
  policy). breachgraph lowers confidence and lists blind spots rather than overclaiming.
