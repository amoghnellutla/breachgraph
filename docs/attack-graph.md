# Attack-path analysis

breachgraph builds a single graph linking your code, containers, Kubernetes and cloud, then finds
the paths an attacker could walk from the internet to a high-value ("crown-jewel") asset. This is
what separates a finding that matters from one that doesn't: a medium-severity SSRF on a route
whose pod can reach a data bucket is a breach; the same SSRF on an isolated internal job is noise.

## The model

**Nodes** are assets: the internet, entrypoints (load balancers, ingresses, open security groups),
workloads (pods, EC2, ECS, Lambda, Azure VMs/App Service/Container Apps, GCE, Cloud Run, Cloud
Functions), container images, HTTP routes, identities (IAM roles, managed identities, GCP and
Kubernetes service accounts), data stores and secrets, and hosts.

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
| `metadata_reachable` | `hostNetwork`, EC2/ECS metadata, Azure IMDS, GCP metadata server | combined with SSRF, the node/instance identity |

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

**Terraform / Azure** (`sources/azure.py`): role assignments are evaluated, not just listed. Each
role (built-in, or a custom `azurerm_role_definition`) is expanded to its Actions, NotActions and
DataActions, and the scope (resource, resource group, subscription) decides which stores it
covers. An identity reaches a store only through an operation that yields the data: reading blobs,
listing storage or Cosmos DB keys, reading Key Vault secrets, or resetting a database admin
password. Key Vaults are checked in both permission models (RBAC, and access policies, where
anyone who can edit the vault can grant themselves secrets). `roleAssignments/write` (Owner, User
Access Administrator) is privilege escalation. Compute: VMs and scale sets (IMDS), App Service,
Functions, Container Apps, AKS kubelet identities; system- and user-assigned identities. Exposure:
public IP + NSG on both the NIC and the subnet (Standard vs Basic SKU), Container Apps external
ingress, App Service public access, anonymous blob containers, SQL/PostgreSQL/MySQL firewall rules
open to the internet. AKS workload identity via `azurerm_federated_identity_credential`.

**Terraform / GCP** (`sources/gcp.py`): IAM members, bindings and policies at organization,
folder, project and resource level (buckets, secrets, datasets, KMS keys, service accounts),
predefined and custom roles expanded to permissions. Token or key creation on another service
account is followed as impersonation, so chains like *service account → token creator → admin
service account → bucket* are found. `setIamPolicy` on the project is privilege escalation.
Compute: GCE (including access scopes), Cloud Run v1/v2, Cloud Functions v1/v2, GKE node service
accounts. Exposure: external IP + firewall rules matched by network, target tags and target
service accounts; `allUsers` invokers on Cloud Run/Functions; public buckets (respecting public
access prevention) and datasets; Cloud SQL open to `0.0.0.0/0`. GKE Workload Identity from both
sides (`roles/iam.workloadIdentityUser` binding and the `iam.gke.io/gcp-service-account`
annotation).

The metadata endpoint is modeled per cloud. On Azure and GCP it requires a request header
(`Metadata: true`, `Metadata-Flavor: Google`), like IMDSv2 on AWS, so an SSRF path to it is low
confidence. App Service and Container Apps serve tokens only with a secret header from the
environment, so SSRF alone reaches nothing there; code execution does.

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

- **Dependency reachability is import-level**: a KEV CVE in a package that first-party code imports
  is treated as a possible compromise of that workload; whether the vulnerable *function* is
  called is not yet proven. Packages nothing imports are not weapons.
- **Terraform only for Azure and GCP**: Bicep/ARM templates and Deployment Manager are not
  parsed. Roles and identities created outside Terraform (portal, other repos) are invisible, so a
  role that is not modeled, or a scope that cannot be resolved, is listed as a blind spot.
- Static analysis can't see everything (apply-time values, admission controllers, runtime network
  policy). breachgraph lowers confidence and lists blind spots rather than overclaiming.
