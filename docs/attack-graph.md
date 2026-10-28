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
*weakness* of a required class. This is the core idea: reaching a workload over the network is
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

Structural privilege edges (a pod → its service account, a workload → its IAM role, a workload →
a mounted secret) all carry a `requires` gate. With **no** code vulnerability, an internet-facing
pod whose role can read a bucket produces **no path** to that bucket. A route only reaches the
pod's identity once a real weapon (code execution, SSRF, …) is present on it. This is enforced and
[tested](../tests/test_graph_paths.py) (`test_no_free_ride_without_a_weapon`).

## Finding and ranking paths

The engine enumerates paths from the internet to crown jewels (bounded DFS with a step budget, so
it always terminates), and keeps the best path **per distinct set of weapons**. That way two
independent entry points (say command injection and SSRF both reaching the same bucket) surface
as separate vectors, because fixing one does not fix the other.

Each path is scored by the target's value, the difficulty of each step, and the weakest edge's
confidence. **Choke points** are the weaknesses that appear on the most paths: fixing one breaks
every path through it, so they are the recommended fixes, cheapest first.

## What each source understands

**Kubernetes** (`sources/kubernetes.py`): Ingress / LoadBalancer / NodePort exposure (internal
annotations respected), container escape (privileged, host mounts, capabilities, hostPID),
`hostNetwork` → metadata, mounted secrets, RBAC (a token that can read secrets / exec pods /
create workloads), and IRSA service-account-to-role mapping. Helm charts are rendered with
`helm template` and their default values (the Docker image includes Helm), offline and with an
empty Helm home, and analyzed like plain manifests; evidence points at the template each object
came from. A chart that does not render (dependencies not vendored, required values missing) is
one blind spot with Helm's error. Kustomizations are built with `kustomize build` (or `kubectl
kustomize`; the image includes Kustomize), starting from each one no other kustomization
includes, so namespaces, name prefixes and patches apply as deployed; evidence points at the file
each object came from, and the raw base and patch files are not analyzed a second time. A
kustomization with a remote resource or a path outside the scanned directory is not built, and
neither is one that fails: its files are then read as they are, and the reason is a blind spot.

**Terraform / AWS** (`sources/terraform.py`): IAM policies are actually evaluated: action/resource
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

**GitHub Actions** (`sources/actions.py`): a job that anyone with a GitHub account can start
(`pull_request_target`, `issue_comment`, `issues`, `discussion*`, `workflow_run`) is an entry point,
since it runs with the repository's secrets and token. Its credentials are linked behind a code
execution gate: cloud identities assumed over OIDC (an AWS role only when its trust policy's `sub`
condition admits the token this job gets, e.g. `ref:refs/heads/main` for an `issue_comment`
workflow; an Azure identity only when a federated credential's subject matches), the secrets the
job references, and a `GITHUB_TOKEN` that can push code or publish packages. A role that trusts
GitHub's OIDC provider without naming a repository is reachable from the internet directly. See
[CI/CD and supply chain](cicd.md).

**Routes** (`sources/routes.py`): HTTP routes and handler line ranges via tree-sitter for Python
(Flask, FastAPI, Django), JS/TS (Express, NestJS, Next.js), Java (Spring) and Go (net/http, Gin,
Echo, Chi). Findings inside a handler's line range attach to that route. Other findings in a
service's source attach to the service. Findings in CI configuration, tests, fixtures, examples
and docs do not, since the service doesn't run that code.

**Compose** (`sources/images.py`): each service with a `build:` context is a workload that runs the
code in that context. A service that publishes a port on a public interface, or sits behind an
nginx, Traefik, Caddy, HAProxy or Envoy service that does (`depends_on` or `links`), is exposed at
medium confidence: a compose file may only be used for local development.

**Hosting platforms** (`sources/hosting.py`): `vercel.json`, `netlify.toml`, `render.yaml`,
`fly.toml`, a Procfile with a `web` process, and App Engine's `app.yaml`. Each service becomes a
workload running the code in the directory the platform builds from (Netlify's `base`, Render's
`rootDir`). It is exposed to the internet when the platform serves it publicly: Vercel and Netlify
sites, Render `web` services, Fly apps with an HTTP service, App Engine services, and (at medium
confidence, since several platforms read Procfiles) Procfile web processes. Render private
services and workers, and Fly apps with no public service, are workloads with no way in.

**Applications without infrastructure code** (`sources/app.py`): most application repositories
have no Terraform or Kubernetes, yet the database the code talks to is the crown jewel. It is
added as "Application database" when the code imports a database driver or ORM (SQLAlchemy,
psycopg, Django, Sequelize, Prisma, TypeORM, Mongoose, GORM, `database/sql`, JDBC, JPA, Hibernate
and others), or when a config file sets `DATABASE_URL` or a similar setting. It is skipped
when a Terraform or Kubernetes source already defines a queryable database. Code execution in a
service reaches it through the service's own connection, and SQL or NoSQL injection reaches it
directly. When the repository serves HTTP routes and has no deployment configuration at all, the
application is modeled as one workload assumed to be internet-facing, and the coverage line says
so.

## Credentials and other ways in

The default starting point is the internet. Two kinds of credentials are followed from it:

- **Login credentials committed to the repository.** An Azure VM with a literal `admin_password` and
  password login enabled, or an EC2 instance whose key pair's private key is in the repository,
  can be logged into by anyone who can read the repository (everyone, if it is public). With the
  VM's SSH or RDP port open to the internet, that login reaches the VM's identity.
- **IAM users.** Users, groups, inline and attached policies are evaluated like roles, and a user
  reaches a role only when its policy allows `sts:AssumeRole` on that role and the role's trust
  policy admits the user or its account.

Two more starting points are opt-in with `attack_graph.entry_points`, because they are assumptions
rather than facts found in the repository:

- `credentials`: every long-lived access key that Terraform manages is treated as leaked. Its secret
  sits in the state file, and in any output that prints it. Paths start at a node named
  "Leaked access key of IAM user ... (assumed)".
- `cluster`: an attacker already runs code in some pod. Paths start at "Inside the cluster
  (assumed breach)". NetworkPolicy decides what that foothold reaches: a pod that no ingress
  policy selects accepts any pod; a pod a policy isolates accepts only the peers its rules allow
  (pod and namespace selectors, including `kubernetes.io/metadata.name`), so reaching it takes
  control of one of those pods first; a default-deny policy cuts it off. Selectors with
  `matchExpressions` are read as matching, which keeps the result an upper bound.

Paths from an assumed entry point carry that name as their first step, so a report never presents
an assumption as an exposure.

## MITRE ATT&CK

Every step of a path is labeled with the ATT&CK Enterprise technique an attacker uses to cross it,
and the path lists them in order. Reports link each one to attack.mitre.org, and SARIF results for
findings on a path carry `attack-path` and `attack.<id>` tags.

| Step | Technique |
|---|---|
| Exploiting a weakness in an internet-facing route or service | T1190 Exploit Public-Facing Application |
| Code execution in a CI job an outsider can start | T1677 Poisoned Pipeline Execution |
| SSRF to the cloud metadata endpoint | T1552.005 Unsecured Credentials: Cloud Instance Metadata API |
| Logging in with a password or key committed to the repository | T1552.001 Unsecured Credentials: Credentials In Files |
| Acting as a cloud role, managed identity or service account | T1078.004 Valid Accounts: Cloud Accounts |
| Using a Kubernetes service-account token or the CI job token | T1528 Steal Application Access Token |
| Container escape to the node | T1611 Escape to Host |
| Privilege escalation through IAM | T1098.003 Account Manipulation: Additional Cloud Roles |
| Reading a Kubernetes secret | T1552.007 Unsecured Credentials: Container API |
| Reading a cloud secret store | T1555.006 Credentials from Password Stores: Cloud Secrets Management Stores |
| Reading a bucket or storage account | T1530 Data from Cloud Storage |
| Reading a database | T1213 Data from Information Repositories |

The labels describe paths; they never decide which paths exist.

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

- **Dependency reachability is import-level, with function-level evidence for Go**: a KEV CVE in a
  package that first-party code imports is treated as a possible compromise of that workload.
  For Go, the Go vulnerability database names the vulnerable symbols, and breachgraph searches
  first-party code for calls to them: a call is shown as evidence (file:line) and raises the
  priority; an imported package whose vulnerable function is never called directly lowers it a
  little. It stays a weapon either way, because a dependency may still call the function; only a
  whole-program call graph (govulncheck) can rule that out. Other ecosystems have no symbol data
  in OSV yet. Packages nothing imports are not weapons.
- **Terraform only for Azure and GCP**: Bicep/ARM templates and Deployment Manager are not
  parsed. Roles and identities created outside Terraform (portal, other repos) are invisible, so a
  role that is not modeled, or a scope that cannot be resolved, is listed as a blind spot.
- Static analysis can't see everything (apply-time values, admission controllers, runtime network
  policy). breachgraph lowers confidence and lists blind spots rather than overclaiming.
