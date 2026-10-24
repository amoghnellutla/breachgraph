# ⚠️ Intentionally vulnerable platform

**Do not deploy this. Do not copy from it.** Fake credentials, deliberate flaws.

This is a small microservice platform that demonstrates breachgraph's **attack-path analysis** —
how a code vulnerability, a container setting and an over-broad cloud role combine into a real path
from the internet to customer data.

## The setup

- `services/api/app.py` — a Flask API with an **SSRF** route (`/fetch`) and a **command-injection**
  route (`/thumbnail`).
- `k8s/api.yaml` — the API behind a public **Ingress**, in a pod with **`hostNetwork: true`** and
  an **IRSA** service account mapped to an IAM role.
- `infra/main.tf` — the `customer-data` S3 bucket (tagged PII), an EKS **node role** that can read
  it, and a **pod role** with `AmazonS3FullAccess`.

## The paths breachgraph finds

1. **Command injection** on `/thumbnail` → code execution in the pod → the pod's IRSA role
   (`AmazonS3FullAccess`) → the customer-data bucket.
2. **SSRF** on `/fetch` → because of `hostNetwork`, the request reaches the node's metadata
   endpoint → the **node role**'s credentials → the customer-data bucket (the node role can read it).

Two independent vectors to the same crown jewel. Fixing one does not fix the other, so both are
reported, each with its own cheapest fix.

```bash
# scanners find the SSRF/command-injection; the graph turns them into paths
docker run --rm -v "$PWD:/src" ghcr.io/OWNER/breachgraph scan examples/vulnerable-platform
```

With **no** code findings, breachgraph reports **no path** to the bucket — being internet-facing
with an over-broad role is not, by itself, a breach. That's the point.
