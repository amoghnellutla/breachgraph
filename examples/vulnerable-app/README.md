# ⚠️ Intentionally vulnerable demo app

**Do not deploy this. Do not copy code from it.**

This directory exists so you can watch breachgraph work end to end. Each file contains deliberate,
well-known security flaws that the bundled scanners should catch:

| File | Planted issues | Caught by |
|---|---|---|
| `app.py` | SQL injection, OS command injection, SSRF, insecure deserialization, Flask debug mode, hardcoded secret key, unsafe YAML load | Semgrep |
| `settings.py` | Hardcoded API key and private key (**fake values**, generated randomly) | Gitleaks |
| `requirements.txt` | Outdated Flask, Jinja2, PyYAML, requests, urllib3 with known CVEs | Trivy (SCA) + EPSS |
| `pom.xml` | log4j-core 2.14.1 (**Log4Shell**, CVE-2021-44228, in CISA KEV) | Trivy (SCA) + KEV |
| `Dockerfile` | EOL base image, runs as root, no HEALTHCHECK | Trivy + Checkov (deduplicated) |
| `infra/main.tf` | Public S3 bucket, SSH open to the internet, unencrypted DB, hardcoded password | Trivy + Checkov (deduplicated) |
| `k8s/deployment.yaml` | Privileged container, host network, no resource limits | Trivy + Checkov |

```bash
docker run --rm -v "$PWD:/src" ghcr.io/amoghnellutla/breachgraph scan examples/vulnerable-app
```

The secrets are random strings shaped to match the detection rules. They are not real
credentials for any service.
