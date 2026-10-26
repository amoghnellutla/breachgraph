# breachgraph: all scanners, pinned and checksum-verified, in one image.
#   docker run --rm -v "$PWD:/src" ghcr.io/amoghnellutla/breachgraph scan /src
#
# Bump versions with the matching SHA-256 from each project's release checksums file.
# The base image is pinned by digest; Dependabot proposes updates.

FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS binaries
ARG TARGETARCH=amd64
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) T_ARCH=64bit; G_ARCH=x64;   T_SHA=${TRIVY_SHA256_AMD64}; G_SHA=${GITLEAKS_SHA256_AMD64} ;; \
      arm64) T_ARCH=ARM64; G_ARCH=arm64; T_SHA=${TRIVY_SHA256_ARM64}; G_SHA=${GITLEAKS_SHA256_ARM64} ;; \
      *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSLo trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${T_ARCH}.tar.gz"; \
    echo "${T_SHA}  trivy.tgz" | sha256sum -c -; \
    tar -xzf trivy.tgz trivy; \
    curl -fsSLo gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${G_ARCH}.tar.gz"; \
    echo "${G_SHA}  gitleaks.tgz" | sha256sum -c -; \
    tar -xzf gitleaks.tgz gitleaks; \
    chmod 0755 trivy gitleaks

FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS python-tools
ARG SEMGREP_VERSION=1.179.0
ARG CHECKOV_VERSION=3.3.26
ARG ZIZMOR_VERSION=1.30.1
# Separate virtualenvs: semgrep and checkov pin conflicting dependencies.
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && python -m venv /opt/checkov && /opt/checkov/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" \
    && python -m venv /opt/zizmor && /opt/zizmor/bin/pip install --no-cache-dir "zizmor==${ZIZMOR_VERSION}"
COPY pyproject.toml README.md LICENSE /build/
COPY src /build/src
RUN python -m venv /opt/breachgraph && /opt/breachgraph/bin/pip install --no-cache-dir "/build[ai]"

FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
LABEL org.opencontainers.image.title="breachgraph" \
      org.opencontainers.image.description="Security gate: Semgrep, Gitleaks, Trivy, Checkov, zizmor, ZAP with dedupe, KEV/EPSS risk scoring, attack paths and policy" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*' \
    && useradd --uid 10001 --create-home breachgraph
COPY --from=binaries /dl/trivy /dl/gitleaks /usr/local/bin/
COPY --from=python-tools /opt /opt
RUN ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
    && ln -s /opt/zizmor/bin/zizmor /usr/local/bin/zizmor \
    && ln -s /opt/breachgraph/bin/breachgraph /usr/local/bin/breachgraph

# Writable caches for any UID (CI runners often use --user "$(id -u):$(id -g)").
ENV HOME=/tmp/home \
    BREACHGRAPH_CACHE_DIR=/tmp/breachgraph-cache \
    TRIVY_CACHE_DIR=/tmp/trivy-cache \
    SEMGREP_SEND_METRICS=off \
    PYTHONUNBUFFERED=1
RUN mkdir -p /tmp/home && chmod 1777 /tmp/home
USER 10001
WORKDIR /src
# A CLI that runs and exits: there is no long-running process to health-check.
HEALTHCHECK NONE
ENTRYPOINT ["breachgraph"]
CMD ["scan", "."]
