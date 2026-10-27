"""The weekly refresh only takes settled releases, and only with checksums from the release."""

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location("refresh_binaries", ROOT / "scripts" / "refresh_binaries.py")
assert spec and spec.loader
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)

NOW = datetime(2026, 10, 27, tzinfo=UTC)
DOCKER = """ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=old1
ARG TRIVY_SHA256_ARM64=old2
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=old3
ARG GITLEAKS_SHA256_ARM64=old4
ARG HELM_VERSION=4.3.0
ARG HELM_SHA256_AMD64=old5
ARG HELM_SHA256_ARM64=old6
"""
A, B = "a" * 64, "b" * 64


def fake(responses: dict[str, object]):  # type: ignore[no-untyped-def]
    def get(url: str) -> bytes:
        body = responses[url]
        return body.encode() if isinstance(body, str) else json.dumps(body).encode()

    return get


def releases(*items: tuple[str, str, bool]) -> list[dict[str, object]]:
    return [{"tag_name": t, "published_at": d, "prerelease": pre, "draft": False} for t, d, pre in items]


def test_takes_the_newest_settled_release(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        refresh,
        "_get",
        fake(
            {
                "https://api.github.com/repos/aquasecurity/trivy/releases?per_page=30": releases(
                    ("v0.77.0", "2026-10-25T00:00:00Z", False),  # too new
                    ("v0.76.2-rc1", "2026-10-01T00:00:00Z", True),  # prerelease
                    ("v0.76.1", "2026-10-05T00:00:00Z", False),
                ),
                "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_checksums.txt": (
                    f"{A}  trivy_0.76.1_Linux-64bit.tar.gz\n{B}  trivy_0.76.1_Linux-ARM64.tar.gz\n"
                ),
                "https://api.github.com/repos/gitleaks/gitleaks/releases?per_page=30": releases(
                    ("v8.30.1", "2026-01-01T00:00:00Z", False)
                ),
                "https://api.github.com/repos/helm/helm/releases?per_page=30": releases(
                    ("v4.3.1", "2026-10-01T00:00:00Z", False),
                    ("v3.22.1", "2026-10-02T00:00:00Z", False),  # other major line: ignored
                ),
                "https://get.helm.sh/helm-v4.3.1-linux-amd64.tar.gz.sha256sum": f"{A}  helm-v4.3.1-linux-amd64.tar.gz\n",
                "https://get.helm.sh/helm-v4.3.1-linux-arm64.tar.gz.sha256sum": f"{B}  helm-v4.3.1-linux-arm64.tar.gz\n",
            }
        ),
    )
    text, changes = refresh.refresh(DOCKER, NOW)
    assert changes == ["trivy 0.75.0 -> 0.76.1", "helm 4.3.0 -> 4.3.1"]
    assert f"ARG HELM_VERSION=4.3.1\nARG HELM_SHA256_AMD64={A}\nARG HELM_SHA256_ARM64={B}" in text
    assert f"ARG TRIVY_VERSION=0.76.1\nARG TRIVY_SHA256_AMD64={A}\nARG TRIVY_SHA256_ARM64={B}" in text
    assert "ARG GITLEAKS_VERSION=8.30.1\nARG GITLEAKS_SHA256_AMD64=old3" in text  # already current


def test_missing_checksums_leave_the_pin_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        refresh,
        "_get",
        fake(
            {
                "https://api.github.com/repos/aquasecurity/trivy/releases?per_page=30": releases(
                    ("v0.76.1", "2026-10-05T00:00:00Z", False)
                ),
                "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_checksums.txt": (
                    f"{A}  trivy_0.76.1_Linux-64bit.tar.gz\n"
                ),
                "https://api.github.com/repos/gitleaks/gitleaks/releases?per_page=30": [],
                "https://api.github.com/repos/helm/helm/releases?per_page=30": [],
            }
        ),
    )
    text, changes = refresh.refresh(DOCKER, NOW)
    assert text == DOCKER and changes == ["trivy 0.76.1: checksums missing, not updated"]


def test_lock_diff_pairs_old_and_new_versions() -> None:
    spec2 = importlib.util.spec_from_file_location("lock_diff", ROOT / "scripts" / "lock_diff.py")
    assert spec2 and spec2.loader
    lock_diff = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(lock_diff)
    old = "semgrep==1.179.0 \\n    --hash=sha256:x\nrich==13.0 ; python_version >= '3.11'\ngone==1\n"
    new = "semgrep==1.180.0 \\n    --hash=sha256:y\nrich==13.0\nfresh==2\n"
    assert lock_diff.changes(old, new) == [
        "fresh (new) -> 2",
        "gone 1 -> (removed)",
        "semgrep 1.179.0 -> 1.180.0",
    ]
