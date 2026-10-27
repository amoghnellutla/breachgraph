"""The audit evidence pack: complete, self-describing, and checkable."""

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from breachgraph.reporters import write_reports
from tests.test_coverage import ALL, run
from tests.test_pipeline_attackgraph import CMDI, PLATFORM, SSRF


def test_evidence_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    res = run(PLATFORM, ALL, [SSRF, CMDI])
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text("{}", encoding="utf-8")
    res.artifacts["sbom"] = str(sbom)
    written = write_reports(res, tmp_path / "out", ["evidence"])
    with zipfile.ZipFile(written["evidence"]) as zf:
        names = set(zf.namelist())
        assert {
            "breachgraph.json", "breachgraph.sarif", "breachgraph.html", "breachgraph.vex.json",
            "sbom.cdx.json", "policy.json", "SUMMARY.md", "manifest.json",
        } <= names  # fmt: skip
        manifest = json.loads(zf.read("manifest.json"))
        for name, digest in manifest["files"].items():
            assert hashlib.sha256(zf.read(name)).hexdigest() == digest
        summary = zf.read("SUMMARY.md").decode()
        policy = json.loads(zf.read("policy.json"))
    assert "| Commit | abc123 |" in summary and "**Failed**" in summary
    assert "S3 bucket shop-customer-data-prod" in summary and "ISO/IEC 27001:2022 A.8.8" in summary
    assert policy["fail_on"]["priority"] == "P1"
    assert not (tmp_path / "out" / "breachgraph.json").exists()  # only the pack was asked for
