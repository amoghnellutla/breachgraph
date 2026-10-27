"""MITRE ATT&CK techniques on attack paths and OWASP CI/CD risks on CI findings."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.attack import TECHNIQUES, technique_url
from breachgraph.graph.summary import summarize
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.normalize import finalize
from breachgraph.normalize.taxonomy import normalize_owasp
from breachgraph.reporters import html, markdown, sarif
from tests.test_coverage import ALL, run
from tests.test_entry_points import AZ_VM, write
from tests.test_pipeline_attackgraph import CMDI, PLATFORM, SSRF


def test_platform_paths_carry_techniques() -> None:
    res = run(PLATFORM, ALL, [SSRF, CMDI])
    by_target = {tuple(p.techniques) for p in res.attack_graph.paths}  # type: ignore[union-attr]
    assert ("T1190", "T1552.005", "T1530") in by_target  # SSRF -> node metadata -> bucket
    assert ("T1190", "T1528", "T1078.004", "T1530") in by_target  # RCE -> pod token -> IRSA role
    assert all(t in TECHNIQUES for p in res.attack_graph.paths for t in p.techniques)  # type: ignore[union-attr]
    assert "[T1552.005](https://attack.mitre.org/techniques/T1552/005/)" in markdown.render(res)
    assert 'href="https://attack.mitre.org/techniques/T1530/"' in html.render(res)
    tags = [r["properties"].get("tags", []) for r in sarif.build(res)["runs"][0]["results"]]
    assert ["attack-path", "attack.T1190", "attack.T1552.005", "attack.T1530"] in tags


def test_committed_password_and_assumed_key(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", AZ_VM % "false")
    result = build_attack_graph(tmp_path, [], Config())
    views = summarize(result, [], Config().attack_graph, baseline_used=False).paths
    assert any(v.techniques[:1] == ["T1552.001"] and "T1078.004" in v.techniques for v in views)
    assert any(v.techniques[-1] == "T1530" for v in views)


def test_technique_url() -> None:
    assert technique_url("T1078.004") == "https://attack.mitre.org/techniques/T1078/004/"


def ci(rule: str, tool: str = "zizmor") -> Finding:
    return Finding(
        tool=tool,
        rule_id=rule,
        title=rule,
        severity=Severity.HIGH,
        category=Category.CICD,
        confidence=Confidence.HIGH,
        location=Location(path=".github/workflows/ci.yml", start_line=3),
    )


def test_ci_findings_get_owasp_cicd_risks() -> None:
    out = {
        f.rule_id: f.owasp
        for f in finalize(
            [
                ci("template-injection"),
                ci("unpinned-uses"),
                ci("cicd/untrusted-checkout", "cicd"),
                ci("artipacked"),
                ci("something-new"),
            ]
        )
    }
    assert "CICD-SEC-4" in out["template-injection"]
    assert "CICD-SEC-4" in out["cicd/untrusted-checkout"]
    assert "CICD-SEC-3" in out["unpinned-uses"]
    assert "CICD-SEC-6" in out["artipacked"]
    assert not any(o.startswith("CICD-SEC") for o in out["something-new"])
    assert normalize_owasp(["cicd-sec-4", "A03:2021 - Injection"]) == ["CICD-SEC-4", "A03:2021"]
