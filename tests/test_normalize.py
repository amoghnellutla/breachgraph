from tests.conftest import make_finding, make_vuln
from triagegate.models import Category, Confidence, Location, Severity
from triagegate.normalize import dedupe, finalize


def test_fingerprint_survives_line_shift() -> None:
    a = finalize([make_finding(line=10)])[0]
    b = finalize([make_finding(line=42)])[0]
    assert a.fingerprint == b.fingerprint


def test_fingerprint_changes_with_code() -> None:
    a = finalize([make_finding(snippet="eval(x)")])[0]
    b = finalize([make_finding(snippet="eval(y)")])[0]
    assert a.fingerprint != b.fingerprint


def test_fingerprint_ignores_whitespace() -> None:
    a = finalize([make_finding(snippet="eval( x )")])[0]
    b = finalize([make_finding(snippet="eval(x)")])[0]
    assert a.fingerprint == b.fingerprint


def test_identical_matches_get_distinct_fingerprints() -> None:
    items = finalize([make_finding(line=1), make_finding(line=50)])
    assert len({f.fingerprint for f in items}) == 2


def test_sca_fingerprint_ignores_installed_version() -> None:
    a = make_vuln()
    b = make_vuln()
    assert b.package is not None
    b.package.version = "2.14.0"
    assert finalize([a])[0].fingerprint == finalize([b])[0].fingerprint


def test_finalize_fills_owasp_and_normalizes() -> None:
    f = finalize([make_finding(cwe=["CWE-89: SQL Injection"], path="./src/db.py")])[0]
    assert f.cwe == ["CWE-89"]
    assert f.owasp == ["A03:2021"]
    assert f.location.path == "src/db.py"
    assert f.sources == ["semgrep"]


def test_dedupe_merges_equivalent_iac_rules() -> None:
    trivy = make_finding(
        tool="trivy",
        rule_id="AVD-DS-0002",
        title="Image user should not be 'root'",
        category=Category.IAC,
        severity=Severity.HIGH,
        path="Dockerfile",
        line=1,
        end_line=7,
    )
    checkov = make_finding(
        tool="checkov",
        rule_id="CKV_DOCKER_3",
        title="Ensure that a user for the container has been created",
        category=Category.IAC,
        severity=Severity.MEDIUM,
        path="Dockerfile",
        line=1,
        end_line=7,
    )
    out = dedupe(finalize([trivy, checkov]))
    assert len(out) == 1
    merged = out[0]
    assert merged.tool == "trivy"  # higher severity wins as primary
    assert merged.sources == ["trivy", "checkov"] or merged.sources == ["checkov", "trivy"]
    assert "checkov:CKV_DOCKER_3" in merged.related_rules
    assert len(merged.fingerprints) == 2


def test_dedupe_merges_secrets_on_same_line() -> None:
    gl = make_finding(
        tool="gitleaks",
        rule_id="generic-api-key",
        category=Category.SECRETS,
        title="Hardcoded secret",
        path="settings.py",
        line=4,
        cwe=["CWE-798"],
    )
    sg = make_finding(
        tool="semgrep",
        rule_id="generic.secrets.api-key",
        category=Category.SAST,
        title="Hardcoded API key",
        path="settings.py",
        line=4,
        cwe=["CWE-798"],
    )
    assert len(dedupe(finalize([gl, sg]))) == 1


def test_dedupe_keeps_distinct_issues() -> None:
    a = make_finding(
        tool="trivy",
        rule_id="AVD-AWS-0086",
        title="S3 Access block should block public ACL",
        category=Category.IAC,
        path="main.tf",
        line=10,
        end_line=16,
    )
    b = make_finding(
        tool="checkov",
        rule_id="CKV_AWS_24",
        title="Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
        category=Category.IAC,
        path="main.tf",
        line=10,
        end_line=16,
    )
    assert len(dedupe(finalize([a, b]))) == 2


def test_dedupe_same_tool_never_merges() -> None:
    a = make_finding(rule_id="r1", snippet="a()")
    b = make_finding(rule_id="r2", snippet="a()")
    assert len(dedupe(finalize([a, b]))) == 2


def test_dedupe_merges_same_cve_package_path() -> None:
    a = make_vuln()
    b = make_vuln(tool="osv")
    out = dedupe(finalize([a, b]))
    assert len(out) == 1
    assert set(out[0].sources) == {"trivy", "osv"}


def test_merge_keeps_best_metadata() -> None:
    a = make_finding(
        tool="trivy",
        rule_id="X",
        category=Category.IAC,
        path="main.tf",
        title="Bucket is public",
        confidence=Confidence.MEDIUM,
        cwe=["CWE-284"],
        remediation=None,
    )
    b = make_finding(
        tool="checkov",
        rule_id="Y",
        category=Category.IAC,
        path="main.tf",
        title="Public bucket",
        confidence=Confidence.HIGH,
        cwe=["CWE-284"],
        remediation="Block public access",
    )
    merged = dedupe(finalize([a, b]))[0]
    assert merged.remediation == "Block public access"


def test_dast_locations_are_not_paths() -> None:
    f = finalize(
        [
            make_finding(
                tool="zap",
                category=Category.DAST,
                location=Location(path="https://app/x?q=1", in_repo=False),
            )
        ]
    )[0]
    assert f.location.path == "https://app/x?q=1"


def test_same_tool_rules_on_same_code_and_cwe_merge() -> None:
    a = make_finding(rule_id="flask.ssrf", cwe=["CWE-918"], line=36, end_line=37, snippet="a")
    b = make_finding(rule_id="django.ssrf", cwe=["CWE-918"], line=37, snippet="b")
    c = make_finding(rule_id="other", cwe=["CWE-89"], line=37, snippet="c")
    out = dedupe(finalize([a, b, c]))
    assert len(out) == 2


def test_cross_tool_clusters_hold_one_finding_per_tool() -> None:
    """Chains of weak matches must not swallow distinct checks (real Trivy+Checkov S3 case)."""

    def tf(tool: str, rule: str, title: str, line: int, end: int):  # type: ignore[no-untyped-def]
        return make_finding(
            tool=tool,
            rule_id=rule,
            title=title,
            category=Category.IAC,
            path="main.tf",
            line=line,
            end_line=end,
            snippet=rule,
        )

    items = [
        tf("trivy", "AWS-0086", "S3 Access block should block public ACL", 12, 12),
        tf("trivy", "AWS-0087", "S3 Access block should block public policy", 13, 13),
        tf("checkov", "CKV_AWS_53", "Ensure S3 bucket has block public ACLS enabled", 10, 16),
        tf("checkov", "CKV_AWS_54", "Ensure S3 bucket has block public policy enabled", 10, 16),
    ]
    out = dedupe(finalize(items))
    assert len(out) == 2
    pairs = {frozenset([f.rule_id, *(r.split(":", 1)[1] for r in f.related_rules)]) for f in out}
    assert pairs == {frozenset({"AWS-0086", "CKV_AWS_53"}), frozenset({"AWS-0087", "CKV_AWS_54"})}


def test_equivalent_rules_merge_without_line_numbers() -> None:
    trivy = make_finding(
        tool="trivy",
        rule_id="DS-0026",
        title="No HEALTHCHECK defined",
        category=Category.IAC,
        path="Dockerfile",
        line=None,
        snippet=None,
    )
    checkov = make_finding(
        tool="checkov",
        rule_id="CKV_DOCKER_2",
        title="Ensure HEALTHCHECK added",
        category=Category.IAC,
        path="Dockerfile",
        line=1,
        end_line=7,
    )
    assert len(dedupe(finalize([trivy, checkov]))) == 1
