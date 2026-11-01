"""Only a key in a provider's format, in code that runs, blocks. Checksums aren't secrets."""

from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.models import Category, Confidence, Location, Priority, Severity
from breachgraph.policy import evaluate_gate
from breachgraph.scanners.base import ScanContext
from breachgraph.scanners.gitleaks import GitleaksScanner, verdict
from tests.test_entry_points import write

MD5 = "d41d8cd98f00b204e9800998ecf8427e"


@pytest.mark.parametrize(
    ("rule", "rel", "line", "expected"),
    [
        ("generic-api-key", "i18n.lock", f"hash: {MD5}", "drop"),
        ("aws-access-token", "yarn.lock", "x", "drop"),
        ("generic-api-key", "pnpm-lock.yaml", "x", "drop"),
        ("generic-api-key", "src/data.json", f'"sum": "{MD5}"', "drop"),
        ("generic-api-key", "src/config.py", 'api_key = "aB3dE5gH7jK9"', "report"),
        ("generic-api-key", "src/config.py", f'PAYMENTS_API_KEY = "{MD5}"', "report"),
        ("jwt", "src/auth.ts", "x", "report"),
        ("aws-access-token", ".env.example", "AWS=AKIA1234567890ABCDEF", "report"),
        ("aws-access-token", "tests/conftest.py", "AKIA1234567890ABCDEF", "report"),
        ("github-pat", "docs/setup.md", "ghp_x", "report"),
        ("stripe-access-token", "src/pay.ts", "sk_test_abc", "report"),
        ("aws-access-token", "src/aws.py", "AKIAIOSFODNN7EXAMPLE", "report"),
        ("private-key", "scale/benchmark/mock-api/keys.ts", "-----BEGIN PRIVATE KEY", "report"),
        ("private-key", ".devcontainer/certs/key.pem", "-----BEGIN PRIVATE KEY", "report"),
        ("private-key", "backend/localhostssl/server.key", "-----BEGIN PRIVATE KEY", "report"),
        ("sentry-access-token", "src/locales/source-hashes.json", "x", "drop"),
        ("aws-access-token", "src/hash_utils.py", "key = AKIA1234567890ABCDEF", "block"),
        ("aws-access-token", "src/attestation.py", "key = AKIA1234567890ABCDEF", "block"),
        ("aws-access-token", "src/aws.py", "key = AKIA1234567890ABCDEF", "block"),
        ("github-pat", "deploy/run.sh", "TOKEN=ghp_abc123", "block"),
        ("private-key", "deploy/id_rsa", "-----BEGIN RSA PRIVATE KEY-----", "block"),
    ],
)
def test_verdict(rule: str, rel: str, line: str, expected: str) -> None:
    assert verdict(rule, rel, line) == expected


def parse(tmp: Path, rel: str, text: str, rule: str):  # type: ignore[no-untyped-def]
    write(tmp, rel, text)
    ctx = ScanContext(target=tmp, work_dir=tmp, config=Config())
    raw = [{"RuleID": rule, "File": rel, "StartLine": 1, "Secret": "REDACTED", "Description": "d"}]
    return GitleaksScanner().parse(raw, ctx)


def test_a_checksum_is_not_a_finding(tmp_path: Path) -> None:
    assert parse(tmp_path, "src/a.json", f'"sum": "{MD5}"\n', "generic-api-key") == []


def test_a_guess_is_reported_without_blocking(tmp_path: Path) -> None:
    from tests.test_scoring_policy import _result

    [f] = parse(tmp_path, "src/a.py", 'key = "aB3dE5gH7jK9mN"\n', "generic-api-key")
    assert f.confidence is Confidence.LOW and f.severity is Severity.LOW and f.category is Category.SECRETS
    f.priority = Priority.P4
    assert evaluate_gate(_result([f]), Config()).passed


def test_a_real_key_blocks(tmp_path: Path) -> None:
    from tests.test_scoring_policy import _result

    [f] = parse(tmp_path, "src/a.py", 'key = "AKIA1234567890ABCDEF"\n', "aws-access-token")
    assert f.confidence is Confidence.HIGH and f.severity is Severity.CRITICAL
    assert not evaluate_gate(_result([f]), Config()).passed
    assert isinstance(f.location, Location)


@pytest.mark.parametrize(
    ("rule", "rel", "line", "expected"),
    [
        ("linkedin-client-secret", "src/a.ts", "x", "report"),
        ("discord-api-token", "release.env", "SHA256='abc'", "report"),
        ("vault-service-token", "internal/t.go", "s.someVeryLongFieldNameHere", "report"),
        ("vault-service-token", "internal/t.go", "token := hvs.abcdef", "block"),
        ("gcp-api-key", "clients/app/google-services.json", "x", "report"),
        ("private-key", ".examples/mtls/certs/client.key", "x", "report"),
        ("private-key", "client/src/api/constellation.demo.tsx", "x", "report"),
    ],
)
def test_more_verdicts(rule: str, rel: str, line: str, expected: str) -> None:
    assert verdict(rule, rel, line) == expected


def test_code_that_handles_a_key_is_not_a_key(tmp_path: Path) -> None:
    code = "const pem = `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`\n"
    [f] = parse(tmp_path, "src/jwt.ts", code, "private-key")
    assert f.confidence is Confidence.LOW
    body = "\n".join(["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"] * 6)
    [f] = parse(
        tmp_path,
        "deploy/id.pem",
        f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n",
        "private-key",
    )
    assert f.confidence is Confidence.HIGH


def test_a_word_and_any_token_is_not_a_provider_format() -> None:
    assert verdict("airtable-api-key", "src/icons.ts", '"brand-airtable": "abcdefghij1234567"') == "report"


def test_a_scanner_ignore_list_holds_false_alarms_on_purpose() -> None:
    assert verdict("square-access-token", ".secretsignore", "EAAAxxxx") == "drop"
    assert verdict("aws-access-token", "sub/.gitleaksignore", "AKIA") == "drop"


def test_real_provider_formats_still_block() -> None:
    for rule in ("aws-access-token", "github-pat", "stripe-access-token", "gitlab-pat", "slack-bot-token"):
        assert verdict(rule, "src/config.py", "value") == "block"
