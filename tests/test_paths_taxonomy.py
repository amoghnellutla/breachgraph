import pytest

from triagegate.models import Category, Severity
from triagegate.normalize.taxonomy import normalize_cwes, normalize_owasp, owasp_for
from triagegate.paths import glob_match, normalize_path


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("./src/app.py", "src/app.py"), ("/main.tf", "main.tf"), ("a\\b\\c.py", "a/b/c.py")],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


@pytest.mark.parametrize(
    ("path", "pattern", "hit"),
    [
        ("node_modules/x/y.js", "node_modules/", True),
        ("web/node_modules/x.js", "node_modules/", True),
        ("tests/test_app.py", "tests/", True),
        ("src/tests_helper.py", "tests/", False),
        ("pkg/foo_test.go", "**/*_test.go", True),
        ("pkg/foo.go", "**/*_test.go", False),
        ("infra/prod/main.tf", "infra/*/main.tf", True),
        ("infra/prod/x/main.tf", "infra/*/main.tf", False),
        ("docs/guide.md", "docs", True),
    ],
)
def test_glob_match(path: str, pattern: str, hit: bool) -> None:
    assert glob_match(path, pattern) is hit


def test_normalize_cwes_handles_tool_spellings() -> None:
    raw = ["CWE-89: Improper Neutralization of SQL", "cwe_79", "CWE-89", "79"]
    assert normalize_cwes(raw) == ["CWE-89", "CWE-79"]


def test_normalize_owasp() -> None:
    assert normalize_owasp(["A03:2021 - Injection", "A1:2017-Injection"]) == [
        "A03:2021",
        "A01:2017",
    ]


def test_owasp_mapping_with_category_fallback() -> None:
    assert owasp_for(["CWE-918"], Category.SAST) == ["A10:2021"]
    assert owasp_for([], Category.SCA) == ["A06:2021"]
    assert owasp_for([], Category.SAST) == []


def test_severity_aliases() -> None:
    assert Severity.parse("ERROR") is Severity.HIGH
    assert Severity.parse("moderate") is Severity.MEDIUM
    assert Severity.parse("UNKNOWN") is Severity.MEDIUM
    assert Severity.parse(None, default=Severity.LOW) is Severity.LOW
