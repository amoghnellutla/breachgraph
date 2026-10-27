from pathlib import Path

import pytest

from breachgraph.models import Category, Severity
from breachgraph.normalize.taxonomy import normalize_cwes, normalize_owasp, owasp_for
from breachgraph.paths import glob_match, iter_files, normalize_path


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


def test_iter_files_prunes_excluded_dirs(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from breachgraph.paths import iter_files

    for rel in [
        "a.py",
        ".venv/lib/x.py",
        "node_modules/p/Dockerfile",
        "src/b.py",
        ".git/config",
        "docs/c.md",
    ]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x", encoding="utf-8")
    got = [rel for _, rel in iter_files(tmp_path, ["**/.venv/", "node_modules/", "docs/*.md"])]
    assert got == ["a.py", "src/b.py"]


def test_symlinks_out_of_the_tree_are_not_read(tmp_path: Path) -> None:
    repo, outside = tmp_path / "repo", tmp_path / "secret.yaml"
    repo.mkdir()
    outside.write_text("token: hunter2\n", encoding="utf-8")
    (repo / "real.yaml").write_text("a: 1\n", encoding="utf-8")
    try:
        (repo / "evil.yaml").symlink_to(outside)
        (repo / "alias.yaml").symlink_to(repo / "real.yaml")
    except OSError:
        pytest.skip("symlinks need extra privileges on this platform")
    assert sorted(rel for _, rel in iter_files(repo, [])) == ["alias.yaml", "real.yaml"]
