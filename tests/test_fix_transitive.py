"""A dependency of a dependency: pinned when that's safe, left to a person when it isn't."""

import json
from pathlib import Path

import pytest

from breachgraph.fix import fix_finding
from breachgraph.models import Category, Package
from tests.conftest import make_finding


def cve(manifest: str, version: str = "1.2.0", fixed: str = "1.2.5"):  # type: ignore[no-untyped-def]
    f = make_finding(path=manifest, title="CVE-2026-1 in lodash")
    f.category = Category.SCA
    f.package = Package(name="lodash", version=version, fixed_version=fixed, ecosystem="npm")
    return f


@pytest.mark.parametrize(
    ("lock", "path"),
    [
        ("package-lock.json", ["overrides"]),
        ("yarn.lock", ["resolutions"]),
        ("pnpm-lock.yaml", ["pnpm", "overrides"]),
    ],
)
def test_each_package_manager_gets_its_own_key(tmp_path: Path, lock: str, path: list[str]) -> None:
    (tmp_path / "package.json").write_text('{\n    "name": "shop"\n}\n', encoding="utf-8")
    (tmp_path / lock).write_text("", encoding="utf-8")
    fix = fix_finding(cve(lock), tmp_path)
    doc = json.loads(fix.files["package.json"])
    for key in path:
        doc = doc[key]
    assert doc == {"lodash": "1.2.5"}
    assert '    "name"' in fix.files["package.json"]  # the file keeps its indent


def test_a_new_major_version_is_left_to_a_person(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    fix = fix_finding(cve("package-lock.json", "1.2.0", "2.0.0"), tmp_path)
    assert not fix.files and "new major version" in fix.reason


def test_an_existing_pin_is_not_overwritten(tmp_path: Path) -> None:
    text = '{"overrides": {"lodash": "1.0.0"}}'
    (tmp_path / "package.json").write_text(text, encoding="utf-8")
    assert not fix_finding(cve("package-lock.json"), tmp_path).files


def test_requirements_get_a_line_that_says_why(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    fix = fix_finding(cve("requirements.txt"), tmp_path)
    assert fix.files["requirements.txt"] == "flask==3.0.0\nlodash>=1.2.5  # transitive, for CVE-2026-1\n"


def test_a_hash_pinned_lock_is_regenerated_not_edited(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0 --hash=sha256:aa\n", encoding="utf-8")
    assert not fix_finding(cve("requirements.txt"), tmp_path).files
