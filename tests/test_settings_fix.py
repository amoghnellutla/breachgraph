"""Fixes are proved by rebuilding the graph; one that removes no path is dropped."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.fix import Fix
from breachgraph.graph import build_attack_graph
from breachgraph.models import AttackGraphSummary, Category, Finding, Location, ScanResult, Severity
from breachgraph.settings_fix import _drop_public_grant, candidates, prove, proved_settings
from tests.test_entry_points import write

BUCKET = """resource "aws_s3_bucket" "data" {
  bucket = "customer-data"
  acl    = "public-read"
}
"""
GRANT = """resource "google_storage_bucket" "data" {
  name = "customer-data"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
"""


def result() -> ScanResult:
    return ScanResult(breachgraph_version="1", target=".", attack_graph=AttackGraphSummary())


def test_a_public_bucket_gets_a_proved_fix(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", BUCKET)
    [fix] = proved_settings(result(), tmp_path, Config(), 3)
    assert (fix.removed, fix.added) == (1, 0)
    assert 'acl    = "private"' in fix.files["main.tf"]
    assert (tmp_path / "main.tf").read_text(encoding="utf-8") == BUCKET  # the repository is untouched


def test_a_public_grant_is_removed_and_the_bucket_kept(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", GRANT)
    [fix] = proved_settings(result(), tmp_path, Config(), 3)
    assert fix.removed == 1
    new = fix.files["main.tf"]
    assert "iam_member" not in new and 'resource "google_storage_bucket" "data"' in new
    assert not build_attack_graph(tmp_path, [], Config()).paths or "allUsers" not in new


def test_a_list_keeps_its_other_members() -> None:
    lines = ['  members = ["allUsers", "user:a@example.com"]']
    assert _drop_public_grant(lines, 0) == (['  members = ["user:a@example.com"]'], "from the list")


def test_a_fix_that_removes_no_path_is_dropped(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", BUCKET + "\n# note\n")
    finding = Finding(
        tool="x",
        rule_id="y",
        title="t",
        severity=Severity.LOW,
        category=Category.IAC,
        location=Location(path="main.tf", start_line=1),
    )
    fix = Fix(finding, files={"main.tf": BUCKET}, summary="A comment")
    [proved] = prove([fix], result(), tmp_path, Config())
    assert proved.files == {} and "removed no attack path" in proved.reason


def test_nothing_on_a_path_means_no_candidates(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", 'resource "aws_s3_bucket" "data" {\n  bucket = "customer-data"\n}\n')
    assert candidates(build_attack_graph(tmp_path, [], Config()), tmp_path) == []
