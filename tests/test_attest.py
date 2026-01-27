from __future__ import annotations

from pathlib import Path

import pytest

import sba_attest


def test_content_statement_directory_matches_manifest(manifest: dict, repo_root: Path) -> None:
    tv1 = manifest["testVectors"]["tv-1-minimal"]
    statement = sba_attest.create_content_statement(repo_root / tv1["path"], is_archive=False)

    bundle = statement["predicate"]["bundle"]
    assert bundle["digest"] == tv1["expectedDigest"]
    expected_subject = tv1["expectedDigest"].replace("sha256:", "")
    assert statement["subject"][0]["digest"]["sha256"] == expected_subject
    assert bundle["bundleType"] == "directory"


def test_content_statement_archive_matches_manifest(manifest: dict, repo_root: Path) -> None:
    tv3 = manifest["testVectors"]["tv-3-archive"]
    statement = sba_attest.create_content_statement(repo_root / tv3["path"], is_archive=True)

    bundle = statement["predicate"]["bundle"]
    assert bundle["archiveDigest"] == tv3["expectedDigest"]
    expected_subject = tv3["expectedDigest"].replace("sha256:", "")
    assert statement["subject"][0]["digest"]["sha256"] == expected_subject
    assert bundle["bundleType"] == "archive"


def test_parse_frontmatter_lines_basic() -> None:
    frontmatter = "name: demo\ndescription: example\nversion: 1.2.3\n"
    data = sba_attest._parse_frontmatter_lines(frontmatter)
    assert data["name"] == "demo"
    assert data["description"] == "example"
    assert data["version"] == "1.2.3"


def test_extract_skill_metadata_missing_skill_md(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        sba_attest.extract_skill_metadata(tmp_path)


def test_extract_skill_metadata_fallback_description(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "SKILL.md").write_text(
        "# Title\n\nThis is the first description line.\n\nMore text.\n",
        encoding="utf-8",
    )
    meta = sba_attest.extract_skill_metadata(bundle)
    assert meta["name"] == "bundle"
    assert meta["description"].startswith("This is the first description line.")


def test_parse_frontmatter_invalid_yaml_returns_empty() -> None:
    invalid = "name: [unterminated"
    assert sba_attest._parse_frontmatter(invalid) == {}


def test_create_content_statement_archive_root_requires_archive(repo_root: Path) -> None:
    bundle_path = repo_root / "test-vectors" / "tv-1-minimal"
    with pytest.raises(ValueError, match="--archive-root requires --archive"):
        sba_attest.create_content_statement(bundle_path, is_archive=False, archive_root="bundle")


def test_sign_dsse_envelope_requires_payload_type(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "SKILL.md").write_text("---\nname: test\n---\n", encoding="utf-8")
    statement = sba_attest.create_content_statement(bundle, is_archive=False)
    envelope = sba_attest.create_dsse_envelope(statement)
    envelope["payloadType"] = "application/json"

    key_path = tmp_path / "key.pem"
    key_path.write_text("invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="payloadType mismatch"):
        sba_attest.sign_dsse_envelope(envelope, key_path)
