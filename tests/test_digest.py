from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import sba_digest


@pytest.mark.parametrize(
    ("bad_path", "match"),
    [
        ("", r"^Empty path$"),
        ("../secret", r"^Path traversal"),
        ("./", r"^Current directory"),
        ("./bad", r"^Current directory"),
        ("a//b", r"^Empty path component"),
        ("a/./b", r"^Current directory"),
        ("a/../b", r"^Path traversal"),
        ("/abs/path", r"^Absolute path"),
        ("a\\b", r"^Path contains backslash"),
        ("nul\x00byte", r"^Path contains NUL byte"),
    ],
)
def test_validate_path_rejects_invalid(bad_path: str, match: str) -> None:
    with pytest.raises(sba_digest.PathValidationError, match=match):
        sba_digest.validate_path(bad_path)


def test_check_case_collisions_detects_conflicts() -> None:
    collision = sba_digest.check_case_collisions(["Readme.md", "README.md"])
    assert collision is not None


def test_check_case_collisions_no_conflict() -> None:
    assert sba_digest.check_case_collisions(["readme.md", "docs/readme.md"]) is None


def test_digest_matches_manifest(manifest: dict, repo_root: Path) -> None:
    for name, spec in manifest["testVectors"].items():
        path = repo_root / spec["path"]
        if spec.get("mode") == "archive":
            digest_hex, _ = sba_digest.compute_archive_digest(path)
            computed = f"sha256:{digest_hex}"
        else:
            result = sba_digest.compute_bundle_digest(path)
            computed = f"sha256:{result.digest}"

        assert computed == spec["expectedDigest"], f"{name} digest mismatch"


def test_formatters_render_digest(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "SKILL.md").write_text(
        "---\nname: format-test\ndescription: test\nversion: 0.1.0\n---\n",
        encoding="utf-8",
    )

    result = sba_digest.compute_bundle_digest(bundle)

    json_payload = json.loads(sba_digest.format_result_json(result))
    assert json_payload["bundleDigest"] == f"sha256:{result.digest}"
    assert json_payload["algorithm"] == result.algorithm
    assert json_payload["entryCount"] == result.entry_count
    assert json_payload["totalBytes"] == result.total_bytes
    entries = {entry["path"]: entry for entry in json_payload["entries"]}
    assert len(entries) == result.entry_count
    for entry in result.entries:
        payload = entries[entry.path]
        assert payload["digest"] == f"sha256:{entry.digest}"
        assert payload["size"] == entry.size

    human_payload = sba_digest.format_result_human(result)
    assert f"Bundle Digest: sha256:{result.digest}" in human_payload
    assert f"Files: {result.entry_count}" in human_payload
    assert f"Total Size: {result.total_bytes:,} bytes" in human_payload
    assert "Entries:" in human_payload
    for entry in result.entries:
        assert entry.path in human_payload
    assert result.digest in human_payload


def test_normalize_path_strips_dot_prefix_and_backslashes() -> None:
    assert sba_digest.normalize_path("./foo/bar") == "foo/bar"
    assert sba_digest.normalize_path("foo\\bar") == "foo/bar"
    assert sba_digest.normalize_path("././foo/bar") == "foo/bar"


def test_should_exclude_default_patterns() -> None:
    assert sba_digest.should_exclude(".git/config")
    assert sba_digest.should_exclude("SBA.attestation.json")
    assert sba_digest.should_exclude(".sba/attestation.json")
    assert not sba_digest.should_exclude("src/app.py")


def test_validate_path_rejects_long_component() -> None:
    component = "a" * (sba_digest.MAX_PATH_COMPONENT_LENGTH + 1)
    with pytest.raises(sba_digest.PathValidationError, match=r"^Path component exceeds"):
        sba_digest.validate_path(f"{component}/file.txt")


def test_validate_path_rejects_long_path() -> None:
    long_path = "a" * (sba_digest.MAX_PATH_LENGTH + 1)
    with pytest.raises(sba_digest.PathValidationError, match=r"^Path exceeds"):
        sba_digest.validate_path(long_path)


def test_hash_file_returns_digest_and_size(tmp_path: Path) -> None:
    path = tmp_path / "data.bin"
    data = b"hello world"
    path.write_bytes(data)
    digest, size = sba_digest.hash_file(path)
    assert size == len(data)
    assert digest == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_compute_bundle_digest_errors_on_missing_or_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(FileNotFoundError):
        sba_digest.compute_bundle_digest(missing)

    file_path = tmp_path / "file.txt"
    file_path.write_text("data", encoding="utf-8")
    with pytest.raises(ValueError):
        sba_digest.compute_bundle_digest(file_path)


def test_format_entry_bytes() -> None:
    entry = sba_digest.FileEntry(path="a.txt", digest="deadbeef", size=12)
    payload = sba_digest.format_entry(entry)
    assert payload == b"a.txt\x00sha256:deadbeef\x0012\n"


def test_compute_bundle_digest_sorts_entries(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "b.txt").write_text("b", encoding="utf-8")
    (bundle / "a.txt").write_text("a", encoding="utf-8")

    result = sba_digest.compute_bundle_digest(bundle)
    paths = [entry.path for entry in result.entries]
    assert paths == ["a.txt", "b.txt"]


def test_enumerate_bundle_files_excludes_paths(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "keep.txt").write_text("ok", encoding="utf-8")
    (bundle / ".git").mkdir()
    (bundle / ".git" / "config").write_text("nope", encoding="utf-8")
    (bundle / ".attestations").mkdir()
    (bundle / "SBA.attestation.json").write_text("nope", encoding="utf-8")

    files = [rel for rel, _ in sba_digest.enumerate_bundle_files(bundle)]
    assert "keep.txt" in files
    assert all(".git" not in path for path in files)
    assert all(".attestations" not in path for path in files)
    assert all(path != "SBA.attestation.json" for path in files)


def test_enumerate_bundle_files_skips_symlink(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    target = bundle / "target.txt"
    target.write_text("ok", encoding="utf-8")
    link = bundle / "link.txt"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlinks not supported on this platform")

    files = [rel for rel, _ in sba_digest.enumerate_bundle_files(bundle)]
    assert "target.txt" in files
    assert "link.txt" not in files
