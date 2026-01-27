from __future__ import annotations

from pathlib import Path

import sba_digest
import sba_zip


def test_deterministic_zip_matches_manifest(
    manifest: dict,
    repo_root: Path,
    tmp_path: Path,
) -> None:
    tv_archive = manifest["testVectors"]["tv-3-archive"]
    source_dir = repo_root / manifest["testVectors"]["tv-2-complex"]["path"]

    out_zip = tmp_path / "bundle.zip"
    sba_zip.build_zip(source_dir, out_zip)

    digest_hex, _ = sba_digest.compute_archive_digest(out_zip)
    assert f"sha256:{digest_hex}" == tv_archive["expectedDigest"]


def test_zip_metadata_is_deterministic(
    manifest: dict,
    repo_root: Path,
    tmp_path: Path,
) -> None:
    source_dir = repo_root / manifest["testVectors"]["tv-2-complex"]["path"]
    out_zip = tmp_path / "bundle.zip"
    sba_zip.build_zip(source_dir, out_zip)

    import zipfile

    with zipfile.ZipFile(out_zip, "r") as zf:
        infos = zf.infolist()
        assert infos, "zip should contain entries"
        for info in infos:
            assert info.compress_type == zipfile.ZIP_STORED
            assert info.date_time == (2025, 1, 1, 0, 0, 0)


def test_zip_creates_parent_directory(
    manifest: dict,
    repo_root: Path,
    tmp_path: Path,
) -> None:
    source_dir = repo_root / manifest["testVectors"]["tv-2-complex"]["path"]
    out_zip = tmp_path / "nested" / "bundle.zip"
    sba_zip.build_zip(source_dir, out_zip)
    assert out_zip.exists()
