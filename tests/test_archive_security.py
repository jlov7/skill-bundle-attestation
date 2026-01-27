from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

import sba_archive
import sba_digest


def _write_skill_dir(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(
        "---\nname: secure-skill\ndescription: test bundle\nversion: 0.1.0\n---\n",
        encoding="utf-8",
    )


def test_resolve_archive_root_uses_root_when_skill_present(tmp_path: Path) -> None:
    _write_skill_dir(tmp_path)
    root, archive_root = sba_archive.resolve_archive_root(tmp_path, None)
    assert root == tmp_path.resolve()
    assert archive_root is None


def test_resolve_archive_root_uses_single_nested_dir(tmp_path: Path) -> None:
    nested = tmp_path / "bundle"
    _write_skill_dir(nested)
    root, archive_root = sba_archive.resolve_archive_root(tmp_path, None)
    assert root == nested.resolve()
    assert archive_root == "bundle"


def test_resolve_archive_root_missing_skill_raises(tmp_path: Path) -> None:
    (tmp_path / "bundle").mkdir()
    with pytest.raises(FileNotFoundError):
        sba_archive.resolve_archive_root(tmp_path, None)


def test_resolve_archive_root_rejects_traversal(tmp_path: Path) -> None:
    _write_skill_dir(tmp_path / "bundle")
    with pytest.raises(sba_digest.PathValidationError):
        sba_archive.resolve_archive_root(tmp_path, "../bundle")


def test_extract_zip_rejects_traversal(tmp_path: Path) -> None:
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.txt", "nope")
    with pytest.raises(sba_digest.PathValidationError):
        sba_archive.extract_archive(zip_path, tmp_path / "out")


def test_extract_zip_rejects_symlink(tmp_path: Path) -> None:
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "target")
    with pytest.raises(ValueError, match="Symlinks not allowed"):
        sba_archive.extract_archive(zip_path, tmp_path / "out")


def test_extract_zip_rejects_absolute_path(tmp_path: Path) -> None:
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("/abs.txt", "nope")
    with pytest.raises(sba_digest.PathValidationError):
        sba_archive.extract_archive(zip_path, tmp_path / "out")


def test_extract_tar_rejects_traversal(tmp_path: Path) -> None:
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("../evil.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"nope"))
    with pytest.raises(sba_digest.PathValidationError):
        sba_archive.extract_archive(tar_path, tmp_path / "out")


def test_extract_tar_rejects_symlink(tmp_path: Path) -> None:
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "target"
        tf.addfile(info)
    with pytest.raises(ValueError, match="Symlinks not allowed"):
        sba_archive.extract_archive(tar_path, tmp_path / "out")


def test_extract_tar_rejects_absolute_path(tmp_path: Path) -> None:
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("/abs.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"nope"))
    with pytest.raises(sba_digest.PathValidationError):
        sba_archive.extract_archive(tar_path, tmp_path / "out")
