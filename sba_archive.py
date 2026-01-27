#!/usr/bin/env python3
"""Archive extraction helpers for SBA.

Supports ZIP and tar archives with path traversal and symlink hardening.
"""

from __future__ import annotations

import shutil
import tarfile
import zipfile
from pathlib import Path
from stat import S_ISLNK
from typing import Optional, Tuple

from sba_digest import normalize_path, validate_path


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a ZIP archive safely, rejecting traversal and symlinks."""
    dest = dest.resolve()
    for member in zf.infolist():
        if member.is_dir() or member.filename.endswith("/"):
            continue
        if S_ISLNK(member.external_attr >> 16):
            raise ValueError(f"Symlinks not allowed in archive: {member.filename}")
        normalized = normalize_path(member.filename)
        validate_path(normalized)
        target = (dest / normalized).resolve()
        if not target.is_relative_to(dest):
            raise ValueError(f"Archive member escapes destination: {member.filename}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract a tar archive safely, rejecting traversal and symlinks."""
    dest = dest.resolve()
    for member in tf.getmembers():
        if member.isdir():
            continue
        if member.issym() or member.islnk():
            raise ValueError(f"Symlinks not allowed in archive: {member.name}")
        normalized = normalize_path(member.name)
        validate_path(normalized)
        target = (dest / normalized).resolve()
        if not target.is_relative_to(dest):
            raise ValueError(f"Archive member escapes destination: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(member)
        if src is None:
            continue
        with src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)


def resolve_archive_root(
    extracted_root: Path, archive_root: Optional[str]
) -> Tuple[Path, Optional[str]]:
    """Resolve the bundle root within an extracted archive.

    If archive_root is provided, it must be a valid relative path and must exist.
    If not provided, SKILL.md is expected at the extraction root. As a convenience,
    a single top-level directory containing SKILL.md will be used and recorded.
    """
    extracted_root = extracted_root.resolve()
    if archive_root:
        normalized = normalize_path(archive_root)
        validate_path(normalized)
        candidate = (extracted_root / normalized).resolve()
        if not candidate.is_relative_to(extracted_root):
            raise ValueError(f"Archive root escapes extraction dir: {archive_root}")
        if not candidate.exists() or not candidate.is_dir():
            raise FileNotFoundError(f"Archive root not found: {archive_root}")
        return candidate, normalized

    skill_md = extracted_root / "SKILL.md"
    if skill_md.exists():
        return extracted_root, None

    entries = list(extracted_root.iterdir())
    dirs = [p for p in entries if p.is_dir()]
    files = [p for p in entries if p.is_file()]

    if len(dirs) == 1 and not files:
        candidate = dirs[0]
        if (candidate / "SKILL.md").exists():
            return candidate, candidate.name

    raise FileNotFoundError(
        "SKILL.md not found at archive root. Provide --archive-root if the bundle is nested."
    )


def extract_archive(
    archive_path: Path,
    dest: Path,
    archive_root: Optional[str] = None,
) -> Tuple[Path, Optional[str]]:
    """Extract supported archives and return bundle root + archive_root used."""
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            _safe_extract_zip(zf, dest)
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as tf:
            _safe_extract_tar(tf, dest)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path}")

    return resolve_archive_root(dest, archive_root)
