#!/usr/bin/env python3
"""
SBA Bundle Digest Reference Implementation v1.0

This module implements the canonical bundle digest algorithm for
Skill Bundle Attestation (SBA). The digest provides a deterministic,
cross-platform identity for Agent Skill bundles.

Algorithm Summary:
1. Enumerate all regular files under bundle root (excluding patterns)
2. For each file: compute SHA-256 of raw bytes
3. Create entry: "<path>\0sha256:<hex>\0<size>\n"
4. Sort entries by path (bytewise UTF-8)
5. Concatenate all entries
6. Compute SHA-256 of concatenated entries

This implementation is dependency-free (stdlib only) and serves as
the executable specification for SBA bundle identity.

SPDX-License-Identifier: Apache-2.0
"""

import hashlib
import os
import sys
import unicodedata
from pathlib import Path
from typing import Iterator, NamedTuple, Optional, Set

# =============================================================================
# Constants (Normative)
# =============================================================================

# Default exclusion patterns - these files/directories are NEVER included in digest
# NORMATIVE: This list MUST match the schema's excludePatterns default
DEFAULT_EXCLUDES: Set[str] = {
    ".git",
    ".attestations",
    ".skillcheck",
    ".specstory",
    ".DS_Store",
    "Thumbs.db",
    ".gitignore",
    ".gitattributes",
    "__pycache__",
    "node_modules",
    ".venv",
}

# File/directory prefixes that indicate attestation storage
ATTESTATION_PREFIXES: Set[str] = {
    "SBA.",
    ".sba",
}

# Maximum path component length (security hardening)
MAX_PATH_COMPONENT_LENGTH = 255

# Maximum total path length
MAX_PATH_LENGTH = 4096


# =============================================================================
# Data Types
# =============================================================================


class FileEntry(NamedTuple):
    """Represents a single file in the bundle digest computation."""

    path: str  # Bundle-relative path, / separators, NFC normalized
    digest: str  # SHA-256 hex digest of file contents
    size: int  # File size in bytes


class BundleDigestResult(NamedTuple):
    """Result of bundle digest computation."""

    digest: str  # SHA-256 hex digest of bundle
    algorithm: str  # Always "sha256"
    entry_count: int  # Number of files included
    total_bytes: int  # Total size of all files
    entries: tuple[FileEntry, ...]  # All file entries (sorted)


# =============================================================================
# Path Validation (Security Hardening)
# =============================================================================


class PathValidationError(Exception):
    """Raised when a path fails security validation."""

    pass


def validate_path(path: str) -> None:
    """
    Validate a bundle-relative path for security.

    Rejects:
    - Paths containing ".." (directory traversal)
    - Paths containing NUL bytes
    - Paths containing backslashes (non-portable)
    - Paths starting with / (absolute paths)
    - Empty path components
    - Paths exceeding length limits

    Raises:
        PathValidationError: If path fails validation
    """
    if not path:
        raise PathValidationError("Empty path")

    if len(path) > MAX_PATH_LENGTH:
        raise PathValidationError(f"Path exceeds {MAX_PATH_LENGTH} characters: {path[:50]}...")

    if "\x00" in path:
        raise PathValidationError(f"Path contains NUL byte: {repr(path)}")

    if "\\" in path:
        raise PathValidationError(f"Path contains backslash (use / separator): {path}")

    if path.startswith("/"):
        raise PathValidationError(f"Absolute path not allowed: {path}")

    components = path.split("/")
    for component in components:
        if not component:
            raise PathValidationError(f"Empty path component in: {path}")

        if component == "..":
            raise PathValidationError(f"Path traversal (..) not allowed: {path}")

        if component == ".":
            raise PathValidationError(f"Current directory (.) not allowed in path: {path}")

        if len(component) > MAX_PATH_COMPONENT_LENGTH:
            raise PathValidationError(
                "Path component exceeds "
                f"{MAX_PATH_COMPONENT_LENGTH} characters: {component[:50]}..."
            )


def normalize_path(path: str) -> str:
    """
    Normalize a path to canonical form.

    - Converts to forward slashes
    - Applies Unicode NFC normalization
    - Strips leading ./

    Args:
        path: Raw path string

    Returns:
        Normalized path string
    """
    # Convert backslashes to forward slashes
    normalized = path.replace("\\", "/")

    # Apply Unicode NFC normalization
    normalized = unicodedata.normalize("NFC", normalized)

    # Strip leading ./
    while normalized.startswith("./"):
        normalized = normalized[2:]

    return normalized


# =============================================================================
# Exclusion Logic
# =============================================================================


def should_exclude(relative_path: str, excludes: Optional[Set[str]] = None) -> bool:
    """
    Determine if a path should be excluded from digest computation.

    Args:
        relative_path: Bundle-relative path (already normalized)
        excludes: Set of exclusion patterns (uses DEFAULT_EXCLUDES if None)

    Returns:
        True if path should be excluded
    """
    if excludes is None:
        excludes = DEFAULT_EXCLUDES

    # Split into components
    components = relative_path.split("/")

    # Check if any component matches exclusion patterns
    for component in components:
        # Direct match
        if component in excludes:
            return True

        # Attestation prefix match
        for prefix in ATTESTATION_PREFIXES:
            if component.startswith(prefix):
                return True

    return False


# =============================================================================
# File Hashing
# =============================================================================


def hash_file(filepath: Path, chunk_size: int = 65536) -> tuple[str, int]:
    """
    Compute SHA-256 hash of a file.

    Args:
        filepath: Path to file
        chunk_size: Read buffer size

    Returns:
        Tuple of (hex digest, file size in bytes)
    """
    hasher = hashlib.sha256()
    size = 0

    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
            size += len(chunk)

    return hasher.hexdigest(), size


# =============================================================================
# Bundle Enumeration
# =============================================================================


def enumerate_bundle_files(
    bundle_root: Path, excludes: Optional[Set[str]] = None
) -> Iterator[tuple[str, Path]]:
    """
    Enumerate all files in a bundle that should be included in digest.

    Args:
        bundle_root: Path to bundle root directory
        excludes: Set of exclusion patterns

    Yields:
        Tuples of (relative_path, absolute_path)
    """
    bundle_root = bundle_root.resolve()

    for dirpath, dirnames, filenames in os.walk(bundle_root):
        # Get relative directory path
        rel_dir = Path(dirpath).relative_to(bundle_root)
        rel_dir_str = str(rel_dir).replace("\\", "/")
        if rel_dir_str == ".":
            rel_dir_str = ""

        # Filter out excluded directories (modifies dirnames in-place)
        dirnames[:] = [
            d
            for d in dirnames
            if not should_exclude(f"{rel_dir_str}/{d}" if rel_dir_str else d, excludes)
        ]

        # Process files
        for filename in filenames:
            if rel_dir_str:
                rel_path = f"{rel_dir_str}/{filename}"
            else:
                rel_path = filename

            # Normalize path
            rel_path = normalize_path(rel_path)

            # Check exclusion
            if should_exclude(rel_path, excludes):
                continue

            abs_path = Path(dirpath) / filename

            # Skip non-regular files (symlinks, etc.)
            if not abs_path.is_file() or abs_path.is_symlink():
                continue

            yield rel_path, abs_path


# =============================================================================
# Case-Insensitive Duplicate Detection (Security Hardening)
# =============================================================================


def check_case_collisions(paths: list[str]) -> Optional[str]:
    """
    Check for paths that would collide on case-insensitive filesystems.

    Args:
        paths: List of normalized paths

    Returns:
        Error message if collision detected, None otherwise
    """
    seen: dict[str, str] = {}  # lowercase -> original

    for path in paths:
        lower = path.lower()
        if lower in seen:
            return f"Case-insensitive collision detected: '{seen[lower]}' and '{path}'"
        seen[lower] = path

    return None


# =============================================================================
# Entry Formatting
# =============================================================================


def format_entry(entry: FileEntry) -> bytes:
    """
    Format a file entry for digest computation.

    Format: <path>\0sha256:<hex>\0<size>\n

    Args:
        entry: FileEntry to format

    Returns:
        UTF-8 encoded entry bytes
    """
    return f"{entry.path}\x00sha256:{entry.digest}\x00{entry.size}\n".encode("utf-8")


# =============================================================================
# Main Digest Computation
# =============================================================================


def compute_bundle_digest(
    bundle_root: Path, excludes: Optional[Set[str]] = None, check_case_sensitivity: bool = True
) -> BundleDigestResult:
    """
    Compute the canonical SBA bundle digest.

    Args:
        bundle_root: Path to bundle root directory
        excludes: Set of exclusion patterns (uses DEFAULT_EXCLUDES if None)
        check_case_sensitivity: If True, reject bundles with case-colliding paths

    Returns:
        BundleDigestResult with digest and metadata

    Raises:
        PathValidationError: If any path fails validation
        ValueError: If case collision detected (when check enabled)
        FileNotFoundError: If bundle_root doesn't exist
    """
    bundle_root = Path(bundle_root)

    if not bundle_root.exists():
        raise FileNotFoundError(f"Bundle root not found: {bundle_root}")

    if not bundle_root.is_dir():
        raise ValueError(f"Bundle root is not a directory: {bundle_root}")

    # Collect all file entries
    entries: list[FileEntry] = []

    for rel_path, abs_path in enumerate_bundle_files(bundle_root, excludes):
        # Validate path
        validate_path(rel_path)

        # Hash file
        file_digest, file_size = hash_file(abs_path)

        entries.append(FileEntry(path=rel_path, digest=file_digest, size=file_size))

    # Check for case collisions
    if check_case_sensitivity:
        collision = check_case_collisions([e.path for e in entries])
        if collision:
            raise ValueError(collision)

    # Sort entries by path (bytewise UTF-8 order)
    entries.sort(key=lambda e: e.path.encode("utf-8"))

    # Compute bundle digest
    bundle_hasher = hashlib.sha256()
    total_bytes = 0

    for entry in entries:
        bundle_hasher.update(format_entry(entry))
        total_bytes += entry.size

    return BundleDigestResult(
        digest=bundle_hasher.hexdigest(),
        algorithm="sha256",
        entry_count=len(entries),
        total_bytes=total_bytes,
        entries=tuple(entries),
    )


# =============================================================================
# Archive Mode Support
# =============================================================================


def compute_archive_digest(archive_path: Path) -> tuple[str, int]:
    """
    Compute SHA-256 digest of an archive file.

    This is the "archive mode" subject digest - simply the hash
    of the archive file itself.

    Args:
        archive_path: Path to .zip or .tar.gz archive

    Returns:
        Tuple of (hex digest, file size)
    """
    return hash_file(archive_path)


# =============================================================================
# Output Formatting
# =============================================================================


def format_result_json(result: BundleDigestResult) -> str:
    """Format result as JSON for machine consumption."""
    import json

    return json.dumps(
        {
            "bundleDigest": f"sha256:{result.digest}",
            "algorithm": result.algorithm,
            "entryCount": result.entry_count,
            "totalBytes": result.total_bytes,
            "entries": [
                {"path": e.path, "digest": f"sha256:{e.digest}", "size": e.size}
                for e in result.entries
            ],
        },
        indent=2,
    )


def format_result_human(result: BundleDigestResult) -> str:
    """Format result for human consumption."""
    lines = [
        f"Bundle Digest: sha256:{result.digest}",
        f"Files: {result.entry_count}",
        f"Total Size: {result.total_bytes:,} bytes",
        "",
        "Entries:",
    ]

    for entry in result.entries:
        lines.append(f"  {entry.path}")
        lines.append(f"    sha256:{entry.digest} ({entry.size:,} bytes)")

    return "\n".join(lines)


# =============================================================================
# CLI Interface
# =============================================================================


# pragma: no mutate
def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Compute SBA bundle digest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s path/to/skill/           # Compute directory digest
  %(prog)s path/to/skill.zip --archive  # Compute archive digest
  %(prog)s path/to/skill/ --json    # Output as JSON
  %(prog)s path/to/skill/ --verbose # Show all file entries
        """,
    )

    parser.add_argument("path", type=Path, help="Path to skill bundle (directory or archive)")

    parser.add_argument(
        "--archive", action="store_true", help="Treat path as archive file (compute file hash only)"
    )

    parser.add_argument("--json", action="store_true", help="Output as JSON")

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output including all file entries",
    )

    parser.add_argument(
        "--no-case-check", action="store_true", help="Disable case-insensitive collision checking"
    )

    args = parser.parse_args()

    try:
        if args.archive:
            # Archive mode
            digest, size = compute_archive_digest(args.path)
            if args.json:
                import json

                print(json.dumps({"archiveDigest": f"sha256:{digest}", "size": size}, indent=2))
            else:
                print(f"sha256:{digest}")
                if args.verbose:
                    print(f"Size: {size:,} bytes")
        else:
            # Directory mode
            result = compute_bundle_digest(args.path, check_case_sensitivity=not args.no_case_check)

            if args.json:
                print(format_result_json(result))
            elif args.verbose:
                print(format_result_human(result))
            else:
                print(f"sha256:{result.digest}")

        return 0

    except (PathValidationError, ValueError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
