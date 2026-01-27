#!/usr/bin/env python3
"""Create a deterministic ZIP archive from a bundle directory.

This is primarily useful for *test vectors* where the archive itself is part of
the vector and therefore must be reproducible.

Determinism settings:
  - All file entries use a fixed timestamp (2025-01-01 00:00:00).
  - Files are added in lexicographic order of their normalized POSIX paths.
  - Permissions are fixed to 0644.
  - ZIP uses ZIP_STORED (no compression) to avoid any cross-environment
    differences in deflate implementations.

Note: ZIP files are byte-for-byte stable only if the input file bytes are identical.
"""

from __future__ import annotations

import argparse
import pathlib
import zipfile

from sba_digest import enumerate_bundle_files


def iter_files(root: pathlib.Path):
    for rel, fpath in enumerate_bundle_files(root):
        yield rel, fpath


def build_zip(bundle_dir: pathlib.Path, out_zip: pathlib.Path) -> None:
    files = sorted(iter_files(bundle_dir), key=lambda t: t[0])

    # Ensure parent exists
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    # NOTE: We intentionally use ZIP_STORED (no compression) for maximal
    # reproducibility across environments.
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_STORED) as zf:
        for rel, fpath in files:
            zi = zipfile.ZipInfo(filename=rel, date_time=(2025, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zi.create_system = 0  # "FAT"; avoids platform-specific permission bits
            # Fixed permissions: -rw-r--r--
            zi.external_attr = (0o644 & 0xFFFF) << 16
            with open(fpath, "rb") as f:
                data = f.read()
            zf.writestr(zi, data)


# pragma: no mutate
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", help="Path to bundle directory")
    ap.add_argument("out_zip", help="Output zip path")
    args = ap.parse_args()

    build_zip(pathlib.Path(args.bundle), pathlib.Path(args.out_zip))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
