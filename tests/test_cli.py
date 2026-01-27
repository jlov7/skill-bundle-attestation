from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_cli_digest_output(manifest: dict, repo_root: Path) -> None:
    tv1 = manifest["testVectors"]["tv-1-minimal"]
    result = subprocess.run(
        [sys.executable, str(repo_root / "sba_digest.py"), str(repo_root / tv1["path"])],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == tv1["expectedDigest"]


def test_cli_verify_json(repo_root: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(repo_root / "sba_verify.py"),
            str(repo_root / "examples" / "tv-1-attestation.json"),
            "--bundle",
            str(repo_root / "test-vectors" / "tv-1-minimal"),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["passed"] is True
