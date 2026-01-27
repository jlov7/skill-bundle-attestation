#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CycloneDX SBOM.")
    parser.add_argument(
        "--requirements",
        default="requirements-dev.lock",
        help="Requirements file to use for SBOM input.",
    )
    parser.add_argument(
        "--output",
        default="artifacts/sbom-dev.json",
        help="Output SBOM file path.",
    )
    args = parser.parse_args()

    if find_spec("cyclonedx_py") is None:
        print(
            "Error: cyclonedx-py not found. Install with: pip install cyclonedx-bom",
            file=sys.stderr,
        )
        return 1

    requirements_path = Path(args.requirements)
    if not requirements_path.exists():
        fallback = Path("requirements-dev.txt")
        if fallback.exists():
            requirements_path = fallback

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "cyclonedx_py",
        "requirements",
        str(requirements_path),
        "--pyproject",
        "pyproject.toml",
        "--mc-type",
        "application",
        "--output-reproducible",
        "--output-file",
        str(output),
    ]
    env = os.environ.copy()
    env.setdefault("PYTHONWARNINGS", "ignore::UserWarning:cyclonedx.model.bom")
    result = subprocess.run(cmd, check=False, env=env)
    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
