#!/usr/bin/env python3
"""Unified CLI wrapper for SBA tools."""

from __future__ import annotations

import importlib
import sys
from typing import List, Optional, Tuple

_COMMANDS: dict[str, Tuple[str, str]] = {
    "digest": ("sba_digest", "Compute bundle digests"),
    "attest": ("sba_attest", "Generate content/audit/approval attestations"),
    "verify": ("sba_verify", "Verify attestations and bundles"),
    "zip": ("sba_zip", "Create deterministic ZIP archives"),
}

_BANNER = r"""
   _____ ____   ___
  / ___// __ \ / _ \
  \__ \/ /_/ // ___/
 ___/ /\____//_/
/____/  Skill Bundle Attestation
""".strip("\n")


def _render_help() -> str:
    lines = [
        _BANNER,
        "",
        "Usage:",
        "  sba <command> [options]",
        "",
        "Commands:",
    ]
    for name, (_, description) in _COMMANDS.items():
        lines.append(f"  {name:<8} {description}")
    lines.extend(
        [
            "",
            "Run: sba <command> --help for command-specific options.",
        ]
    )
    return "\n".join(lines)


def _dispatch(command: str, argv: List[str]) -> int:
    module_name, _ = _COMMANDS[command]
    module = importlib.import_module(module_name)
    if not hasattr(module, "main"):
        print(f"Error: {module_name} has no main()", file=sys.stderr)
        return 2

    old_argv = sys.argv
    sys.argv = [f"sba {command}", *argv]
    try:
        result = module.main()
        return int(result) if result is not None else 0
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 1
    finally:
        sys.argv = old_argv


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in {"-h", "--help"}:
        print(_render_help())
        return 0

    command, *rest = argv
    if command not in _COMMANDS:
        print(f"Unknown command: {command}", file=sys.stderr)
        print(_render_help())
        return 2

    return _dispatch(command, rest)


if __name__ == "__main__":
    sys.exit(main())
