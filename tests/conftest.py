from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

if os.environ.get("SBA_MUTMUT") == "1":
    _main_module = sys.modules.get("__main__")
    _main_spec = getattr(_main_module, "__spec__", None)
    if (
        _main_module is not None
        and _main_spec
        and getattr(_main_spec, "name", None) == "mutmut.__main__"
    ):
        sys.modules.setdefault("mutmut.__main__", _main_module)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    if root.name == "mutants":
        return root.parent
    return root


@pytest.fixture(scope="session")
def manifest(repo_root: Path) -> dict:
    return json.loads((repo_root / "manifest.json").read_text(encoding="utf-8"))
