from __future__ import annotations

import multiprocessing as _mp
import os


def _patch_start_method() -> None:
    """Avoid mutmut start-method crashes without affecting normal runs."""
    if os.environ.get("SBA_MUTMUT") != "1":
        return

    original = _mp.set_start_method

    def _safe_set_start_method(method: str, force: bool = False) -> None:
        try:
            original(method, force=force)
        except RuntimeError as exc:
            if "context has already been set" in str(exc):
                return
            raise

    if _mp.set_start_method is not _safe_set_start_method:
        _mp.set_start_method = _safe_set_start_method  # type: ignore[assignment]


_patch_start_method()
