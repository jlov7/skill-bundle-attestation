from __future__ import annotations

import importlib.util
from pathlib import Path

try:
    import sba
except ModuleNotFoundError:
    repo_root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("sba", repo_root / "sba.py")
    if spec is None or spec.loader is None:
        raise
    sba = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sba)


def test_sba_help(capsys):
    assert sba.main(["--help"]) == 0
    captured = capsys.readouterr()
    assert "Usage:" in captured.out
    assert "digest" in captured.out


def test_sba_unknown_command(capsys):
    assert sba.main(["nope"]) == 2
    captured = capsys.readouterr()
    assert "Unknown command" in captured.err
    assert "Usage:" in captured.out


def test_sba_dispatch_help(capsys):
    assert sba.main(["digest", "--help"]) == 0
    captured = capsys.readouterr()
    assert "Compute SBA bundle digest" in captured.out
