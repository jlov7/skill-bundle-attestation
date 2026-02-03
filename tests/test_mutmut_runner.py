import os
from pathlib import Path

from scripts import run_mutmut


def test_resolve_timeout_default(monkeypatch):
    monkeypatch.delenv("SBA_MUTMUT_TIMEOUT", raising=False)
    assert run_mutmut._resolve_timeout_seconds() == 120.0


def test_resolve_timeout_override(monkeypatch):
    monkeypatch.setenv("SBA_MUTMUT_TIMEOUT", "300")
    assert run_mutmut._resolve_timeout_seconds() == 300.0


def test_resolve_timeout_disable(monkeypatch):
    monkeypatch.setenv("SBA_MUTMUT_TIMEOUT", "0")
    assert run_mutmut._resolve_timeout_seconds() is None


def test_resolve_paths_override(monkeypatch):
    monkeypatch.setenv("SBA_MUTMUT_PATHS", "sba_digest.py,sba_verify.py")
    assert run_mutmut._resolve_mutation_paths() == ["sba_digest.py", "sba_verify.py"]


def test_load_paths_to_mutate():
    from scripts import run_mutmut_chunks

    paths = run_mutmut_chunks._load_paths_to_mutate()
    assert "sba_digest.py" in paths
    assert "sba_verify.py" in paths


def test_extend_pythonpath_adds_root():
    env: dict[str, str] = {}
    run_mutmut._extend_pythonpath(env, Path("/tmp/root"))
    assert env["PYTHONPATH"] == "/tmp/root"

    env = {"PYTHONPATH": os.pathsep.join(["/other", "/else"])}
    run_mutmut._extend_pythonpath(env, Path("/tmp/root"))
    assert env["PYTHONPATH"].split(os.pathsep)[0] == "/tmp/root"

    env = {"PYTHONPATH": os.pathsep.join(["/tmp/root", "/other"])}
    run_mutmut._extend_pythonpath(env, Path("/tmp/root"))
    assert env["PYTHONPATH"] == os.pathsep.join(["/tmp/root", "/other"])
