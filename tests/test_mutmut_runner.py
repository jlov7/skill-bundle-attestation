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
