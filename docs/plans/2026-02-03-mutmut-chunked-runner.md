# Mutmut Chunked Runner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a strict, chunked mutation-testing runner with clear progress and resumability, without weakening existing mutation rigor.

**Architecture:** Extend `scripts/run_mutmut.py` with small, testable helpers (timeout parsing and optional path override). Add a new `scripts/run_mutmut_chunks.py` driver that reads `setup.cfg`’s `mutmut.paths_to_mutate` and runs `run_mutmut.py` per path, reporting progress. Wire `make verify-strict` to the chunked driver and document usage.

**Tech Stack:** Python 3.10+, pytest, mutmut, configparser, Makefile.

---

### Task 1: Add unit tests for new helpers

**Files:**
- Create: `tests/test_mutmut_runner.py`

**Step 1: Write failing tests**
```python
import os

from scripts import run_mutmut


def test_resolve_timeout_default():
    os.environ.pop("SBA_MUTMUT_TIMEOUT", None)
    assert run_mutmut._resolve_timeout_seconds() == 120.0


def test_resolve_timeout_override():
    os.environ["SBA_MUTMUT_TIMEOUT"] = "300"
    assert run_mutmut._resolve_timeout_seconds() == 300.0


def test_resolve_timeout_disable():
    os.environ["SBA_MUTMUT_TIMEOUT"] = "0"
    assert run_mutmut._resolve_timeout_seconds() is None
```

**Step 2: Run test to verify it fails**
Run: `PYTHON=.venv/bin/python pytest tests/test_mutmut_runner.py -v`
Expected: FAIL because `_resolve_timeout_seconds` does not exist yet.

**Step 3: Write minimal implementation**
Add `_resolve_timeout_seconds()` to `scripts/run_mutmut.py` and import it in test.

**Step 4: Run test to verify it passes**
Run: `PYTHON=.venv/bin/python pytest tests/test_mutmut_runner.py -v`
Expected: PASS

**Step 5: Commit**
```bash
git add tests/test_mutmut_runner.py scripts/run_mutmut.py
git commit -m "test: cover mutmut timeout parsing"
```

---

### Task 2: Add optional mutation path override

**Files:**
- Modify: `scripts/run_mutmut.py`

**Step 1: Write failing test**
Extend `tests/test_mutmut_runner.py`:
```python
from scripts import run_mutmut


def test_resolve_paths_override(tmp_path):
    os.environ["SBA_MUTMUT_PATHS"] = "sba_digest.py,sba_verify.py"
    assert run_mutmut._resolve_mutation_paths() == ["sba_digest.py", "sba_verify.py"]
```

**Step 2: Run test to verify it fails**
Run: `PYTHON=.venv/bin/python pytest tests/test_mutmut_runner.py::test_resolve_paths_override -v`
Expected: FAIL because `_resolve_mutation_paths` does not exist.

**Step 3: Write minimal implementation**
Implement `_resolve_mutation_paths()` in `scripts/run_mutmut.py` that:
- Reads `SBA_MUTMUT_PATHS`
- Splits by comma
- Strips whitespace
- Returns `None` if empty

Use it in `main()` to set `mutmut.config.paths_to_mutate` when provided.

**Step 4: Run test to verify it passes**
Run: `PYTHON=.venv/bin/python pytest tests/test_mutmut_runner.py::test_resolve_paths_override -v`
Expected: PASS

**Step 5: Commit**
```bash
git add tests/test_mutmut_runner.py scripts/run_mutmut.py
git commit -m "feat: allow mutmut path overrides"
```

---

### Task 3: Implement chunked runner driver

**Files:**
- Create: `scripts/run_mutmut_chunks.py`
- Test: `tests/test_mutmut_runner.py`

**Step 1: Write failing test**
Extend `tests/test_mutmut_runner.py`:
```python
from scripts import run_mutmut_chunks


def test_load_paths_to_mutate():
    paths = run_mutmut_chunks._load_paths_to_mutate()
    assert "sba_digest.py" in paths
    assert "sba_verify.py" in paths
```

**Step 2: Run test to verify it fails**
Run: `PYTHON=.venv/bin/python pytest tests/test_mutmut_runner.py::test_load_paths_to_mutate -v`
Expected: FAIL because `run_mutmut_chunks` does not exist.

**Step 3: Write minimal implementation**
Create `scripts/run_mutmut_chunks.py` with:
- `_load_paths_to_mutate()` reading `setup.cfg` via `configparser`
- `main()` that loops over paths and runs `scripts/run_mutmut.py` per path via subprocess
- Clear progress logs for each chunk
- Propagate exit code on failure

**Step 4: Run test to verify it passes**
Run: `PYTHON=.venv/bin/python pytest tests/test_mutmut_runner.py::test_load_paths_to_mutate -v`
Expected: PASS

**Step 5: Commit**
```bash
git add scripts/run_mutmut_chunks.py tests/test_mutmut_runner.py
git commit -m "feat: add chunked mutmut runner"
```

---

### Task 4: Wire `make verify-strict` and docs

**Files:**
- Modify: `Makefile`
- Modify: `TESTING.md`

**Step 1: Update Makefile**
Change `verify-strict` to invoke the chunked runner:
```
SBA_MUTMUT=1 $(PYTHON) scripts/run_mutmut_chunks.py --max-children $(MUTMUT_MAX_CHILDREN)
```

**Step 2: Update documentation**
Add a section in `TESTING.md` explaining chunked mutation runs, resumability, and env vars (`SBA_MUTMUT_TIMEOUT`, `SBA_MUTMUT_PATHS`).

**Step 3: Run tests to verify**
Run: `PYTHON=.venv/bin/python make verify`
Expected: PASS

**Step 4: Commit**
```bash
git add Makefile TESTING.md
git commit -m "docs: wire chunked mutation runner"
```

---

### Task 5: Full verification

**Step 1: Run strict verification**
Run: `PYTHON=.venv/bin/python MUTMUT_MAX_CHILDREN=1 SBA_MUTMUT_TIMEOUT=120 make verify-strict`
Expected: Long run, but with chunked progress; completes and mutation guard passes.

**Step 2: Report results**
Summarize:
- `make verify`
- `make verify-strict`
- Mutation stats and thresholds

---
