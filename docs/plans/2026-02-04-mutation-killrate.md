# Mutation Kill-Rate Improvement Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Raise mutation kill rate above baseline by adding targeted tests that kill at least 10 surviving mutants in critical security/correctness paths.

**Architecture:** Use existing mutation results to identify high-impact surviving mutants, add focused tests to cover invariants, and confirm each target mutant is killed with `mutmut run` for that mutant. Avoid relaxing baseline thresholds.

**Tech Stack:** Python, pytest, mutmut

---

### Task 1: Sync mutation results for triage

**Files:**
- None (data sync only)

**Step 1: Copy existing mutation metadata into worktree**

Run:
```bash
rsync -a --delete /Users/jasonlovell/AI/White\ Papers/SBA/mutants/ /Users/jasonlovell/AI/White\ Papers/SBA/.worktrees/mutmut-killrate/mutants/
```
Expected: `mutants/*.meta` present in worktree.

**Step 2: Confirm overall stats**

Run:
```bash
python3 - <<'PY'
import json
from pathlib import Path
for path in sorted(Path('mutants').glob('*.meta')):
    data=json.loads(path.read_text())
    exit_codes=data.get('exit_code_by_key',{})
    total=len(exit_codes)
    done=sum(1 for v in exit_codes.values() if v is not None)
    killed=sum(1 for v in exit_codes.values() if v==1)
    survived=sum(1 for v in exit_codes.values() if v==0)
    other=done-killed-survived
    print(path.name, 'total', total, 'done', done, 'killed', killed, 'survived', survived, 'other', other)
PY
```
Expected: all `done == total`.

### Task 2: Select target survivors

**Files:**
- None (analysis)

**Step 1: List survivors**

Run:
```bash
python3 -m mutmut results > /tmp/mutmut-survivors.txt
```
Expected: survivors listed in `/tmp/mutmut-survivors.txt`.

**Step 2: Prioritize 10–15 survivors in critical modules**

Focus on:
- `sba_digest` path validation and digest determinism
- `sba_archive` archive root safety
- `sba_crypto` signature verification helpers
- `sba_verify` verification rules

Document chosen mutants in a short checklist inside `docs/plans/2026-02-04-mutation-killrate.md` under a new “Selected Mutants” section.

**Selected Mutants**
- `sba_digest.x_validate_path__mutmut_2` (empty path message integrity)
- `sba_digest.x_validate_path__mutmut_3` (empty path message integrity)
- `sba_digest.x_validate_path__mutmut_4` (empty path message integrity)
- `sba_digest.x_validate_path__mutmut_5` (empty path message integrity)
- `sba_digest.x_validate_path__mutmut_15` (backslash error messaging)
- `sba_digest.x_validate_path__mutmut_17` (absolute path error messaging)
- `sba_digest.x_validate_path__mutmut_23` (empty component error messaging)
- `sba_digest.x_validate_path__mutmut_26` (traversal error messaging)
- `sba_digest.x_validate_path__mutmut_29` (current directory error messaging)
- `sba_digest.x_format_result_json__mutmut_8` (algorithm field presence)
- `sba_digest.x_format_result_json__mutmut_13` (totalBytes field presence)
- `sba_digest.x_format_result_json__mutmut_14` (totalBytes field presence)
- `sba_digest.x_format_result_json__mutmut_17` (entries field presence)

### Task 3: Add tests to kill each selected mutant (TDD)

**Files:**
- Modify: `tests/test_digest.py`
- Modify: `tests/test_archive_security.py`
- Modify: `tests/test_crypto.py`
- Modify: `tests/test_verify.py`

For each selected mutant:

**Step 1: Inspect the mutant**

Run:
```bash
python3 -m mutmut show <mutant_name>
```
Expected: view of mutated line(s).

**Step 2: Write the failing test**

Add or extend a test that should fail under the mutant’s behavior. Keep it minimal and focused on the invariant.

**Step 3: Verify the mutant is killed (RED)**

Run:
```bash
SBA_MUTMUT=1 python3 -m mutmut run <mutant_name>
```
Expected: mutant is killed (test fails for mutated code).

**Step 4: Ensure test passes on clean code (GREEN)**

Run:
```bash
python3 -m pytest tests/<relevant_test_file>.py -v
```
Expected: test passes.

**Step 5: Refactor if needed**

Only if required; keep tests green.

Repeat Steps 1–5 for all selected mutants.

### Task 4: Re-run mutation guard and verification

**Files:**
- None

**Step 1: Re-run mutation guard**

Run:
```bash
python3 scripts/mutation_guard.py
```
Expected: pass (kill rate and survivors within thresholds).

**Step 2: Full verify**

Run:
```bash
PYTHON="/Users/jasonlovell/AI/White Papers/SBA/.venv/bin/python" make verify
```
Expected: all checks pass.

### Task 5: Commit

**Files:**
- Modify: test files updated
- Modify: `docs/plans/2026-02-04-mutation-killrate.md` (Selected Mutants section)

**Step 1: Commit**

```bash
git add tests/test_*.py docs/plans/2026-02-04-mutation-killrate.md

git commit -m "test: increase mutation coverage for critical paths"
```
