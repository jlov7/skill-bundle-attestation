# Testing

## Prerequisites
- Python 3.10+ (tested with 3.14)
- `pip`
- Optional: `make`

## Setup
```bash
python3 -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes optional crypto/YAML/Sigstore tooling used by DSSE
signature tests, Sigstore verification, and frontmatter parsing.

For mutation testing:
```bash
python3 -m pip install -r requirements-strict.txt
```

## Run the full verification suite
```bash
make verify
```

This runs:
- `ruff` (lint + format check)
- `mypy` (type checking)
- `pytest` (unit + integration)
- `scripts/eval_invariants.py` (invariant checks; JSON output)
- `ci_validate.py` (schema + vector validation)

## Mutation testing (strict)
```bash
make verify-strict
```

`verify-strict` runs `mutmut` using `setup.cfg` and can take a while. It
invokes `scripts/run_mutmut_chunks.py`, which executes mutation testing in
per-module chunks for visible progress and resumability. Each chunk uses
`scripts/run_mutmut.py`, which runs pytest in subprocesses and seeds all mutants
with the full test list to avoid forking after threads (improves stability on
macOS/Python 3.14 at the cost of longer runtimes).
The Makefile sets `SBA_MUTMUT=1` so the runtime patch only applies to mutation
runs.
`verify-strict` also runs `scripts/mutation_guard.py` to enforce mutation
thresholds from `mutation-baseline.json`.

If mutation runs still report segfaults under Python 3.14, run mutmut with a
stable interpreter (e.g., Python 3.12/3.13) by setting `PYTHON` or invoking the
script directly:
```bash
PYTHON=python3.12 make verify-strict
# or
SBA_MUTMUT=1 python3.12 scripts/run_mutmut_chunks.py
SBA_MUTMUT=1 python3.12 -m mutmut results
```

You can also tune parallelism to improve stability or speed:
```bash
MUTMUT_MAX_CHILDREN=1 make verify-strict
```

Per-mutant pytest timeouts prevent hangs in pathological mutants. Override or
disable if needed:
```bash
SBA_MUTMUT_TIMEOUT=300 make verify-strict
SBA_MUTMUT_TIMEOUT=0 make verify-strict
```

For debugging a single module, override mutation paths:
```bash
SBA_MUTMUT_PATHS=sba_digest.py make verify-strict
```

To update the mutation baseline after an intentional test expansion:
```bash
python3 scripts/mutation_guard.py --update-baseline
```

## Individual commands
```bash
python3 -m pytest
python3 -m ruff check .
python3 -m ruff format --check .
python3 -m mypy .
python3 scripts/eval_invariants.py
python3 ci_validate.py
```

## Security and SBOM
```bash
make security
```

This runs:
- `pip-audit` against `requirements-dev.lock` and `requirements-strict.lock`
- `cyclonedx-py` to generate a reproducible SBOM at `artifacts/sbom-dev.json`

To refresh lockfiles after changing dependencies:
```bash
make lock
```
