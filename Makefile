PYTHON ?= python3
MUTMUT_MAX_CHILDREN ?= 1

.PHONY: verify verify-strict lint typecheck test evals sbom audit security lock

verify: lint typecheck test evals
	$(PYTHON) ci_validate.py

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

typecheck:
	$(PYTHON) -m mypy .

test:
	$(PYTHON) -m pytest

evals:
	$(PYTHON) scripts/eval_invariants.py

sbom:
	$(PYTHON) scripts/generate_sbom.py

audit:
	$(PYTHON) -m pip_audit -r requirements-dev.lock
	$(PYTHON) -m pip_audit -r requirements-strict.lock

security: audit sbom

lock:
	$(PYTHON) -m piptools compile --strip-extras --output-file requirements-dev.lock requirements-dev.txt
	$(PYTHON) -m piptools compile --strip-extras --output-file requirements-strict.lock requirements-strict.txt

verify-strict: verify
	SBA_MUTMUT=1 $(PYTHON) scripts/run_mutmut_chunks.py --max-children $(MUTMUT_MAX_CHILDREN)
	SBA_MUTMUT=1 $(PYTHON) -m mutmut results
	$(PYTHON) scripts/mutation_guard.py
