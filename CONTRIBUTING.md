# Contributing

Thanks for helping improve SBA.

## Development setup
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

## Verification
```bash
make verify
```

## Code style
- Python formatting and linting are enforced via `ruff`.
- Keep public CLI behavior stable and add tests for changes.

## Tests
- Unit + integration tests live in `tests/`.
- Invariant checks live in `scripts/eval_invariants.py`.

## Pull request checklist
- [ ] `make verify` passes
- [ ] New behavior includes tests
- [ ] Public CLI changes documented in `README.md`
