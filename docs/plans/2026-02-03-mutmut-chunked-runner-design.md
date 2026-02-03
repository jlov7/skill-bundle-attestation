# Mutmut Chunked Runner Design

**Goal:** Make strict mutation testing deterministic, resumable, and visibly progressing without weakening coverage.

**Context:** The current `scripts/run_mutmut.py` runs the full test suite for every mutant to avoid macOS fork/thread instability. This is defensible but extremely slow and offers minimal progress feedback, which looks like a “freeze.” We need a way to keep strictness while improving observability and resumability.

**Approach:** Add a new driver, `scripts/run_mutmut_chunks.py`, that runs mutation testing in module-sized chunks based on `setup.cfg`’s `paths_to_mutate`. The driver will:

- Read `setup.cfg` and extract the `mutmut.paths_to_mutate` list.
- Iterate per-path, running the existing `scripts/run_mutmut.py` in a subprocess with a scoped environment variable (for example, `SBA_MUTMUT_PATHS=...`) that temporarily overrides mutmut’s target paths.
- Print clear start/end markers and a summary after each chunk by reading `mutants/*.meta`.
- Preserve strictness: each mutant still runs the full test set (as today).
- Preserve resumability: existing mutmut metadata is reused, and completed mutants are skipped automatically.

**Data Flow:** The chunk runner sets environment variables and invokes `run_mutmut.py`; the runner uses these to set `mutmut.config.paths_to_mutate` before generating mutants. Mutation results continue to be written to `mutants/*.meta` and `mutants/mutmut-stats.json`, which the chunk runner reads for progress reporting.

**Error Handling:** If a chunk fails, the script exits non-zero and prints the failing path. The operator can rerun the same command to resume (mutmut skips finished mutants). A per-mutant pytest timeout is enforced via `SBA_MUTMUT_TIMEOUT` to prevent hangs.

**Testing:**
- Run `make verify` to ensure standard checks are intact.
- Run the new chunked strict command (wired to `make verify-strict`) and confirm that mutation stats match the existing baseline thresholds.
- Validate that rerunning the chunked command completes quickly due to skipping already-checked mutants.
