from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

import mutmut
import mutmut.__main__ as mutmut_main


class _NoThread:
    def __init__(self, *args, **kwargs) -> None:
        self._target = kwargs.get("target")

    def start(self) -> None:
        # Avoid starting background threads before fork (macOS safety).
        return


class _SubprocessPytestRunner(mutmut_main.PytestRunner):
    def execute_pytest(self, params: list[str], **kwargs):
        if kwargs.get("plugins"):
            # Stats collection is disabled in this runner.
            return 0

        timeout = _resolve_timeout_seconds()
        args = ["-m", "pytest", "--rootdir=.", "--tb=native", *params, *self._pytest_add_cli_args]
        if mutmut.config.debug:
            args = ["-vv", *args]
            print("python", *args)

        env = os.environ.copy()
        env.setdefault("SBA_MUTMUT", "1")
        env.setdefault("MUTANT_UNDER_TEST", "")
        try:
            result = subprocess.run(
                [sys.executable, *args],
                env=env,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            mutant = env.get("MUTANT_UNDER_TEST") or "unknown-mutant"
            print(f"mutmut timeout after {timeout:.0f}s for {mutant}", file=sys.stderr)
            return 1
        return int(result.returncode)


def _resolve_timeout_seconds() -> float | None:
    raw = os.environ.get("SBA_MUTMUT_TIMEOUT", "").strip()
    if not raw:
        return 120.0
    try:
        value = float(raw)
    except ValueError:
        return 120.0
    if value <= 0:
        return None
    return value


def _sync_tests() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    tests_src = repo_root / "tests"
    mutants_root = repo_root / "mutants"
    tests_dst = mutants_root / "tests"

    mutants_root.mkdir(parents=True, exist_ok=True)
    if tests_dst.exists():
        shutil.rmtree(tests_dst)
    shutil.copytree(tests_src, tests_dst)


def _collect_all_tests() -> list[str]:
    _sync_tests()
    env = os.environ.copy()
    env.setdefault("SBA_MUTMUT", "1")
    env.setdefault("MUTANT_UNDER_TEST", "")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only"],
        cwd="mutants",
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Failed to collect tests for mutmut.\n"
            f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
        )
    return [line.strip() for line in result.stdout.splitlines() if "::" in line]


def _seed_all_tests() -> None:
    tests = _collect_all_tests()
    mutmut.tests_by_mangled_function_name.clear()
    mutmut.duration_by_test = {test: 0.0 for test in tests}

    original_collect = mutmut_main.collect_source_file_mutation_data

    def _collect_and_seed(*, mutant_names):
        mutants, source_file_mutation_data_by_path = original_collect(mutant_names=mutant_names)
        for _, mutant_name, _ in mutants:
            mangled = mutmut_main.mangled_name_from_mutant_name(mutant_name)
            mutmut.tests_by_mangled_function_name[mangled].update(tests)
        return mutants, source_file_mutation_data_by_path

    mutmut_main.collect_source_file_mutation_data = _collect_and_seed

    def _no_stats(_runner):
        return None

    mutmut_main.collect_or_load_stats = _no_stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Run mutmut without background threads.")
    parser.add_argument("--max-children", type=int, default=None)
    parser.add_argument("mutant_names", nargs="*")
    args = parser.parse_args()

    mutmut_main.Thread = _NoThread
    mutmut_main.PytestRunner = _SubprocessPytestRunner
    mutmut_main.setproctitle = lambda *_args, **_kwargs: None
    _seed_all_tests()

    mutmut_main._run(args.mutant_names, args.max_children)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
