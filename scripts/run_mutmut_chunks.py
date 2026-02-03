from __future__ import annotations

import argparse
import configparser
import json
import os
import subprocess
import sys
from pathlib import Path


def _load_paths_to_mutate(config_path: Path | None = None) -> list[str]:
    path = config_path or (Path(__file__).resolve().parents[1] / "setup.cfg")
    config = configparser.ConfigParser()
    config.read(path)
    if "mutmut" not in config or "paths_to_mutate" not in config["mutmut"]:
        raise ValueError(f"mutmut.paths_to_mutate not found in {path}")
    raw = config["mutmut"].get("paths_to_mutate", "")
    paths = [line.strip() for line in raw.splitlines() if line.strip()]
    if not paths:
        raise ValueError(f"No mutation paths found in {path}")
    return paths


def _summarize_mutation_stats(mutants_dir: Path) -> tuple[int, int, int, int]:
    killed = survived = not_run = 0
    meta_files = list(mutants_dir.glob("*.meta"))
    for meta_path in meta_files:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        for _, code in data.get("exit_code_by_key", {}).items():
            if code == 0:
                survived += 1
            elif code == 1:
                killed += 1
            else:
                not_run += 1
    total = killed + survived + not_run
    return total, killed, survived, not_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Run mutmut in module-sized chunks.")
    parser.add_argument("--max-children", type=int, default=None)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    paths = _load_paths_to_mutate()

    for index, path in enumerate(paths, start=1):
        print("=" * 60)
        print(f"Mutmut chunk {index}/{len(paths)}: {path}")
        print("=" * 60)

        env = os.environ.copy()
        env.setdefault("SBA_MUTMUT", "1")
        env["SBA_MUTMUT_PATHS"] = path

        cmd = [sys.executable, "scripts/run_mutmut.py"]
        if args.max_children is not None:
            cmd.extend(["--max-children", str(args.max_children)])

        result = subprocess.run(cmd, cwd=repo_root, env=env, check=False)
        if result.returncode != 0:
            print(f"Chunk failed: {path} (exit {result.returncode})", file=sys.stderr)
            return result.returncode

        total, killed, survived, not_run = _summarize_mutation_stats(repo_root / "mutants")
        print(
            "Mutation stats so far: "
            f"total={total} killed={killed} survived={survived} not_run={not_run}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
