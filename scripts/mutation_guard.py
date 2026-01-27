#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class MutationStats:
    total: int
    killed: int
    survived: int
    not_run: int

    @property
    def kill_rate(self) -> float:
        return (self.killed / self.total) if self.total else 0.0


def _load_stats(mutants_dir: Path) -> MutationStats:
    if not mutants_dir.exists():
        raise FileNotFoundError(f"Mutants directory not found: {mutants_dir}")

    killed = survived = not_run = 0
    meta_files = list(mutants_dir.glob("*.meta"))
    if not meta_files:
        raise FileNotFoundError(f"No mutmut metadata found in {mutants_dir}")

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
    return MutationStats(total=total, killed=killed, survived=survived, not_run=not_run)


def _load_baseline(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_baseline(path: Path, stats: MutationStats) -> None:
    baseline = {
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": stats.total,
        "killed": stats.killed,
        "survived": stats.survived,
        "notRun": stats.not_run,
        "minKillRate": round(stats.kill_rate, 4),
        "maxSurvivors": stats.survived,
        "maxNotRun": stats.not_run,
    }
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def _resolve_threshold(value: Optional[float], fallback: Optional[float]) -> Optional[float]:
    return value if value is not None else fallback


def main() -> int:
    parser = argparse.ArgumentParser(description="Guard mutation testing thresholds.")
    parser.add_argument(
        "--mutants-dir",
        type=Path,
        default=Path("mutants"),
        help="Directory containing mutmut metadata",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("mutation-baseline.json"),
        help="Baseline file with thresholds",
    )
    parser.add_argument("--update-baseline", action="store_true", help="Write baseline and exit")
    parser.add_argument("--min-kill-rate", type=float, default=None)
    parser.add_argument("--max-survivors", type=int, default=None)
    parser.add_argument("--max-not-run", type=int, default=None)
    args = parser.parse_args()

    stats = _load_stats(args.mutants_dir)

    if args.update_baseline:
        _write_baseline(args.baseline, stats)
        print(f"Wrote mutation baseline to {args.baseline}")
        print(
            f"Totals: total={stats.total} killed={stats.killed} "
            f"survived={stats.survived} not_run={stats.not_run} "
            f"kill_rate={stats.kill_rate:.3f}"
        )
        return 0

    baseline = {}
    if args.baseline.exists():
        baseline = _load_baseline(args.baseline)

    min_kill_rate = _resolve_threshold(args.min_kill_rate, baseline.get("minKillRate"))
    max_survivors = _resolve_threshold(args.max_survivors, baseline.get("maxSurvivors"))
    max_not_run = _resolve_threshold(args.max_not_run, baseline.get("maxNotRun"))

    if min_kill_rate is None and max_survivors is None and max_not_run is None:
        print("No mutation thresholds configured. Provide --min-kill-rate or a baseline file.")
        return 2

    failures = []
    if min_kill_rate is not None and stats.kill_rate < float(min_kill_rate):
        failures.append(f"kill_rate {stats.kill_rate:.3f} < required {float(min_kill_rate):.3f}")
    if max_survivors is not None and stats.survived > int(max_survivors):
        failures.append(f"survivors {stats.survived} > allowed {int(max_survivors)}")
    if max_not_run is not None and stats.not_run > int(max_not_run):
        failures.append(f"not_run {stats.not_run} > allowed {int(max_not_run)}")

    print(
        f"Mutation stats: total={stats.total} killed={stats.killed} "
        f"survived={stats.survived} not_run={stats.not_run} "
        f"kill_rate={stats.kill_rate:.3f}"
    )

    if failures:
        print("Mutation thresholds failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Mutation thresholds satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
