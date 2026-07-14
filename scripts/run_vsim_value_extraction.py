#!/usr/bin/env python3
"""Run vSim value extraction for binaries listed in a vSim CSV file."""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "corpus" / "vsim" / "crypto_shared_elf.csv"
DEFAULT_VSIM_HOME = ROOT / "vSim"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--vsim-home", type=Path, default=DEFAULT_VSIM_HOME)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--index", type=int, help="Run only one 0-based CSV row index.")
    parser.add_argument("--force", action="store_true", help="Delete an existing dump dir before extraction.")
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def has_existing_dump(path: Path) -> bool:
    return path.exists() and any(path.glob("*.pkl"))


def file_md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cache_path_for(row: dict[str, str]) -> Path:
    binary = Path(row["binary"])
    return Path(row["cache_dir"]) / f"{binary.name}_{file_md5(binary)}.pkl"


def main() -> None:
    args = parse_args()
    rows = read_rows(args.csv)
    if args.index is not None:
        rows = [rows[args.index]]
    elif args.limit is not None:
        rows = rows[: args.limit]

    env = os.environ.copy()
    env["VSIM_HOME"] = str(args.vsim_home.resolve())
    env["PYTHONPATH"] = str(args.vsim_home.resolve())
    env.setdefault("MPLCONFIGDIR", "/tmp/vsim-mpl")

    analyzer = args.vsim_home / "src" / "bin_analyzer.py"
    for idx, row in enumerate(rows, start=1):
        dump_dir = Path(row["dump_dir"])
        if args.force and dump_dir.exists():
            for p in dump_dir.glob("*.pkl"):
                p.unlink()
        dump_dir.mkdir(parents=True, exist_ok=True)
        Path(row["cache_dir"]).mkdir(parents=True, exist_ok=True)
        if args.force:
            cache_path = cache_path_for(row)
            cache_path.unlink(missing_ok=True)
            cache_path.with_name(f"{cache_path.stem}_failed.json").unlink(missing_ok=True)
        if has_existing_dump(dump_dir) and not args.force:
            print(f"[skip {idx}/{len(rows)}] existing dump: {dump_dir}")
            continue
        cmd = [
            sys.executable,
            str(analyzer),
            "--bin",
            row["binary"],
            "--dump",
            row["dump_dir"],
            "--cache",
            row["cache_dir"],
            "--loglevel",
            "0",
            "--workers",
            str(args.workers),
        ]
        ida_pkl = row.get("ida_pkl", "").strip()
        if ida_pkl:
            ida_pkl_path = Path(ida_pkl)
            if not ida_pkl_path.exists():
                raise FileNotFoundError(f"IDA pickle not found for {row['binary']}: {ida_pkl_path}")
            cmd.extend(["--ida", str(ida_pkl_path)])
        print(f"[extract {idx}/{len(rows)}] {row['binary']}")
        subprocess.run(cmd, cwd=args.vsim_home, env=env, check=True)


if __name__ == "__main__":
    main()
