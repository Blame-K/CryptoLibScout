#!/usr/bin/env python3
"""Generate vSim fingerprints from value-extraction dumps."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "corpus" / "vsim" / "crypto_shared_elf.csv"
DEFAULT_FP_DIR = ROOT / "corpus" / "vsim" / "fingerprints"
DEFAULT_VSIM_HOME = ROOT / "vSim"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--fingerprint-dir", type=Path, default=DEFAULT_FP_DIR)
    parser.add_argument("--vsim-home", type=Path, default=DEFAULT_VSIM_HOME)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--expr-workers", type=int, default=1)
    parser.add_argument("--expr-timeout", type=int, default=30)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    vsim_home = args.vsim_home.resolve()
    sys.path.insert(0, str(vsim_home))
    os.environ["VSIM_HOME"] = str(vsim_home)
    os.environ["PYTHONPATH"] = str(vsim_home)
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/vsim-mpl")

    from utils import dump_pkl, get_logger_for_file, load_pkl
    from src.pool.pool import BinaryPool

    args.fingerprint_dir.mkdir(parents=True, exist_ok=True)
    func_pool_path = str(args.csv) + ".pkl"

    get_logger_for_file(logging.ERROR, "expr_sim")
    get_logger_for_file(logging.ERROR, logname="binary_pool")

    binary_pool = BinaryPool(str(args.csv), str(args.fingerprint_dir))
    if os.path.exists(func_pool_path) and not args.force:
        print(f"[skip] existing function pool: {func_pool_path}")
        load_pkl(func_pool_path)
        return

    func_pool = binary_pool.build_function_pool(
        workers=args.workers,
        expr_vec_workers=args.expr_workers,
        mode="refined",
        expr_timeout=args.expr_timeout,
        force_run=args.force,
    )
    dump_pkl(func_pool, func_pool_path)
    print(f"fingerprints={args.fingerprint_dir}")
    print(f"function_pool={func_pool_path}")


if __name__ == "__main__":
    main()
