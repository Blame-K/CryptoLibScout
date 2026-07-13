#!/usr/bin/env python3
"""Prepare vSim CSV inputs for target binaries."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = ROOT / "corpus" / "vsim" / "targets"
DEFAULT_CSV = ROOT / "corpus" / "vsim" / "crypto_targets.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="+", type=Path)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_OUT_DIR / "cache")
    parser.add_argument("--bin-id-prefix", default="target")
    return parser.parse_args()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def clean_name(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)


def is_elf(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(4) == b"\x7fELF"


def main() -> None:
    args = parse_args()
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    dump_root = args.out_dir / "dump"
    dump_root.mkdir(parents=True, exist_ok=True)

    selected_jsonl = args.csv.with_suffix(".selected.jsonl")
    rows = []
    selected = []
    skipped = []

    for binary in args.binary:
        path = binary.expanduser().resolve()
        if not path.exists():
            skipped.append({"binary": str(path), "reason": "missing"})
            continue
        if not is_elf(path):
            skipped.append({"binary": str(path), "reason": "not an ELF file"})
            continue
        digest = sha256(path)
        name = clean_name(path)
        key = f"{name}__{digest[:12]}"
        row = {
            "binary": str(path),
            "dump_dir": str((dump_root / key).resolve()),
            "cache_dir": str(args.cache_dir.resolve()),
            "bin_id": f"{args.bin_id_prefix}:{name}",
        }
        rows.append(row)
        selected.append(
            {
                **row,
                "artifact_sha256": digest,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    with args.csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["binary", "dump_dir", "cache_dir", "bin_id"])
        writer.writeheader()
        writer.writerows(rows)

    with selected_jsonl.open("w", encoding="utf-8") as f:
        for record in selected:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    skipped_jsonl = args.csv.with_suffix(".skipped.jsonl")
    with skipped_jsonl.open("w", encoding="utf-8") as f:
        for record in skipped:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    print(f"selected={len(selected)} skipped={len(skipped)}")
    print(f"csv={args.csv}")
    print(f"dump_root={dump_root}")


if __name__ == "__main__":
    main()
