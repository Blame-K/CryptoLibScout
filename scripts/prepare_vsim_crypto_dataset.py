#!/usr/bin/env python3
"""Prepare vSim CSV inputs from the collected crypto corpus metadata."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METADATA = ROOT / "corpus" / "metadata" / "samples.jsonl"
DEFAULT_OUT_DIR = ROOT / "corpus" / "vsim"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--csv-name", default="crypto_shared_elf.csv")
    parser.add_argument("--include-stripped", action="store_true")
    parser.add_argument("--linkage", choices=["shared", "static", "all"], default="shared")
    return parser.parse_args()


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except FileNotFoundError:
        return False


def clean_component(filename: str) -> str:
    name = filename
    name = re.sub(r"\.so(\.\d+)*$", "", name)
    name = re.sub(r"\.a$", "", name)
    return name


def sample_key(record: dict) -> str:
    artifact = Path(record["artifact"])
    parts = [
        record["library"],
        record["version"],
        record["compiler"],
        record["opt"],
        record["linkage"],
        "stripped" if record["stripped"] else "unstripped",
        artifact.name,
        record["artifact_sha256"][:12],
    ]
    return "__".join(re.sub(r"[^A-Za-z0-9_.-]+", "_", p) for p in parts)


def bin_id(record: dict) -> str:
    component = clean_component(Path(record["artifact"]).name)
    return ":".join(
        [
            record["library"],
            record["version"],
            component,
        ]
    )


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    dump_root = args.out_dir / "dump"
    cache_root = args.out_dir / "cache"
    fp_root = args.out_dir / "fingerprints"
    dump_root.mkdir(exist_ok=True)
    cache_root.mkdir(exist_ok=True)
    fp_root.mkdir(exist_ok=True)

    csv_path = args.out_dir / args.csv_name
    output_stem = Path(args.csv_name).with_suffix("").name
    selected_jsonl = args.out_dir / f"{output_stem}.selected.jsonl"
    skipped_jsonl = args.out_dir / f"{output_stem}.skipped.jsonl"

    selected = []
    skipped = []
    with args.metadata.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            record = json.loads(line)
            artifact = ROOT / record["artifact"]
            reason = None
            if args.linkage != "all" and record["linkage"] != args.linkage:
                reason = f"linkage is {record['linkage']}"
            elif record["stripped"] and not args.include_stripped:
                reason = "stripped sample omitted by default"
            elif not is_elf(artifact):
                reason = "not an ELF file; static .a archives need harness binaries"

            if reason:
                skipped.append({"reason": reason, **record})
                continue

            key = sample_key(record)
            row = {
                "binary": str(artifact.resolve()),
                "dump_dir": str((dump_root / key).resolve()),
                "cache_dir": str(cache_root.resolve()),
                "bin_id": bin_id(record),
            }
            selected.append({**record, "sample_key": key, **row})

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["binary", "dump_dir", "cache_dir", "bin_id"])
        writer.writeheader()
        writer.writerows({k: r[k] for k in ["binary", "dump_dir", "cache_dir", "bin_id"]} for r in selected)

    with selected_jsonl.open("w", encoding="utf-8") as f:
        for record in selected:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    with skipped_jsonl.open("w", encoding="utf-8") as f:
        for record in skipped:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    print(f"selected={len(selected)} skipped={len(skipped)}")
    print(f"csv={csv_path}")
    print(f"fingerprint_dir={fp_root}")


if __name__ == "__main__":
    main()
