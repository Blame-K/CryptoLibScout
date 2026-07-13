#!/usr/bin/env python3
"""Remove duplicate metadata records and optionally delete duplicate artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METADATA = ROOT / "corpus" / "metadata" / "samples.jsonl"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--delete-artifacts", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    records = []
    with args.metadata.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    seen = set()
    kept = []
    removed = []
    for record in records:
        key = (
            record["library"],
            record["version"],
            record["compiler"],
            record["opt"],
            record["linkage"],
            record["stripped"],
            record["artifact_sha256"],
        )
        if key in seen:
            removed.append(record)
            continue
        seen.add(key)
        kept.append(record)

    tmp = args.metadata.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for record in kept:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    tmp.replace(args.metadata)

    if args.delete_artifacts:
        for record in removed:
            artifact = args.root / record["artifact"]
            if artifact.exists():
                artifact.unlink()

    print(f"kept={len(kept)} removed={len(removed)}")


if __name__ == "__main__":
    main()
