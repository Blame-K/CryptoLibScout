#!/usr/bin/env python3
"""Build OpenSSL static-link harness executables from collected .a archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METADATA = ROOT / "corpus" / "metadata" / "samples.jsonl"
DEFAULT_SOURCE = ROOT / "harness" / "openssl_static_harness.c"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--version", action="append", help="Build only this OpenSSL version; can be repeated.")
    parser.add_argument("--opt", action="append", help="Build only this optimization level; can be repeated.")
    parser.add_argument("--compiler", action="append", help="Build only this compiler label; can be repeated.")
    parser.add_argument("--cc", default="gcc", help="C compiler executable used to build the harness.")
    parser.add_argument("--profile", default="api-smoke", help="Name used in the output path and metadata.")
    parser.add_argument("--whole-archive", action="store_true", help="Link every object from libssl.a/libcrypto.a.")
    parser.add_argument("--force", action="store_true", help="Rebuild existing harness binaries.")
    return parser.parse_args()


def run(cmd: list[str], cwd: Path) -> None:
    print(f"[run] {cwd}: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def load_metadata(path: Path) -> list[dict]:
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compiler_version(compiler: str) -> str:
    try:
        result = subprocess.run(
            [compiler, "--version"], check=True, text=True, capture_output=True
        )
        return result.stdout.splitlines()[0]
    except Exception:
        return "unknown"


def sanitize(component: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", component)


def group_static_archives(records: list[dict], args: argparse.Namespace) -> dict[tuple[str, str, str], dict]:
    wanted_versions = set(args.version or [])
    wanted_opts = set(args.opt or [])
    wanted_compilers = set(args.compiler or [])
    groups: dict[tuple[str, str, str], dict] = {}

    for record in records:
        if record.get("library") != "openssl":
            continue
        if record.get("linkage") != "static" or record.get("stripped"):
            continue
        artifact = Path(record["artifact"])
        if artifact.name not in {"libcrypto.a", "libssl.a"}:
            continue
        if wanted_versions and record["version"] not in wanted_versions:
            continue
        if wanted_opts and record["opt"] not in wanted_opts:
            continue
        if wanted_compilers and record["compiler"] not in wanted_compilers:
            continue

        key = (record["version"], record["compiler"], record["opt"])
        groups.setdefault(key, {"records": []})
        groups[key][artifact.name] = ROOT / artifact
        groups[key]["records"].append(record)

    return groups


def include_dir(version: str, compiler: str, opt: str) -> Path:
    return ROOT / "corpus" / "work" / "install" / "openssl" / version / f"{compiler}-{opt}-static" / "include"


def build_command(
    args: argparse.Namespace,
    include: Path,
    libssl: Path,
    libcrypto: Path,
    out: Path,
) -> list[str]:
    cmd = [
        args.cc,
        "-g",
        "-fno-omit-frame-pointer",
        "-Wno-deprecated-declarations",
        "-I",
        str(include),
        str(args.source),
    ]
    if args.whole_archive:
        cmd.extend(
            [
                "-Wl,--whole-archive",
                str(libssl),
                str(libcrypto),
                "-Wl,--no-whole-archive",
            ]
        )
    else:
        cmd.extend(
            [
                "-Wl,--start-group",
                str(libssl),
                str(libcrypto),
                "-Wl,--end-group",
            ]
        )
    cmd.extend(["-ldl", "-pthread", "-lm", "-o", str(out)])
    return cmd


def existing_artifact_hashes(records: list[dict]) -> set[str]:
    return {record["artifact_sha256"] for record in records if "artifact_sha256" in record}


def append_metadata(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def build_one(args: argparse.Namespace, key: tuple[str, str, str], group: dict, seen_hashes: set[str]) -> bool:
    version, compiler, opt = key
    libssl = group.get("libssl.a")
    libcrypto = group.get("libcrypto.a")
    include = include_dir(version, compiler, opt)

    if libssl is None or libcrypto is None:
        print(f"[skip] openssl {version} {compiler} {opt}: missing libssl.a or libcrypto.a")
        return False
    if not include.exists():
        print(f"[skip] openssl {version} {compiler} {opt}: missing include dir {include}")
        return False

    profile = sanitize(args.profile + ("-whole" if args.whole_archive else ""))
    out_dir = (
        args.root
        / "corpus"
        / "harness"
        / "openssl"
        / version
        / compiler
        / opt
        / profile
        / "unstripped"
    )
    out = out_dir / "openssl_static_harness"
    out_dir.mkdir(parents=True, exist_ok=True)

    if out.exists() and not args.force:
        print(f"[skip] existing harness: {out}")
    else:
        tmp_out = out.with_suffix(".tmp")
        if tmp_out.exists():
            tmp_out.unlink()
        cmd = build_command(args, include, libssl, libcrypto, tmp_out)
        run(cmd, args.root)
        shutil.move(tmp_out, out)

    artifact_hash = sha256(out)
    if artifact_hash in seen_hashes:
        print(f"[skip] metadata already has artifact hash: {out}")
        return True

    source_record = group["records"][0]
    record = {
        "library": "openssl",
        "version": version,
        "source_url": source_record.get("source_url", "unknown"),
        "source_sha256": source_record.get("source_sha256", "unknown"),
        "compiler": compiler,
        "compiler_version": compiler_version(args.cc),
        "arch": platform.machine(),
        "os": platform.system().lower(),
        "opt": opt,
        "linkage": "static",
        "stripped": False,
        "artifact": str(out.relative_to(args.root)),
        "artifact_sha256": artifact_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "harness": True,
        "harness_profile": profile,
        "harness_source": str(args.source.relative_to(args.root)),
        "linked_archives": [
            str(libssl.relative_to(args.root)),
            str(libcrypto.relative_to(args.root)),
        ],
    }
    append_metadata(args.metadata, record)
    seen_hashes.add(artifact_hash)
    print(f"[built] {out}")
    return True


def main() -> None:
    args = parse_args()
    args.root = args.root.resolve()
    args.metadata = args.metadata.resolve()
    args.source = args.source.resolve()

    if not args.source.exists():
        raise FileNotFoundError(f"harness source missing: {args.source}")

    records = load_metadata(args.metadata)
    groups = group_static_archives(records, args)
    seen_hashes = existing_artifact_hashes(records)

    built = 0
    skipped = 0
    for key in sorted(groups):
        if build_one(args, key, groups[key], seen_hashes):
            built += 1
        else:
            skipped += 1

    print(f"harnesses_ready={built} skipped={skipped}")


if __name__ == "__main__":
    main()
