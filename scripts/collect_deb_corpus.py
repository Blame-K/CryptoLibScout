#!/usr/bin/env python3
"""Collect ELF samples from a downloaded Debian package."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METADATA = ROOT / "corpus" / "metadata" / "samples.jsonl"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    where = cwd or ROOT
    print(f"[run] {where}: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def command_output(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def package_fields(deb: Path) -> dict[str, str]:
    output = command_output(
        ["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture", "Source"]
    )
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key.lower()] = value
    return fields


def metadata_version(package_version: str) -> str:
    return package_version.split(":", 1)[-1]


def copy_artifact(src: Path, dst: Path, strip_artifact: bool) -> None:
    if dst.exists():
        dst.chmod(dst.stat().st_mode | stat.S_IWUSR)
    shutil.copy2(src, dst)
    dst.chmod(dst.stat().st_mode | stat.S_IWUSR)
    if strip_artifact:
        run(["strip", "--strip-unneeded", str(dst)])


def append_metadata(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deb", type=Path, required=True)
    parser.add_argument("--library", required=True)
    parser.add_argument("--artifact", action="append", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--compiler", default="ubuntu-package")
    parser.add_argument("--opt", default="package")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    deb = args.deb.resolve()
    fields = package_fields(deb)
    package = fields.get("package", deb.stem)
    package_version = fields.get("version", "unknown")
    version = metadata_version(package_version)
    package_arch = fields.get("architecture", "unknown")
    package_source = fields.get("source", package)

    extract_dir = args.root / "corpus" / "work" / "deb" / args.library / version
    if extract_dir.exists() and args.force:
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(deb), str(extract_dir)])

    for artifact_name in args.artifact:
        matches = sorted(path for path in extract_dir.rglob(artifact_name) if path.is_file())
        if not matches:
            raise FileNotFoundError(f"{artifact_name} not found in {deb}")
        src = matches[0]

        for stripped in (False, True):
            suffix = "stripped" if stripped else "unstripped"
            out_dir = (
                args.root
                / "corpus"
                / "binaries"
                / args.library
                / version
                / args.compiler
                / args.opt
                / "shared"
                / suffix
            )
            out_dir.mkdir(parents=True, exist_ok=True)
            dst = out_dir / artifact_name
            copy_artifact(src, dst, stripped)
            append_metadata(
                args.metadata,
                {
                    "library": args.library,
                    "version": version,
                    "source_url": f"apt:{package}={package_version}",
                    "source_sha256": sha256(deb),
                    "compiler": args.compiler,
                    "compiler_version": f"{package} {package_version} ({package_arch})",
                    "arch": platform.machine(),
                    "os": platform.system().lower(),
                    "opt": args.opt,
                    "linkage": "shared",
                    "stripped": stripped,
                    "artifact": str(dst.relative_to(args.root)),
                    "artifact_sha256": sha256(dst),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "package": package,
                    "package_architecture": package_arch,
                    "package_source": package_source,
                    "package_version": package_version,
                },
            )


if __name__ == "__main__":
    main()
