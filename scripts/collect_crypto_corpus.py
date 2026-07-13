#!/usr/bin/env python3
"""Build a small, reproducible binary corpus for crypto-library matching."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "crypto_libraries.json"


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"[run] {cwd}: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dst: Path, force: bool) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and not force:
        print(f"[skip] source exists: {dst}")
        return
    print(f"[download] {url}")
    urllib.request.urlretrieve(url, dst)


def extract(archive: Path, dst: Path, force: bool) -> Path:
    if dst.exists() and force:
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    marker = dst / ".extracted"
    if marker.exists() and not force:
        children = [p for p in dst.iterdir() if p.is_dir()]
        if len(children) == 1:
            return children[0]

    print(f"[extract] {archive}")
    with tarfile.open(archive) as tf:
        tf.extractall(dst)
    marker.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")

    children = [p for p in dst.iterdir() if p.is_dir()]
    if len(children) != 1:
        raise RuntimeError(f"cannot identify extracted source directory under {dst}")
    return children[0]


def copy_tree(src: Path, dst: Path, force: bool) -> None:
    if dst.exists():
        if force:
            shutil.rmtree(dst)
        else:
            return
    shutil.copytree(src, dst)


def compiler_version(compiler: str) -> str:
    try:
        result = subprocess.run(
            [compiler, "--version"], check=True, text=True, capture_output=True
        )
        return result.stdout.splitlines()[0]
    except Exception:
        return "unknown"


def build_openssl(src: Path, install: Path, opt: str, mode: str, jobs: int, compiler: str) -> None:
    env = os.environ.copy()
    env["CC"] = compiler
    env["CFLAGS"] = f"-{opt} -fPIC"
    configure_script = src / "Configure"
    first_line = configure_script.open("rb").readline()
    configure_runner = ["./Configure"] if first_line.startswith(b"#!") else ["perl", "./Configure"]
    configure = configure_runner + ["linux-x86_64", f"--prefix={install}", "no-tests"]
    configure.append("shared" if mode == "shared" else "no-shared")
    run(configure, src, env)
    run(["make", f"-j{jobs}"], src, env)
    run(["make", "install_sw"], src, env)


def build_libsodium(src: Path, install: Path, opt: str, mode: str, jobs: int, compiler: str) -> None:
    env = os.environ.copy()
    env["CC"] = compiler
    env["CFLAGS"] = f"-{opt} -fPIC"
    configure = ["./configure", f"--prefix={install}"]
    configure.append("--enable-shared" if mode == "shared" else "--disable-shared")
    configure.append("--enable-static" if mode == "static" else "--disable-static")
    run(configure, src, env)
    run(["make", f"-j{jobs}"], src, env)
    run(["make", "install"], src, env)


def build_mbedtls(src: Path, install: Path, opt: str, mode: str, jobs: int, compiler: str) -> None:
    env = os.environ.copy()
    env["CC"] = compiler
    env["CFLAGS"] = f"-{opt} -fPIC"
    make_target = "SHARED=1" if mode == "shared" else "lib"
    run(["make", f"-j{jobs}", make_target], src, env)
    lib_dst = install / "lib"
    include_dst = install / "include"
    lib_dst.mkdir(parents=True, exist_ok=True)
    include_dst.mkdir(parents=True, exist_ok=True)
    for lib in (src / "library").glob("*.a"):
        shutil.copy2(lib, lib_dst / lib.name)
    for lib in (src / "library").glob("*.so*"):
        if lib.is_file():
            shutil.copy2(lib, lib_dst / lib.name)
    shutil.copytree(src / "include", include_dst, dirs_exist_ok=True)


BUILDERS = {
    "openssl": build_openssl,
    "libsodium": build_libsodium,
    "mbedtls": build_mbedtls,
}


def library_dirs(install: Path) -> list[Path]:
    return [path for path in (install / "lib", install / "lib64") if path.exists()]


def collect_artifacts(install: Path, out_dir: Path, mode: str, stripped: bool, force: bool) -> list[Path]:
    if out_dir.exists() and force:
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    patterns = ["*.so", "*.so.*"] if mode == "shared" else ["*.a"]
    artifacts: list[Path] = []
    seen_hashes: set[str] = set()
    for lib_dir in library_dirs(install):
        for pattern in patterns:
            for src in lib_dir.glob(pattern):
                if src.is_file() and not src.is_symlink():
                    src_hash = sha256(src)
                    if src_hash in seen_hashes:
                        continue
                    seen_hashes.add(src_hash)
                    dst = out_dir / src.name
                    if dst.exists():
                        dst.chmod(dst.stat().st_mode | stat.S_IWUSR)
                    shutil.copy2(src, dst)
                    dst.chmod(dst.stat().st_mode | stat.S_IWUSR)
                    if stripped and dst.suffix != ".a":
                        run(["strip", "--strip-unneeded", str(dst)], out_dir)
                    elif stripped and dst.suffix == ".a":
                        run(["strip", "--strip-debug", str(dst)], out_dir)
                    artifacts.append(dst)
    return sorted(set(artifacts))


def append_metadata(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def selected_libraries(config: dict, wanted: set[str] | None) -> list[dict]:
    libs = config["libraries"]
    if wanted is None:
        return libs
    return [lib for lib in libs if lib["name"] in wanted]


def build_one(args: argparse.Namespace, config: dict, lib: dict, item: dict, opt: str, mode: str) -> None:
    name = lib["name"]
    version = item["version"]
    url = item["url"]
    archive = args.root / "corpus" / "sources" / name / Path(url).name
    extract_dir = args.root / "corpus" / "work" / "extracted" / name / version
    build_dir = args.root / "corpus" / "work" / "builds" / name / version / f"{args.compiler}-{opt}-{mode}"
    install = args.root / "corpus" / "work" / "install" / name / version / f"{args.compiler}-{opt}-{mode}"

    if not args.no_download:
        download(url, archive, args.force)
    if not archive.exists():
        raise FileNotFoundError(f"source archive missing: {archive}")

    source_dir = extract(archive, extract_dir, args.force)
    copy_tree(source_dir, build_dir, args.force)

    if install.exists() and args.force:
        shutil.rmtree(install)
    install.mkdir(parents=True, exist_ok=True)

    builder = BUILDERS[name]
    if not args.collect_only:
        builder(build_dir, install, opt, mode, config["target"]["make_jobs"], args.compiler)

    for stripped in (False, True):
        suffix = "stripped" if stripped else "unstripped"
        out_dir = (
            args.root
            / "corpus"
            / "binaries"
            / name
            / version
            / args.compiler
            / opt
            / mode
            / suffix
        )
        artifacts = collect_artifacts(install, out_dir, mode, stripped, args.force)
        if not artifacts:
            raise RuntimeError(f"no artifacts collected from {install}; checked lib and lib64")
        for artifact in artifacts:
            append_metadata(
                args.root / "corpus" / "metadata" / "samples.jsonl",
                {
                    "library": name,
                    "version": version,
                    "source_url": url,
                    "source_sha256": sha256(archive),
                    "compiler": args.compiler,
                    "compiler_version": compiler_version(args.compiler),
                    "arch": platform.machine(),
                    "os": platform.system().lower(),
                    "opt": opt,
                    "linkage": mode,
                    "stripped": stripped,
                    "artifact": str(artifact.relative_to(args.root)),
                    "artifact_sha256": sha256(artifact),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--library", action="append", help="Build only this library; can be repeated.")
    parser.add_argument("--version", action="append", help="Build only this version; can be repeated.")
    parser.add_argument("--opt", action="append", help="Build only this optimization level; can be repeated.")
    parser.add_argument("--mode", action="append", choices=["shared", "static"])
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--no-download", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--reset-metadata", action="store_true")
    parser.add_argument("--collect-only", action="store_true", help="Reuse an existing install tree and only copy artifacts/metadata.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    wanted_libs = set(args.library) if args.library else None
    wanted_versions = set(args.version) if args.version else None
    opts = args.opt or config["target"]["optimization_levels"]
    modes = args.mode or config["target"]["build_modes"]
    metadata = args.root / "corpus" / "metadata" / "samples.jsonl"
    if args.reset_metadata and metadata.exists():
        metadata.unlink()

    for lib in selected_libraries(config, wanted_libs):
        if lib["name"] not in BUILDERS:
            raise RuntimeError(f"no builder registered for {lib['name']}")
        for item in lib["versions"]:
            if wanted_versions and item["version"] not in wanted_versions:
                continue
            for opt in opts:
                for mode in modes:
                    build_one(args, config, lib, item, opt, mode)


if __name__ == "__main__":
    main()
