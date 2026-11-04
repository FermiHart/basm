#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Create deterministic source or development binary tarballs with file hashes."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_ROOT_FILES = {
    "AGENTS.md", "Makefile", "VERSION", "version.h", "README.md", "LICENSE", "NOTICE", "REUSE.toml",
    "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORTED-SUBSET.md",
    "POLITICA-BASM.md", "ATOMIC-PUBLICATION.md", ".gitignore", "index.html", "downloads/README.md",
    "basm.c", "sign.c", "sign.h", "elftool.c", "sha256_ni.h", "test_sha.c", "test_sign.c",
    "bear_ed25519.c", "bear_ed25519.h", "bench_nasm.sh", "bench_sha.c", "ddc-basm.sh",
    "gate.sh", "verify_one.sh", "build.sh",
    "quarantine/basm_monolith_legacy.c", "quarantine/README.md",
}
ALLOWED_DIRECTORIES = {"modules", "intent", "isa", "runtime", "crypto", "tests", "tools",
                       "examples", "docs", "provenance", "LICENSES", "contracts", "lab", ".github"}
SOURCE_SUFFIXES = {".c", ".h", ".inc", ".basm", ".S", ".md", ".json", ".txt", ".tsv",
                   ".sh", ".py", ".pl", ".yml", ".yaml", ".patch", ".ld"}
PUBLIC_ASSET_FILES = {
    "demo/README.md", "demo/demo.py", "demo/demo.pub", "demo/other-demo.pub",
    "demo/explain_summary.py", "demo/hello.basm", "demo/object_edit.py", "demo/run.sh",
    "readme/LICENSE.media.txt", "readme/generate_media.py",
    "readme/hero-basm.svg", "readme/hero-basm-mobile.svg", "readme/hero-basm.png",
    "readme/basm-in-action.gif", "readme/basm-in-action-mobile.gif",
    "readme/basm-in-action.mp4", "readme/basm-in-action-mobile.mp4",
    "readme/basm-poster.png", "readme/basm-poster-mobile.png",
}
# Published packages are outputs, never inputs to the source package. Keep this
# list exact: another archive, a key or an unknown file must still stop packaging.
PUBLISHED_DOWNLOADS = {
    "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-source.tar.gz",
    "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-source.tar.gz.sha256",
    "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-linux-x86_64.tar.gz",
    "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-linux-x86_64.tar.gz.sha256",
    "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-linux-x86_64-host-diagnostic.tar.gz",
    "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-linux-x86_64-host-diagnostic.tar.gz.sha256",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative(name: str) -> bool:
    path = PurePosixPath(name)
    return (bool(name) and not path.is_absolute() and ".." not in path.parts and
            "\\" not in name and "\x00" not in name and
            all(part not in ("", ".") for part in name.split("/")))


def read_regular(path: Path) -> bytes:
    if any(component.is_symlink() for component in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"package input must be a regular file, not a symlink: {path}")
    return path.read_bytes()


def read_version(root: Path) -> str:
    value = read_regular(root / "VERSION").decode("utf-8").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", value):
        raise ValueError("invalid VERSION")
    return value


def source_entries(root: Path) -> tuple[dict, dict]:
    names = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"], timeout=20)
    entries = {}
    excluded = []
    for raw in names.split(b"\0"):
        if not raw:
            continue
        name = raw.decode("utf-8")
        if not safe_relative(name):
            raise ValueError(f"unsafe tracked path: {name!r}")
        path = PurePosixPath(name)
        if name in PUBLISHED_DOWNLOADS:
            # Validate the declared output too; do not silently accept a symlink
            # merely because its filename matches an excluded archive.
            read_regular(root / name)
            excluded.append(name)
            continue
        allow = (name in ALLOWED_ROOT_FILES or name in PUBLIC_ASSET_FILES or
                 path.parts[0] in ALLOWED_DIRECTORIES and
                 (path.suffix in SOURCE_SUFFIXES or path.name in ("Makefile", "LICENSE", "NOTICE")))
        if not allow:
            # Do not silently package a new binary, key, dump or unknown build input.
            raise ValueError(f"tracked file has no source-distribution policy: {name}")
        if any(part in ("__pycache__", ".git", "node_modules") for part in path.parts):
            raise ValueError(f"cache or repository internals cannot be packaged: {name}")
        source = root / name
        entries[name] = (read_regular(source), 0o755 if source.stat().st_mode & 0o111 else 0o644)
    required = {"Makefile", "VERSION", "version.h", "README.md", "LICENSE", "NOTICE", "REUSE.toml",
                "LICENSES/BSD-3-Clause.txt", "LICENSES/LicenseRef-SPL-1.0.txt",
                "LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt", "LICENSES/Unlicense.txt",
                "basm.c", "tools/build.py", "tools/package.py", "tools/install.py"}
    absent = sorted(required - entries.keys())
    if absent:
        raise ValueError("source distribution requires explicitly Git-staged files: " + ", ".join(absent))
    commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True, timeout=20).strip()
    dirty = bool(subprocess.check_output(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"], timeout=20))
    return entries, {"source_commit": commit, "tracked_worktree_modified": dirty,
                     "selection": "allowlisted Git-tracked worktree files; no untracked files or declared published packages",
                     "excluded_published_artifacts": sorted(excluded)}


def documentation_entries(root: Path) -> dict:
    names = ["README.md", "LICENSE", "NOTICE", "REUSE.toml", "SUPPORTED-SUBSET.md", "POLITICA-BASM.md", "docs/BUILD.md",
             "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "docs/TESTING.md",
             "lab/README.md", "lab/MEASUREMENT.md", "provenance/UPSTREAM.json",
             "index.html", "downloads/README.md",
             "LICENSES/BSD-3-Clause.txt", "LICENSES/LicenseRef-SPL-1.0.txt",
             "LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt", "LICENSES/Unlicense.txt",
             "examples/hello_linux_x86_64.basm", "examples/bytes.basm",
             "readme/LICENSE.media.txt", "readme/hero-basm.svg", "readme/hero-basm-mobile.svg",
             "readme/basm-in-action.gif", "readme/basm-in-action-mobile.gif", "readme/basm-in-action.mp4",
             "readme/basm-in-action-mobile.mp4", "readme/basm-poster.png", "readme/basm-poster-mobile.png",
             "demo/README.md", "demo/demo.py", "demo/demo.pub", "demo/other-demo.pub",
             "demo/explain_summary.py", "demo/hello.basm", "demo/object_edit.py", "demo/run.sh"]
    return {name: (read_regular(root / name), 0o644) for name in names}


def binary_entries(root: Path, build_dir: Path) -> tuple[dict, dict]:
    receipt_data = read_regular(build_dir / "build-receipt.json")
    receipt = json.loads(receipt_data)
    if receipt.get("schema") != "bear-basm-build-v1" or receipt.get("status") != "BUILT":
        raise ValueError("a successful standalone build receipt is required")
    if receipt.get("lane") not in ("sovereign", "host-diagnostic"):
        raise ValueError("unrecognized build lane")
    if receipt.get("version") != read_version(root):
        raise ValueError("VERSION changed since the build")
    binary = read_regular(build_dir / "basm")
    identity = {"bytes": len(binary), "sha256": sha256(binary)}
    if receipt.get("artifacts", {}).get("basm") != identity:
        raise ValueError("assembler does not match its build receipt; refusing stale/mixed output")
    for name, expected in receipt.get("source_inputs", {}).items():
        if not safe_relative(name):
            raise ValueError("unsafe source path in build receipt")
        current = read_regular(root / name)
        if {"sha256": sha256(current), "bytes": len(current)} != expected:
            raise ValueError("source changed since build: " + name)
    if not receipt.get("source_inputs"):
        raise ValueError("build receipt does not identify its sources")
    if receipt["lane"] == "sovereign" and receipt.get("target") != "linux-x86_64":
        raise ValueError("the current sovereign distribution contract is Linux x86-64")
    entries = documentation_entries(root)
    entries.update({"bin/basm": (binary, 0o755), "build-receipt.json": (receipt_data, 0o644),
                    "install.py": (read_regular(root / "tools/install.py"), 0o644)})
    return entries, {"build_lane": receipt["lane"], "target": receipt["target"],
                     "build_receipt_sha256": sha256(receipt_data),
                     "qualification": receipt["qualification"]}


def complete_entries(entries: dict, metadata: dict) -> dict:
    if "MANIFEST.json" in entries or "SHA256SUMS" in entries:
        raise ValueError("reserved package metadata path")
    for name, (_, mode) in entries.items():
        if not safe_relative(name) or mode not in (0o644, 0o755):
            raise ValueError("unsafe package entry: " + name)
    result = dict(entries)
    manifest = {"schema": "bear-basm-package-v1", **metadata,
                "files": [{"path": name, "sha256": sha256(data), "bytes": len(data), "mode": mode}
                          for name, (data, mode) in sorted(entries.items())]}
    result["MANIFEST.json"] = ((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o644)
    sums = "".join(sha256(data) + "  " + name + "\n" for name, (data, _) in sorted(result.items()))
    result["SHA256SUMS"] = (sums.encode(), 0o644)
    return result


def write_archive(destination: Path, prefix: str, entries: dict, epoch: int) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", prefix):
        raise ValueError("unsafe archive prefix")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".bear-basm-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for relative, (content, mode) in sorted(entries.items()):
                        if not safe_relative(relative):
                            raise ValueError("unsafe archive path: " + relative)
                        member = tarfile.TarInfo(prefix + "/" + relative)
                        member.size, member.mode, member.mtime = len(content), mode, epoch
                        member.uid = member.gid = 0
                        member.uname = member.gname = ""
                        archive.addfile(member, io.BytesIO(content))
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=("source", "binary"))
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/sovereign")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        raw_epoch = os.environ.get("SOURCE_DATE_EPOCH", "0")
        if not re.fullmatch(r"[0-9]+", raw_epoch) or int(raw_epoch) > 0xffffffff:
            raise ValueError("SOURCE_DATE_EPOCH must be an integer from 0 through 4294967295")
        epoch = int(raw_epoch)
        release_version = read_version(ROOT)
        if args.kind == "source":
            entries, metadata = source_entries(ROOT)
            suffix = "source"
        else:
            entries, metadata = binary_entries(ROOT, args.build_dir.resolve())
            suffix = metadata["target"]
            if metadata["build_lane"] == "host-diagnostic":
                suffix += "-host-diagnostic"
        name = "bear-basm-" + release_version + "-" + suffix
        metadata.update({"version": release_version, "kind": args.kind,
                         "source_date_epoch": epoch, "integrity": "SHA-256 file inventory; unsigned development package"})
        payload = complete_entries(entries, metadata)
        archive = args.out_dir.resolve() / (name + ".tar.gz")
        write_archive(archive, name, payload, epoch)
        checksum = sha256(archive.read_bytes()) + "  " + archive.name + "\n"
        checksum_path = archive.with_name(archive.name + ".sha256")
        checksum_path.write_text(checksum, encoding="utf-8")
        print(archive)
        print(checksum_path)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("basm package: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
