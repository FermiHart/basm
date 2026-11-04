#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Build the public assembler from a retained snapshot; never promote stale output.

The sovereign lane uses the explicitly supplied Beyond toolchain. The host lane
is a separate contributor/diagnostic route and is never substituted implicitly.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "bear-basm-build-v1"
SOURCE_FILES = (
    "basm.c", "version.h", "VERSION", "elftool.c", "sign.c", "sign.h",
    "sha256_ni.h", "crypto/ed25519.c", "crypto/ed25519.h",
    "isa/forms.tsv", "isa/generate.pl", "isa/intent_forms.h", "isa/INVENTORY.md",
    "runtime/start.basm", "runtime/syscall_x86_64.basm", "test_sha.c", "test_sign.c",
    "Makefile", "tools/build.py",
)
LINK_DEFINITIONS = (
    "fprintf=bear_fprintf", "snprintf=bear_snprintf", "printf=bear_printf",
    "dprintf=bear_dprintf", "exit=bear_exit", "malloc=bear_malloc",
    "calloc=bear_calloc", "free=bear_free", "realloc=bear_realloc",
    "strtol=bear_strtol", "strtoull=bear_strtoull", "getenv=bear_getenv",
    "read=bear_read", "mkdir=bear_mkdir", "stat=bear_stat", "lstat=bear_lstat",
    "fstat=bear_fstat", "getuid=bear_getuid", "chmod=bear_chmod", "rename=bear_rename",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"sha256": digest(data), "bytes": len(data)}


def checked_bytes(path: Path) -> bytes:
    if any(component.is_symlink() for component in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"required regular file is missing or is a symlink: {path}")
    return path.read_bytes()


def version(root: Path = ROOT) -> str:
    value = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", value):
        raise ValueError("VERSION must contain one safe semantic version")
    return value


def validate_version_header(root: Path, expected: str) -> None:
    header = checked_bytes(root / "version.h").decode("utf-8")
    declared = re.findall(r'^\s*#\s*define\s+BASM_VERSION\s+"([^"\n]+)"\s*$', header, re.MULTILINE)
    if declared != [expected]:
        raise ValueError("VERSION and version.h must declare the same single BASM_VERSION")


def git_state(path: Path) -> dict:
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True,
            stderr=subprocess.DEVNULL, timeout=10).strip()
        dirty = bool(subprocess.check_output(
            ["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"],
            stderr=subprocess.DEVNULL, timeout=10))
        return {"commit": commit, "tracked_worktree_modified": dirty}
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "tracked_worktree_modified": None}


def atomic_bytes(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".basm-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_command(argv: list[str], target: Path, *, cwd: Path,
                   log: Path, timeout: int = 180) -> None:
    """The caller names a new output, so failed compilers cannot bless old bytes."""
    if target.exists() or target.is_symlink():
        raise ValueError(f"build output already exists in fresh snapshot: {target}")
    with log.open("wb") as output:
        result = subprocess.run(argv, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False)
    if result.returncode:
        target.unlink(missing_ok=True)
        tail = log.read_text(encoding="utf-8", errors="replace")[-6000:]
        raise RuntimeError(f"command failed ({result.returncode}): {argv[0]}\n{tail}")
    if target.is_symlink() or not target.is_file() or target.stat().st_size == 0:
        target.unlink(missing_ok=True)
        raise RuntimeError(f"command returned success without a nonempty regular output: {argv[0]}")


def executable_identity(path: Path) -> dict:
    resolved = path.resolve(strict=True)
    if not os.access(resolved, os.X_OK):
        raise ValueError(f"tool is not executable: {path}")
    return file_identity(resolved)


def snapshot(source: Path, destination: Path, records: dict, originals: dict,
             name: str, executable: bool = False) -> None:
    content = checked_bytes(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o755 if executable else 0o644)
    identity = {"sha256": digest(content), "bytes": len(content)}
    records[name] = identity
    originals[source] = identity


def cc_flags(cc: str) -> list[str]:
    flags = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-common"]
    for flag in ("-Wno-misleading-indentation", "-Wno-stringop-truncation",
                 "-Wno-format-truncation"):
        result = subprocess.run([cc, flag, "-Werror", "-x", "c", "-c", "-o",
                                 os.devnull, "-"], input=b"", capture_output=True,
                                timeout=20, check=False)
        if result.returncode == 0:
            flags.append(flag)
    # No global -msha/-march=native: the helper's runtime dispatcher owns ISA use.
    if platform.system() == "Darwin":
        flags.append("-DBASM_NO_PROC_SELF_EXE")
    return flags


def static_linux_elf(path: Path) -> None:
    import struct
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("sovereign output is not a little-endian ELF64 executable")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind != 2 or machine != 62:
        raise ValueError("sovereign output must be an x86-64 ET_EXEC")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if count and (size < 56 or offset > len(data) or count > (len(data) - offset) // size):
        raise ValueError("malformed sovereign program header table")
    if any(struct.unpack_from("<I", data, offset + i * size)[0] == 3 for i in range(count)):
        raise ValueError("sovereign output unexpectedly needs a dynamic interpreter")


def build(args: argparse.Namespace) -> int:
    if args.lane == "sovereign":
        if not args.beyond_root:
            raise ValueError("official build requires BEYOND_ROOT=/path/to/Beyond_BDM; "
                             "use 'make host' explicitly for a host diagnostic build")
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            raise ValueError("the sovereign binary lane currently requires a Linux x86-64 host")
    output = (args.output_dir or ROOT / "build" / args.lane).resolve()
    if output == ROOT or ROOT.is_relative_to(output):
        raise ValueError("output directory must not contain the source repository")
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".build.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError(f"another build owns {output}; use a different output directory") from exc
        run = output / "runs" / str(time.time_ns())
        source = run / "source"
        source.mkdir(parents=True)
        (source / "obj").mkdir()
        (source / "out").mkdir()
        receipt = {
            "schema": SCHEMA, "version": version(),
            "lane": "sovereign" if args.lane == "sovereign" else "host-diagnostic",
            "source_repository": git_state(ROOT), "source_inputs": {},
            "toolchain_inputs": {}, "commands": [], "artifacts": {},
            "target": "linux-x86_64" if args.lane == "sovereign" else
                      platform.system().lower() + "-" + platform.machine(),
            "status": "BUILDING", "qualification": "development build; not a release or Beyond guest qualification",
        }
        originals: dict[Path, dict] = {}
        try:
            names = list(SOURCE_FILES)
            names += [p.relative_to(ROOT).as_posix() for directory in ("modules", "intent")
                      for p in sorted((ROOT / directory).glob("*.inc"))]
            for name in names:
                snapshot(ROOT / name, source / name, receipt["source_inputs"], originals, name)
            validate_version_header(source, receipt["version"])
            generated = subprocess.run(["perl", "isa/generate.pl", "--check"], cwd=source,
                                       capture_output=True, text=True, timeout=30, check=False)
            if generated.returncode:
                raise RuntimeError("ISA generated files drifted: " + generated.stderr[-4000:])
            artifacts: dict[str, Path] = {}

            def compile_command(argv: list[str], relative: str) -> Path:
                target = source / relative
                command_number = len(receipt["commands"])
                receipt["commands"].append(argv)
                atomic_command(argv, target, cwd=source,
                               log=run / f"command-{command_number:02d}.log")
                return target

            if args.lane == "host":
                located = shutil.which(args.cc)
                if not located:
                    raise ValueError(f"host compiler not found: {args.cc}")
                cc = str(Path(located).resolve())
                receipt["toolchain_inputs"]["host-compiler"] = executable_identity(Path(cc))
                originals[Path(cc)] = receipt["toolchain_inputs"]["host-compiler"]
                compiler_version = subprocess.check_output([cc, "--version"], text=True, timeout=20)
                # Keep the identity useful without copying compiler installation paths.
                receipt["compiler_version"] = re.sub(r"(?:[A-Za-z]:)?/[^\s]+", "<path>",
                                                     compiler_version.splitlines()[0])[:1000]
                flags = cc_flags(cc) + ["-I."]
                receipt["limitations"] = ["host compiler and system libc; not the sovereign lane",
                                           "system headers and libc are not snapshotted or authenticated"]
                for name, units, extra in (
                    ("basm", ["basm.c", "sign.c", "crypto/ed25519.c"], ["-DBASM_PUBLIC_ONLY=1"]),
                    ("elftool", ["elftool.c", "sign.c", "crypto/ed25519.c"], []),
                    ("test-sha", ["test_sha.c"], []),
                    ("test-sign", ["test_sign.c", "sign.c", "crypto/ed25519.c"], []),
                ):
                    artifacts[name] = compile_command([cc] + flags + extra + units +
                                                      ["-o", "out/" + name], "out/" + name)
                if args.compat:
                    artifacts["basm-compat"] = compile_command(
                        [cc] + flags + ["basm.c", "sign.c", "crypto/ed25519.c", "-o", "out/basm-compat"],
                        "out/basm-compat")
                # Receipts disclose the compiler identity without leaking local machine paths.
                receipt["commands"] = [["<host-compiler>"] + command[1:] for command in receipt["commands"]]
            else:
                beyond = Path(args.beyond_root).expanduser().resolve(strict=True)
                receipt["external_repository"] = git_state(beyond)
                externals = {
                    "toolchain/bear": "toolchain/bear/bear",
                    "toolchain/bear-ld": "BearLinker/bear-ld-host",
                    "toolchain/basm-seed": "toolchain/BearBasm/basm",
                    "toolchain/libblibc.a": "surfaces/blibc/build/libblibc.a",
                    "toolchain/userspace.ld": "BearLinker/userspace.ld",
                    "toolchain/posix_minimal.c": "BearLinker/sovereign-shims/posix_minimal.c",
                    "toolchain/blibc/osif/linux/start_main.c": "surfaces/blibc/osif/linux/start_main.c",
                }
                blibc = beyond / "surfaces/blibc"
                for header in sorted(blibc.rglob("*.h")):
                    relative = header.relative_to(blibc)
                    if "build" in relative.parts or ".git" in relative.parts:
                        continue
                    externals["toolchain/blibc/" + relative.as_posix()] = header.relative_to(beyond).as_posix()
                for destination, original in externals.items():
                    executable = destination in ("toolchain/bear", "toolchain/bear-ld", "toolchain/basm-seed")
                    if executable:
                        executable_identity(beyond / original)
                    snapshot(beyond / original, source / destination, receipt["toolchain_inputs"],
                             originals, original, executable=executable)
                # Match the established toolchain's 64 MiB stack, without changing host limits upward.
                soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
                stack = 64 * 1024 * 1024
                if soft != resource.RLIM_INFINITY and soft < stack and (hard == resource.RLIM_INFINITY or hard >= stack):
                    resource.setrlimit(resource.RLIMIT_STACK, (stack, hard))
                flags = ["-I.", "-Itoolchain/blibc/include", "-Itoolchain/blibc", "-Itoolchain/blibc/posix/include"]
                objects = []
                for name, unit, extra in (
                    ("sign", "sign.c", []), ("ed25519", "crypto/ed25519.c", []),
                    ("start_main", "toolchain/blibc/osif/linux/start_main.c", ["-DBEAR_OSIF_LINUX=1"]),
                    ("posix_minimal", "toolchain/posix_minimal.c", ["-DBEAR_OSIF_LINUX=1"]),
                ):
                    relative = "obj/" + name + ".o"
                    compile_command(["./toolchain/bear", "-c", unit, "-o", relative] + extra + flags, relative)
                    objects.append(relative)
                for name, unit in (("start", "runtime/start.basm"), ("syscall", "runtime/syscall_x86_64.basm")):
                    relative = "obj/" + name + ".o"
                    compile_command(["./toolchain/basm-seed", "--target-profile", "beyond", "-f", "elf64",
                                     "-o", relative, unit], relative)
                    objects.append(relative)
                variants = [("basm", ["-DBASM_PUBLIC_ONLY=1"])]
                if args.compat:
                    variants.append(("basm-compat", []))
                for name, extra in variants:
                    obj = "obj/" + name + ".o"
                    compile_command(["./toolchain/bear", "-c", "basm.c", "-o", obj] + extra + flags, obj)
                    argv = ["./toolchain/bear-ld", "-T", "toolchain/userspace.ld"]
                    for definition in LINK_DEFINITIONS:
                        argv += ["--defsym", definition]
                    argv += ["-o", "out/" + name, obj] + objects + ["toolchain/libblibc.a"]
                    artifacts[name] = compile_command(argv, "out/" + name)
                    artifacts[name].chmod(0o755)
                    static_linux_elf(artifacts[name])
                receipt["limitations"] = ["external toolchain is pinned by hashes, not rebuilt here",
                                           "no bootstrap closure, independent compiler proof or Beyond guest qualification"]
            capabilities = subprocess.check_output([str(artifacts["basm"]), "--capabilities"],
                                                   text=True, timeout=20)
            parsed = json.loads(capabilities)
            if parsed.get("build") != "public-only" or parsed.get("target_profile") != "public":
                raise RuntimeError("public binary did not report the immutable public profile")
            receipt["capabilities"] = parsed
            for name, profile in (("basm", "public-only"), ("basm-compat", "bootstrap-capable")):
                if name in artifacts:
                    reported = subprocess.check_output([str(artifacts[name]), "--version"],
                                                       text=True, timeout=20).strip()
                    expected = f"BearBasm {receipt['version']} ({profile})"
                    if reported != expected:
                        raise RuntimeError(name + " reports a version/profile different from the distribution")
            for name in ("test-sha", "test-sign"):
                if name in artifacts:
                    result = subprocess.run([str(artifacts[name])], capture_output=True, text=True,
                                            timeout=30, check=False)
                    if result.returncode:
                        raise RuntimeError(name + " failed: " + result.stderr[-4000:] + result.stdout[-4000:])
            changed = [str(path) for path, expected in originals.items() if file_identity(path) != expected]
            if changed:
                raise RuntimeError("source/toolchain changed during build; refusing publication: " + ", ".join(changed[:5]))
            receipt["artifacts"] = {name: file_identity(path) for name, path in sorted(artifacts.items())}
            receipt["status"] = "BUILT"
            encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
            atomic_bytes(run / "build-receipt.json", encoded)
            for name, path in artifacts.items():
                atomic_bytes(output / name, path.read_bytes(), 0o755)
            # Receipt is the commit point. Consumers verify every referenced binary hash.
            atomic_bytes(output / "build-receipt.json", encoded)
            print(f"Built {receipt['lane']} public assembler: {output / 'basm'}")
            print(f"Receipt: {output / 'build-receipt.json'}")
            return 0
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            receipt["status"] = "FAILED"
            receipt["error"] = str(exc)
            atomic_bytes(run / "build-receipt.json", (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=("sovereign", "host"), default="sovereign")
    parser.add_argument("--beyond-root", default=os.environ.get("BEYOND_ROOT", ""))
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--compat", action="store_true", help="also build a separate Beyond-compatible test binary")
    args = parser.parse_args()
    try:
        return build(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print("basm build: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
