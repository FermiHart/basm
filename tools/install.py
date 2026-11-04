#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Install BearBasm under a chosen prefix; refuse foreign or modified files.

No downloads, elevated privileges or shell execution. The unpacked bin/basm also
works directly without this optional Python installer.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import tempfile
import uuid

INSTALL_MANIFEST = "share/bear-basm/install-manifest.json"
INSTALLER = "share/bear-basm/install.py"
JOURNAL = "share/bear-basm/install-transaction.json"
LOCK = "share/bear-basm/.install.lock"
LOCK_TOKEN = b"bear-basm-install-lock-v1\n"
SCHEMA = "bear-basm-install-v1"


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def safe_relative(name: str) -> bool:
    path = PurePosixPath(name)
    return (bool(name) and not path.is_absolute() and ".." not in path.parts and
            "\\" not in name and "\x00" not in name and
            all(part not in ("", ".") for part in name.split("/")))


def managed_path(name: str) -> bool:
    return safe_relative(name) and (name == "bin/basm" or name == INSTALLER or
                                   name.startswith("share/doc/bear-basm/"))


def regular(path: Path) -> bytes:
    if any(component.is_symlink() for component in (path, *path.parents)) or not path.is_file():
        raise ValueError("expected a regular file, not a symlink: " + str(path))
    return path.read_bytes()


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".bear-basm-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def destination_root(prefix: str, destdir: str = "") -> Path:
    path = Path(prefix).expanduser()
    if not prefix or not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise ValueError("PREFIX must be an absolute directory other than /, without '..'")
    if destdir:
        stage = Path(destdir).expanduser().absolute()
        if ".." in stage.parts:
            raise ValueError("DESTDIR must not contain '..'")
        path = stage / path.relative_to("/")
    return path


def reject_symlink_parents(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("installation paths cannot cross symlinks: " + str(component))
        if component.exists() and not component.is_dir():
            raise ValueError("installation parent is not a directory: " + str(component))


def previous_manifest(root: Path) -> dict:
    path = root / INSTALL_MANIFEST
    reject_symlink_parents(path.parent)
    if not path.exists() and not path.is_symlink():
        return {}
    manifest = json.loads(regular(path))
    if manifest.get("schema") != SCHEMA or not isinstance(manifest.get("files"), dict):
        raise ValueError("unrecognized existing installation manifest")
    for name, record in manifest["files"].items():
        if not managed_path(name) or not isinstance(record, dict) or not re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")):
            raise ValueError("unsafe existing installation manifest")
    return manifest


def preflight_owned(root: Path, records: dict) -> None:
    for name, record in records.items():
        target = root / name
        reject_symlink_parents(target.parent)
        if target.exists() or target.is_symlink():
            data = regular(target)
            if sha256(data) != record["sha256"]:
                raise ValueError("installed file was modified; leaving it untouched: " + str(target))


@contextlib.contextmanager
def prefix_lock(root: Path):
    """Serialize one prefix, including recovery; never wait behind another writer."""
    lock_path = root / LOCK
    reject_symlink_parents(lock_path.parent)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = None
    for _ in range(3):
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        created = False
        try:
            descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o644)
            created = True
        except FileExistsError:
            descriptor = os.open(lock_path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("installer lock must be a regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("another installation owns this prefix") from exc
            try:
                current = lock_path.stat(follow_symlinks=False)
            except FileNotFoundError:
                os.close(descriptor)
                descriptor = None
                continue
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                os.close(descriptor)
                descriptor = None
                continue
            if created:
                os.write(descriptor, LOCK_TOKEN)
                os.fsync(descriptor)
            break
        except BaseException:
            os.close(descriptor)
            descriptor = None
            raise
    if descriptor is None:
        raise ValueError("installer lock changed while acquiring it")
    try:
        yield
    finally:
        # No more product writes follow this unlink. A contender that opened the
        # old inode must check its identity above before treating its lock as live.
        try:
            if not (root / INSTALL_MANIFEST).exists() and not (root / JOURNAL).exists():
                if lock_path.exists() and regular(lock_path) == LOCK_TOKEN:
                    lock_path.unlink()
        finally:
            os.close(descriptor)


def validate_journal(root: Path, journal: dict) -> list:
    if journal.get("schema") != "bear-basm-install-transaction-v1" or journal.get("phase") not in ("prepared", "committed"):
        raise ValueError("unrecognized installation recovery journal")
    entries = journal.get("entries")
    if not isinstance(entries, list) or len(entries) > 4096:
        raise ValueError("invalid installation recovery journal")
    seen = set()
    for entry in entries:
        name, backup = entry.get("path"), entry.get("backup")
        if not isinstance(name, str) or name in seen or not (managed_path(name) or name == INSTALL_MANIFEST):
            raise ValueError("unsafe recovery destination")
        seen.add(name)
        reject_symlink_parents((root / name).parent)
        for field in ("old_sha256", "new_sha256"):
            if entry.get(field) is not None and not re.fullmatch(r"[0-9a-f]{64}", entry[field]):
                raise ValueError("invalid recovery file identity")
        if backup is not None:
            if (not isinstance(backup, str) or not safe_relative(backup) or
                    PurePosixPath(backup).parent != PurePosixPath(name).parent or
                    not PurePosixPath(backup).name.startswith(".bear-basm-backup-") or
                    entry.get("old_sha256") is None):
                raise ValueError("unsafe recovery backup")
            saved = root / backup
            if saved.exists() or saved.is_symlink():
                if sha256(regular(saved)) != entry["old_sha256"]:
                    raise ValueError("installation backup was modified: " + backup)
    return entries


def cleanup_journal(root: Path, journal: dict) -> None:
    for entry in validate_journal(root, journal):
        if entry.get("backup"):
            (root / entry["backup"]).unlink(missing_ok=True)
    (root / JOURNAL).unlink(missing_ok=True)


def recover(root: Path) -> None:
    path = root / JOURNAL
    if not path.exists() and not path.is_symlink():
        return
    journal = json.loads(regular(path))
    entries = validate_journal(root, journal)
    if journal["phase"] == "committed":
        cleanup_journal(root, journal)
        return
    # Validate the complete recovery before modifying anything. Unknown user
    # replacements are preserved rather than overwritten by an old transaction.
    for entry in entries:
        target = root / entry["path"]
        current = sha256(regular(target)) if target.exists() or target.is_symlink() else None
        if current not in (entry.get("old_sha256"), entry.get("new_sha256"), None):
            raise ValueError("recovery found a separately modified file: " + str(target))
        backup = root / entry["backup"] if entry.get("backup") else None
        if entry.get("old_sha256") is not None and (backup is None or not backup.exists()) and current != entry["old_sha256"]:
            raise ValueError("installation recovery backup is unavailable")
    for entry in entries:
        target = root / entry["path"]
        backup = root / entry["backup"] if entry.get("backup") else None
        if entry.get("old_sha256") is None:
            target.unlink(missing_ok=True)
        elif backup is not None and backup.exists():
            # Same-directory hardlinks let rollback restore old bytes even when
            # there is no free space for a second copy of the executable.
            os.replace(backup, target)
    cleanup_journal(root, journal)


def prepare_transaction(root: Path, replacements: dict) -> dict:
    if (root / JOURNAL).exists() or (root / JOURNAL).is_symlink():
        raise ValueError("a previous installation transaction needs recovery")
    token = uuid.uuid4().hex
    journal = {"schema": "bear-basm-install-transaction-v1", "phase": "prepared", "entries": []}
    try:
        for index, (name, replacement) in enumerate(sorted(replacements.items())):
            target = root / name
            reject_symlink_parents(target.parent)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = regular(target) if target.exists() or target.is_symlink() else None
            backup = None
            if content is not None:
                backup = str(PurePosixPath(name).parent / (".bear-basm-backup-" + token + "-" + str(index)))
                os.link(target, root / backup, follow_symlinks=False)
            journal["entries"].append({"path": name, "backup": backup,
                                       "old_sha256": sha256(content) if content is not None else None,
                                       "new_sha256": sha256(replacement[0]) if replacement is not None else None})
        validate_journal(root, journal)
        atomic_write(root / JOURNAL, (json.dumps(journal, sort_keys=True) + "\n").encode(), 0o644)
        return journal
    except BaseException:
        # No product bytes have changed yet.
        for entry in journal["entries"]:
            if entry.get("backup"):
                (root / entry["backup"]).unlink(missing_ok=True)
        raise


def payload_from_source(root: Path, build_dir: Path) -> tuple[dict, str]:
    receipt_data = regular(build_dir / "build-receipt.json")
    receipt = json.loads(receipt_data)
    if receipt.get("schema") != "bear-basm-build-v1" or receipt.get("status") != "BUILT":
        raise ValueError("successful standalone build receipt required")
    if receipt.get("lane") != "sovereign":
        raise ValueError("make install accepts the sovereign lane; use host diagnostics directly from build/host")
    if receipt.get("target") != "linux-x86_64" or receipt.get("version") != regular(root / "VERSION").decode().strip():
        raise ValueError("build version or platform does not match the installation contract")
    binary = regular(build_dir / "basm")
    if receipt.get("artifacts", {}).get("basm") != {"sha256": sha256(binary), "bytes": len(binary)}:
        raise ValueError("binary and build receipt do not match")
    if not receipt.get("source_inputs"):
        raise ValueError("build receipt does not identify its sources")
    for name, expected in receipt["source_inputs"].items():
        if not safe_relative(name):
            raise ValueError("unsafe source path in build receipt")
        content = regular(root / name)
        if expected != {"sha256": sha256(content), "bytes": len(content)}:
            raise ValueError("source changed since the build: " + name)
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
    payload = {"bin/basm": (binary, 0o755),
               "share/doc/bear-basm/build-receipt.json": (receipt_data, 0o644),
               INSTALLER: (regular(Path(__file__).resolve()), 0o644)}
    for name in names:
        payload["share/doc/bear-basm/" + name] = (regular(root / name), 0o644)
    return payload, receipt["version"]


def payload_from_package(root: Path) -> tuple[dict, str]:
    manifest = json.loads(regular(root / "MANIFEST.json"))
    if manifest.get("schema") != "bear-basm-package-v1" or manifest.get("kind") != "binary":
        raise ValueError("a binary package manifest is required")
    if manifest.get("build_lane") != "sovereign":
        raise ValueError("the installer accepts sovereign packages; run host diagnostics directly")
    payload = {}
    seen = set()
    for record in manifest.get("files", []):
        name = record["path"]
        if not safe_relative(name) or name in seen:
            raise ValueError("unsafe or duplicate package entry")
        seen.add(name)
        data = regular(root / name)
        if sha256(data) != record["sha256"] or len(data) != record["bytes"]:
            raise ValueError("package file failed SHA-256 verification: " + name)
        if name == "bin/basm":
            target, mode = "bin/basm", 0o755
        elif name == "install.py":
            target, mode = INSTALLER, 0o644
        elif name.startswith("bin/"):
            raise ValueError("unexpected executable in package: " + name)
        else:
            target, mode = "share/doc/bear-basm/" + name, 0o644
        payload[target] = (data, mode)
    if "bin/basm" not in payload or INSTALLER not in payload:
        raise ValueError("binary package is incomplete")
    receipt_path = "share/doc/bear-basm/build-receipt.json"
    if receipt_path not in payload:
        raise ValueError("binary package does not contain its build receipt")
    receipt_data = payload[receipt_path][0]
    receipt = json.loads(receipt_data)
    binary = payload["bin/basm"][0]
    if (manifest.get("build_receipt_sha256") != sha256(receipt_data) or
            receipt.get("schema") != "bear-basm-build-v1" or receipt.get("status") != "BUILT" or
            receipt.get("lane") != "sovereign" or receipt.get("target") != "linux-x86_64" or
            receipt.get("version") != manifest.get("version") or
            receipt.get("artifacts", {}).get("basm") != {"sha256": sha256(binary), "bytes": len(binary)}):
        raise ValueError("package and build provenance are inconsistent")
    return payload, manifest["version"]


def install_locked(root: Path, payload: dict, version: str) -> int:
    reject_symlink_parents(root)
    previous = previous_manifest(root)
    old = previous.get("files", {})
    preflight_owned(root, old)
    for name in payload:
        if not managed_path(name):
            raise ValueError("refusing unmanaged destination: " + name)
        target = root / name
        reject_symlink_parents(target.parent)
        if (target.exists() or target.is_symlink()) and name not in old:
            raise ValueError("refusing to overwrite an unrelated file: " + str(target))
    records = {name: {"sha256": sha256(data), "bytes": len(data), "mode": mode}
               for name, (data, mode) in sorted(payload.items())}
    manifest = {"schema": SCHEMA, "version": version, "files": records}
    replacements = dict(payload)
    replacements.update({name: None for name in set(old) - set(payload)})
    replacements[INSTALL_MANIFEST] = ((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o644)
    journal = prepare_transaction(root, replacements)
    try:
        order = sorted(payload, key=lambda name: (name == "bin/basm", name))
        for name in order:
            data, mode = payload[name]
            atomic_write(root / name, data, mode)
        for name in sorted(set(old) - set(payload)):
            (root / name).unlink(missing_ok=True)
        data, mode = replacements[INSTALL_MANIFEST]
        atomic_write(root / INSTALL_MANIFEST, data, mode)
        journal["phase"] = "committed"
        atomic_write(root / JOURNAL, (json.dumps(journal, sort_keys=True) + "\n").encode(), 0o644)
        cleanup_journal(root, journal)
    except BaseException as original:
        try:
            recover(root)
        except (OSError, ValueError) as recovery:
            raise RuntimeError("installation failed and retained its recovery journal: " + str(recovery)) from original
        raise
    print("Installed BearBasm " + version + " at " + str(root / "bin/basm"))
    print("Uninstall: " + shlex.join(["python3", str(root / INSTALLER), "--uninstall", "--prefix", str(root)]))
    return 0


def install(root: Path, payload: dict, version: str) -> int:
    reject_symlink_parents(root)
    # Catch a first-install collision without even creating our lock directory.
    if not (root / INSTALL_MANIFEST).exists() and not (root / JOURNAL).exists():
        for name in payload:
            if (root / name).exists() or (root / name).is_symlink():
                raise ValueError("refusing to overwrite an unrelated file: " + str(root / name))
    with prefix_lock(root):
        recover(root)
        return install_locked(root, payload, version)


def uninstall_locked(root: Path) -> int:
    previous = previous_manifest(root)
    if not previous:
        raise ValueError("no BearBasm installation manifest at " + str(root))
    records = previous["files"]
    preflight_owned(root, records)
    for name in sorted(records):
        (root / name).unlink(missing_ok=True)
    (root / INSTALL_MANIFEST).unlink()
    # Leave directories alone: they may contain files belonging to other tools.
    print("Removed the unchanged files owned by BearBasm from " + str(root))
    return 0


def uninstall(root: Path) -> int:
    if not (root / INSTALL_MANIFEST).exists() and not (root / JOURNAL).exists():
        raise ValueError("no BearBasm installation manifest at " + str(root))
    with prefix_lock(root):
        recover(root)
        return uninstall_locked(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", default=str(Path.home() / ".local"))
    parser.add_argument("--destdir", default="")
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    try:
        root = destination_root(args.prefix, args.destdir)
        if args.uninstall:
            if args.build_dir:
                raise ValueError("--uninstall does not accept --build-dir")
            return uninstall(root)
        if args.build_dir:
            source_root = Path(__file__).resolve().parents[1]
            payload, package_version = payload_from_source(source_root, args.build_dir.resolve())
        else:
            payload, package_version = payload_from_package(Path(__file__).resolve().parent)
        return install(root, payload, package_version)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print("basm install: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
