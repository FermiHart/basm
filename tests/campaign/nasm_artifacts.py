#!/usr/bin/env python3
"""Immutable-by-convention benchmark evidence with fail-closed end checks.

This detects missing/replaced/truncated evidence; it does not establish the cause
of the two mutable aliases found in the previous benchmark. No measured process
or assembler implementation is involved in this module.
"""
import hashlib
import os
from pathlib import Path
import stat


def _state(info):
    return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "nlink": info.st_nlink, "bytes": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def file_identity(path, single_link=False):
    """Read a regular file without accepting a final symlink or a changing read."""
    path = Path(os.path.abspath(path))
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink != 1):
        raise RuntimeError("evidence must be a regular, unaliased file: " + str(path))
    digest = hashlib.sha256()
    count = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            count += len(block)
            digest.update(block)
        closed = os.fstat(stream.fileno())
    after = path.lstat()
    if not (_state(before) == _state(opened) == _state(closed) == _state(after)) or count != after.st_size:
        raise RuntimeError("evidence changed while reading: " + str(path))
    return {"path": str(path), "bytes": count, "sha256": digest.hexdigest(),
            "file_state": _state(after)}


class ArtifactLedger:
    """Allocate once, capture once, and re-read every retained identity at end."""
    def __init__(self, output_directory):
        self.output_directory = Path(output_directory).resolve()
        self.objects = self.output_directory / "objects"
        self.objects.mkdir()
        self.next_object = 0
        self.entries = {}

    def reserve_object(self, role):
        if role not in ("basm", "nasm") or self.next_object >= 1000000:
            raise ValueError("invalid role or exhausted fixed-width object namespace")
        path = self.objects / ("%06d-%s.o" % (self.next_object, role))
        self.next_object += 1
        self.expect_absent(path, "assembly_output", single_link=True)
        return path

    def expect_absent(self, path, kind, single_link=False):
        path = Path(os.path.abspath(path))
        key = str(path)
        if key in self.entries or os.path.lexists(path):
            raise RuntimeError("evidence path is not fresh: " + key)
        self.entries[key] = {"path": key, "kind": kind, "single_link": single_link,
                             "expected": None}

    def capture(self, path, kind, single_link=False):
        path = Path(os.path.abspath(path))
        key = str(path)
        prior = self.entries.get(key)
        if prior and prior["expected"] is not None:
            raise RuntimeError("evidence path was already captured: " + key)
        if prior and (prior["kind"] != kind or prior["single_link"] != single_link):
            raise RuntimeError("evidence reservation changed: " + key)
        expected = file_identity(path, single_link)
        self.entries[key] = {"path": key, "kind": kind, "single_link": single_link,
                             "expected": expected}
        return {key: expected[key] for key in ("path", "bytes", "sha256")}

    def verify(self):
        checks = []
        for entry in self.entries.values():
            check = dict(entry)
            try:
                actual = (file_identity(entry["path"], entry["single_link"])
                          if os.path.lexists(entry["path"]) else None)
                check.update({"actual": actual, "matches": actual == entry["expected"]})
            except (OSError, RuntimeError) as exc:
                check.update({"actual": None, "matches": False, "error": str(exc)})
            checks.append(check)
        failed = [entry["path"] for entry in checks if not entry["matches"]]
        return {"schema": "BASM-NASM-ARTIFACT-LEDGER-v1", "status": "PASS" if not failed else "DRIFT",
                "policy": "Every invocation has a fresh fixed-width output path. Content, inode, size, mode and timestamps are checked again; absent outputs must remain absent.",
                "tracked": len(checks), "failed": failed, "entries": checks}
