#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Build and atomically select a complete object/evidence generation.

Consumers read current.json once, then verify the named immutable generation.
This is an optional host deployment boundary, separate from the assembler core.
It never executes assembled code. A failed build leaves the previous pointer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

SCHEMA = "basm-generation-v1"
MANIFEST_MAX = 16384
ARTIFACT_MAX = 1024 * 1024 * 1024


def regular_reader(path):
    # O_NONBLOCK prevents a static or substituted FIFO from blocking at open.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("generation member is not a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def digest(path):
    h = hashlib.sha256()
    size = 0
    with regular_reader(path) as stream:
        while True:
            block = stream.read(65536)
            if not block:
                break
            h.update(block)
            size += len(block)
            if size > ARTIFACT_MAX:
                raise ValueError("generation artifact exceeds size limit")
    return {"sha256": h.hexdigest(), "bytes": size}


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("command refused (%d): %s" % (result.returncode, result.stderr.strip()))
    return result


def verify_proof(basm, proof, trusted, object_digest, expected_proof=None):
    with regular_reader(proof) as stream:
        body = stream.read(16 * 1024 * 1024 + 1)
    if len(body) > 16 * 1024 * 1024:
        raise ValueError("attestation exceeds size limit")
    identity = {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
    if expected_proof is not None and identity != expected_proof:
        raise ValueError("attestation changed after manifest validation")
    # Generations require consumed-input/configuration commitments from v4.
    # Check the same body whose binding and signature are verified below;
    # the standalone basm CLI retains its separate v2/v3 compatibility policy.
    if not body.startswith(b"basm attestation v4\n"):
        raise ValueError("generation requires attestation v4")
    lines = body.splitlines()
    expected = ("output_sha256: " + object_digest).encode("ascii")
    if [line for line in lines if line.startswith(b"output_sha256:")] != [expected] or \
            [line for line in lines if line.startswith(b"output_format:")] != [b"output_format: elf64"]:
        raise ValueError("attestation does not bind this generation's object")
    # Authenticate exactly the body whose output binding was checked above.
    # Reopening the original path here allowed an A/B/ABA substitution between
    # field extraction and signature verification by the real basm verifier.
    with tempfile.TemporaryDirectory(prefix="basm-proof-snapshot-") as temporary:
        snapshot = Path(temporary) / "proof.basmproof"
        snapshot.write_bytes(body)
        argv = [basm, "--verify-attestation-strict" if trusted else "--verify-attestation", str(snapshot)]
        if trusted:
            argv += ["--trusted-key", trusted]
        command(argv)
    return identity


def verify_contract(obj, contract, source, target=None, expected=None):
    """Run the independent checker; a stored status can never authorize bytes."""
    checker = Path(__file__).resolve().with_name("contract_check.py")
    argv = [sys.executable, str(checker), "--object", str(obj), "--contract", str(contract)]
    if source:
        argv += ["--source", str(source.resolve())]
    if target:
        argv += ["--target", str(target)]
    if expected:
        argv += ["--expect", str(expected)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    if len(result.stdout) > 1024 * 1024:
        raise ValueError("contract result exceeds size limit")
    try:
        report = json.loads(result.stdout)
    except ValueError as exc:
        raise ValueError("contract checker returned invalid JSON") from exc
    if result.returncode or not isinstance(report, dict) or \
            report.get("schema") != "bearbasm-contract-result-v1" or report.get("status") != "VERIFIED_WITHIN_MODEL":
        diagnostics = report.get("diagnostics", []) if isinstance(report, dict) else []
        code = diagnostics[0].get("code", "UNKNOWN") if diagnostics and isinstance(diagnostics[0], dict) else "UNKNOWN"
        raise ValueError("independent contract checker refused: " + str(code)[:96])
    return result.stdout


def publish(args):
    root = args.root.resolve()
    generations = root / "generations"
    if generations.is_symlink():
        raise ValueError("generation directory cannot be a symlink")
    generations.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="generation-", dir=generations))
    committed = False
    pointer_temp = None
    try:
        obj, proof = stage / "object.o", stage / "object.basmproof"
        argv = [args.basm, "--target-profile", args.target_profile, "-f", "elf64",
                "-o", str(obj), "--emit-attestation-v4", str(proof)]
        if args.sign:
            argv += ["--sign", str(args.sign)]
        for path in args.include:
            argv += ["-I", path]
        for definition in args.define:
            argv += ["-D", definition]
        argv += [str(args.source.resolve())]
        command(argv)
        verified_proof = verify_proof(args.basm, proof, args.trusted_key, digest(obj)["sha256"])
        members = [("object", obj), ("attestation", proof)]
        if args.contract:
            result_path = stage / "contract-result.json"
            result_path.write_text(verify_contract(obj, args.contract, args.source, args.contract_target))
            members.append(("contract_result", result_path))
        records = {}
        for name, path in members:
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
            records[name] = {"path": str(path.relative_to(root)), **digest(path)}
            path.chmod(0o444)
        manifest = {"schema": SCHEMA, "generation": stage.name,
                    "trust": "external-key-verified" if args.trusted_key else "integrity-only",
                    "files": records}
        if {k: records["attestation"][k] for k in ("sha256", "bytes")} != verified_proof:
            raise ValueError("attestation changed before generation publication")
        encoded = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        fd, name = tempfile.mkstemp(prefix=".current-", suffix=".json", dir=root)
        pointer_temp = Path(name)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        # Completed generation directory entries precede publication of its pointer.
        if hasattr(os, "O_DIRECTORY"):
            for directory in (stage, generations):
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        os.replace(pointer_temp, root / "current.json")
        pointer_temp = None
        committed = True
        if hasattr(os, "O_DIRECTORY"):
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return manifest
    finally:
        if pointer_temp is not None:
            pointer_temp.unlink(missing_ok=True)
        if not committed:
            # Only this invocation's owned generation is eligible for cleanup.
            shutil.rmtree(stage)


def verify(args):
    root = args.root.resolve()
    with regular_reader(root / "current.json") as stream:
        raw = stream.read(MANIFEST_MAX + 1)
    if len(raw) > MANIFEST_MAX:
        raise ValueError("generation manifest exceeds size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate manifest key")
            result[key] = value
        return result
    manifest = json.loads(raw, object_pairs_hook=unique)
    if set(manifest) != {"schema", "generation", "trust", "files"} or manifest["schema"] != SCHEMA:
        raise ValueError("invalid generation manifest schema")
    generation = manifest["generation"]
    if not isinstance(generation, str) or not generation.startswith("generation-") or \
            Path(generation).name != generation or generation in (".", ".."):
        raise ValueError("invalid generation name")
    generations = root / "generations"
    directory = generations / generation
    if generations.is_symlink() or directory.is_symlink() or not directory.is_dir() or \
            directory.resolve().parent != generations.resolve():
        raise ValueError("generation directory escaped its publication root")
    file_set = set(manifest["files"])
    if file_set not in ({"object", "attestation"}, {"object", "attestation", "contract_result"}):
        raise ValueError("invalid generation file set")
    if ("contract_result" in file_set) != bool(args.contract):
        raise ValueError("contract-bearing verification requires an explicit consumer contract and the stored result")
    paths = {}
    members = [("object", "object.o"), ("attestation", "object.basmproof")]
    if args.contract:
        members.append(("contract_result", "contract-result.json"))
    for name, leaf in members:
        record = manifest["files"][name]
        expected = Path("generations") / generation / leaf
        if set(record) != {"path", "sha256", "bytes"} or record["path"] != str(expected):
            raise ValueError("generation member escaped its declared directory")
        path = root / expected
        if path.is_symlink() or not path.is_file() or path.resolve().parent != directory.resolve():
            raise ValueError("generation member is not a regular owned path")
        actual = digest(path)
        if actual != {"sha256": record["sha256"], "bytes": record["bytes"]}:
            raise ValueError("generation %s digest/size mismatch" % name)
        paths[name] = path
    verify_proof(args.basm, paths["attestation"], args.trusted_key,
                 manifest["files"]["object"]["sha256"],
                 {k: manifest["files"]["attestation"][k] for k in ("sha256", "bytes")})
    if args.contract:
        verify_contract(paths["object"], args.contract, args.source, args.contract_target, paths["contract_result"])
    # A manifest's trust label cannot grant authority; the caller supplies a key.
    return {"schema": SCHEMA, "generation": generation, "status": "verified",
            "trust": "external-key-verified" if args.trusted_key else "integrity-only",
            "contract_status": "VERIFIED_WITHIN_MODEL" if args.contract else "not-requested"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="operation", required=True)
    for name in ("publish", "verify"):
        parser = sub.add_parser(name)
        parser.add_argument("--basm", required=True)
        parser.add_argument("--root", type=Path, required=True)
        parser.add_argument("--trusted-key")
        parser.add_argument("--contract", type=Path, help="Require the independent bounded ABI contract before admission")
        parser.add_argument("--contract-target", type=Path, help="Consumer-declared CPU/OS configuration for --contract")
        parser.add_argument("--source", type=Path, required=name == "publish",
                            help="Source input; also required when verifying a source-bound contract")
        if name == "publish":
            parser.add_argument("--target-profile", choices=("public", "beyond"), default="public")
            parser.add_argument("--sign", type=Path)
            parser.add_argument("--include", action="append", default=[])
            parser.add_argument("--define", action="append", default=[])
    args = ap.parse_args()
    if args.operation == "publish" and bool(args.sign) != bool(args.trusted_key):
        ap.error("signed publication requires both --sign and an external --trusted-key")
    if args.contract_target and not args.contract:
        ap.error("--contract-target requires --contract")
    try:
        result = publish(args) if args.operation == "publish" else verify(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "reason": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
