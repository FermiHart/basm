#!/usr/bin/env python3
"""Independent regressions for key ownership and generation verification.

Uses the explicitly supplied assembler and synthetic local keys. No emitted
object is executed. A deterministic file-swap schedule tests that provenance
claims and signature verification consume the same captured proof bytes.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SEED = bytes(range(32))


def fingerprint(path):
    content = path.read_bytes()
    return {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}


class ReviewRegressions(unittest.TestCase):
    records = []

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="basm-review-regressions-")
        cls.root = Path(cls.temporary.name)
        cls.env = dict(os.environ, SOURCE_DATE_EPOCH="0")
        cls.env.pop("BASM_DDC_COMPILER_HASH", None)
        cls.env.pop("BASM_DDC_COMPILER_PATH", None)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.work = self.root / self._testMethodName
        self.work.mkdir()
        self.source = self.work / "input.basm"
        self.source.write_text("bits 64\nsection .text\nglobal entry\nentry: ret\n")

    def command(self, label, argv, expected=0, timeout=15):
        result = subprocess.run([str(x) for x in argv], env=self.env,
                                capture_output=True, text=True, timeout=timeout)
        self.records.append({"test": self._testMethodName, "case": label,
                             "returncode": result.returncode, "expected": expected,
                             "stderr": result.stderr[-1500:]})
        self.assertEqual(result.returncode, expected, (label, result.stdout, result.stderr))
        return result

    def publish(self, store, extra=()):
        result = self.command("publish complete generation", [sys.executable, PUBLISHER,
                "publish", "--basm", BASM, "--root", store, "--source", self.source, *extra])
        return json.loads(result.stdout)

    def verify(self, store, expected=0, timeout=15):
        return self.command("verify generation", [sys.executable, PUBLISHER,
                "verify", "--basm", BASM, "--root", store], expected, timeout)

    def test_01_publication_cannot_replace_any_key_input(self):
        for mode in ("attestation", "exec-proof", "cache"):
            for destination in ("object", "proof"):
                for alias in ("same", "dot", "hardlink", "symlink"):
                    with self.subTest(key=mode, destination=destination, alias=alias):
                        work = self.work / (mode + "-" + destination + "-" + alias)
                        work.mkdir()
                        seed = work / "key.seed"
                        seed.write_bytes(SEED)
                        seed.chmod(0o600)
                        if alias == "same":
                            key_alias = str(seed)
                        elif alias == "dot":
                            key_alias = str(work) + "/./key.seed"
                        else:
                            target = work / "alias.seed"
                            if alias == "hardlink":
                                os.link(seed, target)
                            else:
                                target.symlink_to(seed)
                            key_alias = str(target)
                        obj, proof = work / "out.o", work / "out.proof"
                        obj.write_bytes(b"PREVIOUS OBJECT")
                        proof.write_bytes(b"PREVIOUS PROOF")
                        out_arg = key_alias if destination == "object" else str(obj)
                        proof_arg = key_alias if destination == "proof" else str(proof)
                        extra = {"attestation": ["--sign", seed],
                                 "exec-proof": ["--emit-exec-proof", "--sign-exec-proof", seed],
                                 "cache": ["--rel8-escrow", work / "cache", "--rel8-key", seed]}[mode]
                        result = self.command("protect " + mode + " " + destination + " " + alias,
                                              [BASM, "--target-profile", "public", "-o", out_arg,
                                               "--emit-attestation-v4", proof_arg, *extra, self.source], 1)
                        self.assertIn("publication would replace a signing or cache key", result.stderr)
                        self.assertEqual(seed.read_bytes(), SEED)
                        self.assertEqual(obj.read_bytes(), b"PREVIOUS OBJECT")
                        self.assertEqual(proof.read_bytes(), b"PREVIOUS PROOF")

    def test_02_generation_directory_symlink_is_rejected(self):
        store = self.work / "store"
        manifest = self.publish(store)
        generation = store / "generations" / manifest["generation"]
        outside = self.work / "outside-generation"
        generation.rename(outside)
        generation.symlink_to(outside, target_is_directory=True)
        self.assertFalse((generation / "object.o").resolve().is_relative_to(store.resolve()))
        self.verify(store, 1)

    def test_03_generations_parent_symlink_is_rejected(self):
        store = self.work / "store"
        self.publish(store)
        pointer = (store / "current.json").read_bytes()
        generations = store / "generations"
        outside = self.work / "outside-generations"
        generations.rename(outside)
        generations.symlink_to(outside, target_is_directory=True)
        self.verify(store, 1)
        before = sorted(p.name for p in outside.iterdir())
        self.command("publish into linked parent", [sys.executable, PUBLISHER, "publish",
                     "--basm", BASM, "--root", store, "--source", self.source], 1)
        self.assertEqual((store / "current.json").read_bytes(), pointer)
        self.assertEqual(sorted(p.name for p in outside.iterdir()), before)

    def test_04_fifo_generation_member_is_rejected_without_opening(self):
        store = self.work / "store"
        manifest = self.publish(store)
        member = store / manifest["files"]["object"]["path"]
        member.unlink()
        os.mkfifo(member)
        self.verify(store, 1, timeout=3)

    def test_05_leaf_symlink_remains_rejected(self):
        store = self.work / "store"
        manifest = self.publish(store)
        member = store / manifest["files"]["object"]["path"]
        outside = self.work / "outside.o"
        member.rename(outside)
        member.symlink_to(outside)
        self.verify(store, 1)

    def test_06_fifo_manifest_is_rejected_without_opening(self):
        store = self.work / "store"
        store.mkdir()
        os.mkfifo(store / "current.json")
        self.verify(store, 1, timeout=3)

    def test_07_signature_and_output_claim_share_one_snapshot(self):
        seed = self.work / "seed"
        seed.write_bytes(SEED)
        seed.chmod(0o600)
        object_b, proof_b = self.work / "signed-b.o", self.work / "signed-b.proof"
        self.command("prepare authentic B", [BASM, "--target-profile", "public", "-o", object_b,
                     "--emit-attestation-v4", proof_b, "--sign", seed, self.source])
        authentic = proof_b.read_bytes()
        pubhex = next(line.split(b": ", 1)[1] for line in authentic.splitlines()
                      if line.startswith(b"signature_pub: "))
        trusted = self.work / "trusted.pub"
        trusted.write_bytes(bytes.fromhex(pubhex.decode()))
        self.command("authentic B accepted", [BASM, "--verify-attestation-strict", proof_b,
                                               "--trusted-key", trusted])
        source_a, object_a = self.work / "different.basm", self.work / "unsigned-a.o"
        source_a.write_text("bits 64\nsection .text\nglobal entry\nentry: mov eax, 999\nret\n")
        self.command("prepare different A", [BASM, "--target-profile", "public", "-o", object_a, source_a])
        hash_a, hash_b = fingerprint(object_a)["sha256"], fingerprint(object_b)["sha256"]
        self.assertNotEqual(hash_a, hash_b)
        forged = authentic.replace(("output_sha256: " + hash_b).encode(),
                                   ("output_sha256: " + hash_a).encode())
        store = self.work / "mixed-store"
        generation = store / "generations" / "generation-interleaving"
        generation.mkdir(parents=True)
        member_object, member_proof = generation / "object.o", generation / "object.basmproof"
        member_object.write_bytes(object_a.read_bytes())
        member_proof.write_bytes(forged)
        manifest = {"schema": "basm-generation-v1", "generation": generation.name,
                    "trust": "external-key-verified", "files": {}}
        for name, path in (("object", member_object), ("attestation", member_proof)):
            manifest["files"][name] = {"path": str(path.relative_to(store)), **fingerprint(path)}
        (store / "current.json").write_text(json.dumps(manifest))
        self.command("forged A rejected without swap", [BASM, "--verify-attestation-strict",
                     member_proof, "--trusted-key", trusted], 1)
        spec = importlib.util.spec_from_file_location("generation_review_target", PUBLISHER)
        publisher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(publisher)
        original_command = publisher.command
        swaps = []

        def scheduled_file_swap(argv):
            if any(str(arg).startswith("--verify-attestation") for arg in argv):
                # Equivalent to another writer replacing this public pathname
                # after claims were read. Never alter the verifier's private copy.
                member_proof.write_bytes(authentic)
                swaps.append(True)
            return original_command(argv)

        args = SimpleNamespace(root=store, basm=str(BASM), trusted_key=str(trusted),
                               contract=None, contract_target=None, source=None)
        with patch.object(publisher, "command", side_effect=scheduled_file_swap):
            with self.assertRaises((OSError, ValueError, RuntimeError)):
                publisher.verify(args)
        self.assertEqual(len(swaps), 1, "test must reach the proof-verification boundary")
        self.records.append({"test": self._testMethodName, "case": "deterministic proof-read schedule",
                             "scheduled_swaps": len(swaps), "accepted_wrong_object": False})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--publisher", type=Path, default=ROOT / "tools/publish_generation.py")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    BASM = args.basm.resolve()
    PUBLISHER = args.publisher.resolve()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReviewRegressions)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "BASM-REVIEW-REGRESSIONS-v1", "status": "PASS" if result.wasSuccessful() else "FAIL",
              "test_groups": result.testsRun, "command_executions": sum("returncode" in r for r in ReviewRegressions.records),
              "command_count_scope": "direct subprocess calls recorded by this harness; excludes publisher descendants",
              "basm": fingerprint(BASM), "publisher": fingerprint(PUBLISHER),
              "records": ReviewRegressions.records, "object_execution": False,
              "external_differential_oracle": "NOT_TESTED_BY_THIS_SUITE"}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "test_groups", "command_executions")}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
