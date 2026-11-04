#!/usr/bin/env python3
"""Synthetic evidence-integrity regressions; never executes an assembler."""
import os
from pathlib import Path
import tempfile
import unittest

from nasm_artifacts import ArtifactLedger


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.ledger = ArtifactLedger(self.directory)

    def tearDown(self):
        self.temporary.cleanup()

    def retained(self, data=b"\x7fELF-synthetic-object"):
        path = self.ledger.reserve_object("nasm")
        path.write_bytes(data)
        self.ledger.capture(path, "assembly_output", single_link=True)
        return path

    def test_unique_equal_length_outputs_and_intact_evidence(self):
        paths = [self.ledger.reserve_object(role) for role in ("nasm", "basm") * 12]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(len({len(str(path)) for path in paths}), 1)
        for path in paths:
            path.write_bytes(b"object")
            self.ledger.capture(path, "assembly_output", single_link=True)
        self.assertEqual(self.ledger.verify()["status"], "PASS")

    def test_synthetic_old_alias_truncation_is_detected(self):
        path = self.retained()
        snapshot = self.directory / "before.object"
        snapshot.write_bytes(path.read_bytes())
        self.ledger.capture(snapshot, "parity_snapshot", single_link=True)
        path.write_bytes(b"")
        result = self.ledger.verify()
        self.assertEqual(result["status"], "DRIFT")
        self.assertEqual(result["failed"], [str(path)])
        self.assertEqual(snapshot.read_bytes(), b"\x7fELF-synthetic-object")

    def test_same_size_corruption_is_detected(self):
        path = self.retained(b"ABCD")
        path.write_bytes(b"ABCE")
        self.assertEqual(self.ledger.verify()["status"], "DRIFT")

    def test_same_content_inode_replacement_is_detected(self):
        path = self.retained()
        replacement = self.directory / "replacement"
        replacement.write_bytes(path.read_bytes())
        replacement.replace(path)
        self.assertEqual(self.ledger.verify()["status"], "DRIFT")

    def test_deleted_output_is_detected(self):
        self.retained().unlink()
        self.assertEqual(self.ledger.verify()["status"], "DRIFT")

    def test_reused_capture_and_path_are_refused(self):
        path = self.retained()
        with self.assertRaises(RuntimeError):
            self.ledger.capture(path, "assembly_output", single_link=True)
        with self.assertRaises(RuntimeError):
            self.ledger.expect_absent(path, "assembly_output", single_link=True)

    def test_missing_failed_output_must_remain_absent(self):
        path = self.ledger.reserve_object("basm")
        self.assertEqual(self.ledger.verify()["status"], "PASS")
        path.write_bytes(b"appeared later")
        self.assertEqual(self.ledger.verify()["status"], "DRIFT")

    def test_symlink_output_is_refused(self):
        target = self.directory / "target"
        target.write_bytes(b"object")
        path = self.ledger.reserve_object("nasm")
        path.symlink_to(target)
        with self.assertRaises(RuntimeError):
            self.ledger.capture(path, "assembly_output", single_link=True)

    def test_hardlinked_output_is_refused(self):
        target = self.directory / "target"
        target.write_bytes(b"object")
        path = self.ledger.reserve_object("nasm")
        os.link(target, path)
        with self.assertRaises(RuntimeError):
            self.ledger.capture(path, "assembly_output", single_link=True)

    def test_changed_permissions_are_detected(self):
        path = self.retained()
        path.chmod(0o400)
        self.assertEqual(self.ledger.verify()["status"], "DRIFT")

    def test_namespace_exhaustion_cannot_grow_or_reuse_names(self):
        self.ledger.next_object = 999999
        self.ledger.reserve_object("nasm")
        with self.assertRaises(ValueError):
            self.ledger.reserve_object("basm")


if __name__ == "__main__":
    unittest.main()
