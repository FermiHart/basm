#!/usr/bin/env python3
"""Black-box distribution CLI checks; no compiler, network, or root required."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
SOURCE = b"bits 64\nsection .text\nnop\nret\n"


class CliContract(unittest.TestCase):
    binary: Path
    build_profile: str

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="basm cli ")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / "source.basm").write_bytes(SOURCE)

    def invoke(self, *arguments: str, **kwargs):
        return subprocess.run(
            [str(self.binary), *arguments],
            cwd=self.directory,
            capture_output=True,
            text=True,
            timeout=10,
            **kwargs,
        )

    def succeeds(self, *arguments: str):
        result = self.invoke(*arguments)
        self.assertEqual(result.returncode, 0, (arguments, result.stderr))
        return result

    def refuses(self, *arguments: str):
        before = (self.directory / "source.basm").read_bytes()
        result = self.invoke(*arguments)
        self.assertNotEqual(result.returncode, 0, arguments)
        self.assertGreater(result.returncode, 0, "CLI refusal must not crash")
        self.assertTrue(result.stderr, arguments)
        self.assertEqual((self.directory / "source.basm").read_bytes(), before)
        return result

    def test_help_is_available_without_source_or_output(self):
        for flag in ("--help", "-h"):
            with self.subTest(flag=flag):
                result = self.succeeds(flag)
                self.assertIn("Usage:", result.stdout)
                self.assertIn("--trusted-key", result.stdout)
                self.assertIn("--target-profile", result.stdout)
                self.assertIn(VERSION, result.stdout)
                self.assertEqual(result.stderr, "")
                self.assertFalse((self.directory / "a.out.o").exists())

    def test_version_is_deterministic_and_matches_distribution(self):
        expected = f"BearBasm {VERSION} ({self.build_profile})\n"
        first = self.succeeds("--version")
        second = self.succeeds("--version")
        self.assertEqual(first.stdout, expected)
        self.assertEqual(second.stdout, expected)
        self.assertEqual(first.stderr, "")
        self.assertFalse((self.directory / "a.out.o").exists())

    def test_help_and_version_do_not_hide_conflicting_work(self):
        cases = (
            ("--help", "source.basm"),
            ("--version", "-o", "forbidden.o", "source.basm"),
            ("--help", "--version"),
            ("--help", "--capabilities"),
            ("--help", "-g"),
            ("--version", "-Wall"),
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.refuses(*arguments)
                self.assertIn("help/version", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse((self.directory / "forbidden.o").exists())
                self.assertFalse((self.directory / "a.out.o").exists())
        self.succeeds("--target-profile", "public", "--help")

    def test_spaces_and_leading_dash_input_names(self):
        for index, name in enumerate(("source with spaces.basm", "-source.basm", "--diagnostics-json", "--profile")):
            with self.subTest(name=name):
                (self.directory / name).write_bytes(SOURCE)
                output = f"output {index}.bin"
                result = self.succeeds("-f", "bin", "-o", output, "--", name)
                self.assertEqual((self.directory / output).read_bytes(), b"\x90\xc3")
                self.assertEqual((self.directory / name).read_bytes(), SOURCE)
                self.assertEqual(result.stderr, "")

    def test_double_dash_is_not_a_second_options_pass(self):
        (self.directory / "--version").write_bytes(SOURCE)
        result = self.succeeds("-f", "bin", "-o", "out.bin", "--", "--version")
        self.assertEqual(result.stdout, "")
        self.assertEqual((self.directory / "out.bin").read_bytes(), b"\x90\xc3")
        self.refuses("-o", "rejected.o", "--", "source.basm", "--version")
        self.assertFalse((self.directory / "rejected.o").exists())

    def test_option_values_named_like_flags_remain_data(self):
        for name in ("--diagnostics-json", "--profile", "--help", "--version", "--"):
            with self.subTest(name=name):
                result = self.succeeds("-f", "bin", "-o", name, "source.basm")
                self.assertEqual((self.directory / name).read_bytes(), b"\x90\xc3")
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")
        (self.directory / "bad.basm").write_text("not_an_instruction\n", encoding="utf-8")
        result = self.refuses("-o", "--diagnostics-json", "bad.basm")
        self.assertFalse(result.stderr.startswith("{"), result.stderr)

    def test_diagnostics_lookahead_respects_option_arity_and_terminator(self):
        result = self.refuses("--unknown", "--diagnostics-json")
        diagnostic = json.loads(result.stderr)
        self.assertEqual(diagnostic["schema"], "basm-diagnostic-v1")
        self.assertEqual(diagnostic["severity"], "error")
        for arguments in (
            ("--target-profile", "--diagnostics-json"),
            ("--unknown", "--", "--diagnostics-json"),
            ("--unknown", "-D", "--diagnostics-json"),
        ):
            with self.subTest(arguments=arguments):
                result = self.refuses(*arguments)
                self.assertFalse(result.stderr.startswith("{"), result.stderr)
        result = self.refuses("-o", "--diagnostics-json", "--diagnostics-json", "missing.basm")
        self.assertEqual(json.loads(result.stderr)["severity"], "error")

    def test_singletons_cannot_silently_override_previous_values(self):
        cases = (
            ("-o", "first.o", "-o", "second.o", "source.basm"),
            ("-f", "elf64", "-f", "bin", "source.basm"),
            ("--target-profile", "public", "--target-profile", "public", "source.basm"),
            ("--sign", "key1", "--sign", "key2", "source.basm"),
            ("--sign-exec-proof", "key1", "--sign-exec-proof", "key2", "source.basm"),
            ("--trusted-key", "key1", "--trusted-key", "key2"),
            ("--verify-attestation", "a", "--verify-attestation-strict", "b"),
            ("--verify-attestation-strict", "a", "--verify-attestation", "b"),
            ("--rel8-escrow", "a", "--rel8-escrow", "b", "source.basm"),
            ("--rel8-key", "a", "--rel8-key", "b", "source.basm"),
            ("--emit-attestation", "a", "--emit-attestation-v4", "b", "source.basm"),
            ("--emit-exec-proof", "--emit-exec-proof", "source.basm"),
            ("--profile", "--profile", "source.basm"),
            ("--explain", "--explain", "source.basm"),
            ("--diagnostics-json", "--diagnostics-json", "source.basm"),
            ("--capabilities", "--capabilities"),
            ("--list-instructions", "--list-forms"),
            ("--batch", "a", "--batch", "b"),
            ("--jobs", "1", "--jobs", "2"),
            ("--help", "-h"),
            ("--version", "--version"),
            ("-F", "dwarf", "-F", "dwarf", "source.basm"),
            ("-g", "-g", "source.basm"),
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.refuses(*arguments)
                self.assertIn("duplicate", result.stderr)
                for path in ("first.o", "second.o", "a.out.o", "a", "b"):
                    self.assertFalse((self.directory / path).exists(), (arguments, path))

    def test_missing_and_empty_option_values_fail_without_output(self):
        options = (
            "-f", "-o", "-I", "-D", "-F", "--target-profile", "--jobs", "--batch",
            "--emit-attestation", "--emit-attestation-v4", "--sign", "--trusted-key",
            "--verify-attestation", "--verify-attestation-strict", "--sign-exec-proof",
            "--rel8-escrow", "--rel8-key", "--bootstrap",
        )
        for option in options:
            for suffix in ((), ("",)):
                with self.subTest(option=option, suffix=suffix):
                    self.refuses(option, *suffix)
                    self.assertFalse((self.directory / "a.out.o").exists())

    def test_repeatable_defines_and_include_paths_still_work(self):
        (self.directory / "included").mkdir()
        (self.directory / "included" / "value.inc").write_text("db X, Y\n", encoding="utf-8")
        (self.directory / "source.basm").write_text('%include "value.inc"\n', encoding="utf-8")
        self.succeeds("-I", "missing", "-Iincluded", "-DX=7", "-D", "Y=8",
                      "-f", "bin", "-o", "out.bin", "source.basm")
        self.assertEqual((self.directory / "out.bin").read_bytes(), b"\x07\x08")

    def test_object_cannot_replace_source_or_its_alias(self):
        source = self.directory / "source.basm"
        os.link(source, self.directory / "hardlink.o")
        (self.directory / "symlink.o").symlink_to("source.basm")
        for output in ("source.basm", "./source.basm", "hardlink.o", "symlink.o"):
            with self.subTest(output=output):
                result = self.refuses("-o", output, "source.basm")
                self.assertIn("publication would replace an input dependency", result.stderr)
                self.assertEqual((self.directory / output).read_bytes(), SOURCE)
        self.assertTrue((self.directory / "symlink.o").is_symlink())

    def test_proof_cannot_replace_source_or_its_alias(self):
        os.link(self.directory / "source.basm", self.directory / "hardlink.proof")
        (self.directory / "symlink.proof").symlink_to("source.basm")
        for proof in ("source.basm", "./source.basm", "hardlink.proof", "symlink.proof"):
            with self.subTest(proof=proof):
                result = self.refuses("-o", "out.o", "--emit-attestation", proof, "source.basm")
                self.assertIn("publication would replace an input dependency", result.stderr)
                self.assertEqual((self.directory / proof).read_bytes(), SOURCE)
                self.assertFalse((self.directory / "out.o").exists())

    def test_output_and_proof_alias_is_rejected_before_publication(self):
        (self.directory / "parent-alias").symlink_to(".", target_is_directory=True)
        for proof in ("out.o", "./out.o", "parent-alias/out.o"):
            with self.subTest(proof=proof):
                result = self.refuses("-o", "out.o", "--emit-attestation", proof, "source.basm")
                self.assertIn("object and attestation paths alias", result.stderr)
                self.assertFalse((self.directory / "out.o").exists())

    def test_included_inputs_are_protected(self):
        included = self.directory / "included.inc"
        included.write_bytes(b"nop\nret\n")
        (self.directory / "source.basm").write_text('%include "included.inc"\n', encoding="utf-8")
        result = self.refuses("-o", "included.inc", "source.basm")
        self.assertIn("publication would replace an input dependency", result.stderr)
        self.assertEqual(included.read_bytes(), b"nop\nret\n")

    def test_failed_assembly_preserves_previous_output(self):
        (self.directory / "out.o").write_bytes(b"previous successful artifact")
        (self.directory / "source.basm").write_text("not_an_instruction\n", encoding="utf-8")
        self.refuses("-o", "out.o", "source.basm")
        self.assertEqual((self.directory / "out.o").read_bytes(), b"previous successful artifact")

    def test_explicit_profiles_remain_available_only_in_their_build(self):
        result = self.succeeds("--target-profile", "public", "--capabilities")
        manifest = json.loads(result.stdout)
        self.assertEqual(manifest["target_profile"], "public")
        self.assertEqual(manifest["build"], self.build_profile)
        self.assertEqual(manifest["modes"], "64")
        if self.build_profile == "public-only":
            self.refuses("--target-profile", "beyond", "--capabilities")
        else:
            result = self.succeeds("--target-profile", "beyond", "--capabilities")
            self.assertEqual(json.loads(result.stdout)["target_profile"], "beyond")

    @unittest.skipUnless(Path("/dev/full").exists(), "requires POSIX /dev/full")
    def test_information_commands_report_stdout_write_errors(self):
        for flag in ("--help", "--version", "--capabilities", "--list-forms", "--list-instructions"):
            with self.subTest(flag=flag), open("/dev/full", "wb") as sink:
                result = subprocess.run([str(self.binary), flag], cwd=self.directory,
                                        stdout=sink, stderr=subprocess.PIPE, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertGreater(result.returncode, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, default=Path(os.environ.get("BASM", ROOT / "build/host/basm")))
    parser.add_argument("--compat", type=Path, help="also exercise a bootstrap-capable compatibility build")
    args = parser.parse_args()
    suite = unittest.TestSuite()
    binaries = [("PublicCLI", args.basm, "public-only")]
    if args.compat is not None:
        binaries.append(("CompatibilityCLI", args.compat, "bootstrap-capable"))
    for name, binary, build_profile in binaries:
        binary = binary.resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"missing executable: {binary}")
        case = type(name, (CliContract,), {"binary": binary, "build_profile": build_profile})
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
