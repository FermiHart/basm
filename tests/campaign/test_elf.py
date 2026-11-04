#!/usr/bin/env python3
"""W02/W03: adversarial ELF64 parser and comparator regression gate.

Default: build the canonical-source harness under ASan + UBSan, with unused
attestation sections removed by the linker (no signing stub). --binary can
instead exercise a complete elftool build. No emitted object is executed.
"""

import argparse
import hashlib
import os
from pathlib import Path
import random
import shlex
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
U64_MAX = (1 << 64) - 1
COMMANDS = ("secs", "sec", "syms", "relocs", "audit", "notes", "digest", "diff")


def elf_object(symbol="exported", *, bss_size=64, text_flags=6, text=b"\0" * 8 + b"\xc3",
               note=None, note_type=7, duplicate=False, rel=False):
    """Small independent ELF writer; does not import the assembler implementation."""
    if note is None:
        note = struct.pack("<III", 5, 3, 1) + b"BEAR\0\0\0\0" + b"abc\0"
    names = ("", ".text", ".text" if duplicate else ".bss", ".shstrtab", ".strtab",
             ".symtab", ".rel.text" if rel else ".rela.text", ".note.test")
    name_offsets, shstrings = [], bytearray()
    for name in names:
        name_offsets.append(len(shstrings))
        shstrings.extend(name.encode() + b"\0")
    strings = b"\0" + symbol.encode() + b"\0"
    symbols = (bytes(24) + struct.pack("<IBBHQQ", 0, 3, 0, 1, 0, 0)
               + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, len(text)))
    reloc = struct.pack("<QQ", 0, (2 << 32) | 1) if text else b""
    if not rel and text:
        reloc += struct.pack("<q", 0)
    # type, flags, payload, memory size, link, info, alignment, entry size
    sections = [
        (0, 0, b"", 0, 0, 0, 0, 0),
        (1, text_flags, text, len(text), 0, 0, 16, 0),
        (8, 3, b"", bss_size, 0, 0, 16, 0),
        (3, 0, bytes(shstrings), len(shstrings), 0, 0, 1, 0),
        (3, 0, strings, len(strings), 0, 0, 1, 0),
        (2, 0, symbols, len(symbols), 4, 2, 8, 24),
        (9 if rel else 4, 0, reloc, len(reloc), 5, 1, 8, 16 if rel else 24),
        (note_type, 0, note, len(note), 0, 0, 4, 0),
    ]
    shoff = 64
    blob = bytearray(64 + 64 * len(sections))
    headers = {}
    for i, (typ, flags, payload, size, link, info, align, entsize) in enumerate(sections):
        if not i:
            continue
        while len(blob) % max(align, 1):
            blob.append(0)
        off = len(blob)
        if typ != 8:
            blob.extend(payload)
        h = shoff + i * 64
        struct.pack_into("<IIQQQQIIQQ", blob, h, name_offsets[i], typ, flags, 0,
                         off, size, link, info, align, entsize)
        headers[names[i]] = (h, off, size)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", blob, 0, ident, 1, 62, 1, 0, 0, shoff,
                     0, 64, 0, 0, 64, len(sections), 3)
    return blob, headers


class ElfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="bearbasm-elf-w02-w03-")
        cls.dir = Path(cls.work.name)
        cls.binary = BINARY
        cls.env = dict(os.environ)
        # Fatal parser exits intentionally do not unwind all caller allocations.
        # Address/undefined behavior checking stays enabled for every input.
        cls.env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:abort_on_error=1"
        cls.env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        cls.raw, cls.headers = elf_object()
        cls.good = cls.dir / "valid.o"
        cls.good.write_bytes(cls.raw)
        cls.sequence = 0
        cls.checked = 0

    @classmethod
    def tearDownClass(cls):
        print(f"ELF gate: {cls.checked} command executions; malformed fixtures never executed as code")
        cls.work.cleanup()

    def save(self, data):
        type(self).sequence += 1
        path = self.dir / f"case-{self.sequence}.o"
        path.write_bytes(data)
        return path

    def run_cmd(self, cmd, path, other=None):
        args = [str(self.binary), cmd, str(path)]
        if cmd == "diff":
            args.append(str(other or self.good))
        if cmd == "sec":
            args.append(".text")
        result = subprocess.run(args, capture_output=True, env=self.env, timeout=8)
        type(self).checked += 1
        self.assertIn(result.returncode, (0, 1), (args, result.returncode, result.stderr.decode(errors="replace")))
        self.assertNotIn(b"AddressSanitizer", result.stderr, result.stderr.decode(errors="replace"))
        self.assertNotIn(b"runtime error:", result.stderr, result.stderr.decode(errors="replace"))
        return result

    def reject(self, raw, commands=COMMANDS):
        path = self.save(raw)
        for cmd in commands:
            with self.subTest(command=cmd):
                result = self.run_cmd(cmd, path)
                self.assertEqual(result.returncode, 1, (cmd, result.stdout, result.stderr))
                self.assertNotIn(b"AUDIT OK", result.stdout)
                self.assertEqual(result.stdout, b"", (cmd, result.stdout))

    def mutate(self, offset, fmt, value):
        raw = bytearray(self.raw)
        struct.pack_into("<" + fmt, raw, offset, value)
        return raw

    def test_01_valid_object_all_commands(self):
        for cmd in COMMANDS:
            with self.subTest(command=cmd):
                result = self.run_cmd(cmd, self.good)
                self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run_cmd("sec", self.good).stdout
        self.assertEqual(output, b"\0" * 8 + b"\xc3")
        digest = self.run_cmd("digest", self.good).stdout.decode()
        self.assertIn(hashlib.sha256(output).hexdigest(), digest)
        self.assertIn(b'owner="BEAR" type=1', self.run_cmd("notes", self.good).stdout)

    def test_02_header_and_section_table_bounds(self):
        cases = [
            (40, "Q", U64_MAX - 8), (40, "Q", len(self.raw)),
            (40, "Q", 0), (58, "H", 0), (58, "H", 63),
            (60, "H", 65535), (60, "H", 0), (62, "H", 8),
            (62, "H", 65535), (52, "H", 63), (20, "I", 2),
            (6, "B", 0), (4, "B", 1), (5, "B", 2),
            (64 + 4, "I", 1),
        ]
        for off, fmt, val in cases:
            with self.subTest(offset=off, value=val):
                self.reject(self.mutate(off, fmt, val))
        self.reject(self.raw[:63])

    def test_03_file_backed_spans_do_not_wrap(self):
        for name in (".text", ".shstrtab", ".strtab", ".symtab", ".rela.text", ".note.test"):
            h, _, _ = self.headers[name]
            with self.subTest(section=name):
                raw = self.mutate(h + 24, "Q", U64_MAX - 15)
                struct.pack_into("<Q", raw, h + 32, 32)
                self.reject(raw)
                self.reject(self.mutate(h + 24, "Q", 0x4000000000))
                self.reject(self.mutate(h + 32, "Q", U64_MAX))

    def test_04_strings_are_bounded_and_linked(self):
        sh, soff, ssize = self.headers[".shstrtab"]
        st, off, size = self.headers[".strtab"]
        symh, symoff, _ = self.headers[".symtab"]
        self.reject(self.mutate(sh + 4, "I", 1))
        self.reject(self.mutate(soff + ssize - 1, "B", 65))
        self.reject(self.mutate(off + size - 1, "B", 65))
        self.reject(self.mutate(off, "B", 65))
        self.reject(self.mutate(symh + 40, "I", 1))
        self.reject(self.mutate(symh + 40, "I", 0x10004))
        self.reject(self.mutate(symoff + 48, "I", 0xffffffff))
        self.reject(self.mutate(self.headers[".text"][0], "I", ssize))
        # A NUL exists elsewhere in the file, but outside the shortened table.
        self.reject(self.mutate(st + 32, "Q", size - 1))

    def test_05_symbol_table_shape_and_indices(self):
        h, off, size = self.headers[".symtab"]
        for pos, fmt, value in (
            (h + 56, "Q", 0), (h + 56, "Q", 23), (h + 32, "Q", size - 1),
            (h + 44, "I", 4), (h + 44, "I", 0),
            (off + 48 + 6, "H", 20), (off + 48 + 6, "H", 0xffff),
            (off + 48 + 4, "B", 2), (off, "I", 1),
        ):
            with self.subTest(offset=pos, value=value):
                self.reject(self.mutate(pos, fmt, value))

    def test_06_relocation_shape_and_full_width_links(self):
        h, off, size = self.headers[".rela.text"]
        for pos, fmt, value in (
            (h + 56, "Q", 0), (h + 56, "Q", 23), (h + 32, "Q", size - 1),
            (h + 40, "I", 4), (h + 40, "I", 0x10005), (h + 44, "I", 8),
            (h + 44, "I", 0), (off + 8, "Q", (3 << 32) | 1),
            (off, "Q", U64_MAX), (off, "Q", 9), (off, "Q", 2),
        ):
            with self.subTest(offset=pos, value=value):
                self.reject(self.mutate(pos, fmt, value))
        raw, _ = elf_object(rel=True)
        path = self.save(raw)
        self.assertEqual(self.run_cmd("audit", path).returncode, 0)
        self.assertIn(b"implicit addend", self.run_cmd("relocs", path).stdout)

    def test_07_notes_lengths_padding_and_termination(self):
        h, off, size = self.headers[".note.test"]
        for pos, value in ((off, 0xffffffff), (off, 0xfffffffd),
                           (off + 4, 0xffffffff), (off + 4, 0xfffffffd)):
            with self.subTest(offset=pos, value=value):
                self.reject(self.mutate(pos, "I", value))
        self.reject(self.mutate(off + 16, "B", 65))
        self.reject(self.mutate(h + 32, "Q", 8))
        self.reject(self.mutate(h + 32, "Q", size - 1))
        trailing, _ = elf_object(note=struct.pack("<III", 0, 0, 1) + b"x")
        self.reject(trailing)
        zero, _ = elf_object(note=struct.pack("<III", 0, 0, 1))
        self.assertEqual(self.run_cmd("notes", self.save(zero)).returncode, 0)
        legacy, _ = elf_object(note=struct.pack("<III", 0xffffffff, 0, 1) + b"\0", note_type=1)
        self.reject(legacy, ("notes",))

    def test_08_nobits_is_virtual_and_policy_still_applies(self):
        raw = self.mutate(self.headers[".bss"][0] + 24, "Q", U64_MAX)
        self.assertEqual(self.run_cmd("audit", self.save(raw)).returncode, 0)
        huge, _ = elf_object(bss_size=1 << 48)
        self.assertEqual(self.run_cmd("audit", self.save(huge)).returncode, 0)
        wx, _ = elf_object(text_flags=7)
        result = self.run_cmd("audit", self.save(wx))
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"A3", result.stdout)
        not_rel = self.mutate(16, "H", 2)
        self.assertEqual(self.run_cmd("audit", self.save(not_rel)).returncode, 1)
        overlap = self.mutate(self.headers[".text"][0] + 24, "Q", self.headers[".strtab"][1])
        self.assertEqual(self.run_cmd("audit", self.save(overlap)).returncode, 1)

    def test_09_program_headers_cannot_claim_wrapped_ranges(self):
        for phoff in (U64_MAX - 8, len(self.raw) - 8):
            raw = self.mutate(32, "Q", phoff)
            struct.pack_into("<HH", raw, 54, 56, 1)
            self.reject(raw)

    def test_10_comparator_binds_flags_bss_and_empty_sizes(self):
        baseline = self.run_cmd("digest", self.good).stdout
        for raw, _ in (elf_object(bss_size=65), elf_object(text_flags=7), elf_object(text=b"")):
            path = self.save(raw)
            self.assertEqual(self.run_cmd("diff", path).returncode, 1)
            self.assertNotEqual(self.run_cmd("digest", path).stdout, baseline)
        aligned = self.mutate(self.headers[".text"][0] + 48, "Q", 8)
        path = self.save(aligned)
        self.assertEqual(self.run_cmd("diff", path).returncode, 1)
        self.assertNotEqual(self.run_cmd("digest", path).stdout, baseline)

    def test_11_long_names_cannot_collapse_to_one_comparison(self):
        a, _ = elf_object("g" * 700 + "A")
        b, _ = elf_object("g" * 700 + "B")
        pa, pb = self.save(a), self.save(b)
        self.assertEqual(self.run_cmd("diff", pa, pb).returncode, 1)
        self.assertNotEqual(self.run_cmd("digest", pa).stdout, self.run_cmd("digest", pb).stdout)
        # A symbol spelling cannot trick the comparator into dropping a GLOBAL.
        a, _ = elf_object("global bind=0 A")
        b, _ = elf_object("global bind=0 B")
        self.assertEqual(self.run_cmd("diff", self.save(a), self.save(b)).returncode, 1)

    def test_12_relocation_target_and_ambiguous_section_names(self):
        h, _, _ = self.headers[".rela.text"]
        path = self.save(self.mutate(h + 44, "I", 2))
        self.assertEqual(self.run_cmd("diff", path).returncode, 1)
        self.assertNotEqual(self.run_cmd("digest", path).stdout, self.run_cmd("digest", self.good).stdout)
        duplicate, _ = elf_object(duplicate=True)
        self.reject(duplicate, ("diff", "digest"))
        self.assertEqual(self.run_cmd("secs", self.save(duplicate)).returncode, 0)

    def test_13_deterministic_mutation_safety(self):
        rng = random.Random(203003)
        for index in range(96):
            raw = bytearray(self.raw)
            for _ in range(1 + index % 4):
                at = rng.randrange(len(raw))
                raw[at] ^= 1 << rng.randrange(8)
            self.run_cmd(COMMANDS[index % len(COMMANDS)], self.save(raw))

    def test_14_header_identity_and_referenced_locals_are_bound(self):
        baseline = self.run_cmd("digest", self.good).stdout
        for off, fmt, value in ((16, "H", 2), (18, "H", 183), (7, "B", 3),
                                (8, "B", 1), (48, "I", 1), (24, "Q", 1)):
            path = self.save(self.mutate(off, fmt, value))
            self.assertEqual(self.run_cmd("diff", path).returncode, 1)
            self.assertNotEqual(self.run_cmd("digest", path).stdout, baseline)
        _, so, _ = self.headers[".symtab"]
        _, ro, _ = self.headers[".rela.text"]
        a = bytearray(self.raw)
        struct.pack_into("<IBBHQQ", a, so + 24, 1, 2, 0, 1, 0, 1)
        struct.pack_into("<Q", a, ro + 8, (1 << 32) | 1)
        b = bytearray(a)
        struct.pack_into("<Q", b, so + 24 + 8, 1)
        self.assertEqual(self.run_cmd("diff", self.save(a), self.save(b)).returncode, 1)
        raw, headers = elf_object(rel=True)
        a = self.save(raw)
        struct.pack_into("<I", raw, headers[".rel.text"][0] + 44, 2)
        self.assertEqual(self.run_cmd("diff", a, self.save(raw)).returncode, 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--no-sanitize", action="store_true")
    args, remaining = parser.parse_known_args()
    with tempfile.TemporaryDirectory(prefix="bearbasm-elf-harness-") as build:
        BINARY = args.binary.resolve() if args.binary else Path(build) / "elf-harness"
        if not args.binary:
            cc = shlex.split(os.environ.get("CC", "cc"))
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                     "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"]
            if not args.no_sanitize:
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie"]
            subprocess.run(cc + flags + [str(ROOT / "tests/campaign/elf_harness.c"), "-o", str(BINARY)], check=True)
        unittest.main(argv=[__file__] + remaining, verbosity=2)
