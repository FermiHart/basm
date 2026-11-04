#!/usr/bin/env python3
"""INV-579/INV-583: exercise the real executable, not a timing-based kill race."""
import os
import hashlib
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time
import unittest

BASM = str(Path(sys.argv.pop(1)).resolve())
LIMIT = 1024
PAYLOAD = 131072
SOURCE = f"bits 64\nsection .text\nglobal entry\nentry:\n times {PAYLOAD} db 0x90\n ret\n"

# This child knows its future assembler PID. All planted paths belong to the
# private test directory; no process-name killing or host resource changes.
PLANT = r"""
import os, resource, signal, sys
from pathlib import Path
basm, output, source, fmt, kind, limited = sys.argv[1:]
path = Path(output + '.tmp.' + str(os.getpid()))
witness = Path(output + '.witness')
if kind == 'symlink': path.symlink_to(witness)
elif kind == 'hardlink': os.link(witness, path)
else: path.write_bytes(b'pre-existing temporary')
if kind == 'exhaust':
    for n in range(1, 32): Path(str(path) + '.' + str(n)).write_bytes(b'pre-existing temporary')
if limited == 'yes':
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execv(basm, [basm, '-f', fmt, '-o', output, source])
"""


class AtomicPublish(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="basm-atomic-", dir=os.environ.get("BASM_PUBLICATION_TMPDIR"))
        self.root = Path(self.temporary.name)
        self.source = self.root / "input.basm"
        self.source.write_text(SOURCE)

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, output, fmt="elf64"):
        return [BASM, "-f", fmt, "-o", str(output), str(self.source)]

    def baseline(self, fmt):
        output = self.root / ("baseline-" + fmt)
        subprocess.run(self.command(output, fmt), check=True, capture_output=True, timeout=15)
        data = output.read_bytes()
        self.assertGreater(len(data), PAYLOAD)
        self.assertGreater(len(data), LIMIT * 2)
        return data

    def test_limited_write_preserves_old_or_absent_destination(self):
        for fmt in ("elf64", "bin"):
            data = self.baseline(fmt)
            for disposition in ("signal", "ignore", "block"):
                for existed in (False, True):
                    with self.subTest(fmt=fmt, disposition=disposition, existed=existed):
                        output = self.root / f"limit-{fmt}-{disposition}-{existed}"
                        old = data[:-1] + b"\xcc"  # distinguish preserved old from new
                        if existed:
                            output.write_bytes(old)

                        def limits():
                            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                            resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
                            signal.signal(signal.SIGXFSZ, signal.SIG_IGN if disposition == "ignore" else signal.SIG_DFL)
                            if disposition == "block":
                                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGXFSZ})

                        result = subprocess.run(self.command(output, fmt), preexec_fn=limits,
                                                capture_output=True, timeout=15)
                        stranded = list(self.root.glob(output.name + ".tmp.*"))
                        if disposition == "signal":
                            self.assertEqual(result.returncode, -signal.SIGXFSZ)
                            self.assertEqual(len(stranded), 1)
                            self.assertEqual(stranded[0].stat().st_size, LIMIT)
                        else:
                            self.assertNotEqual(result.returncode, 0)
                            self.assertIn(b"write error", result.stderr)
                            self.assertFalse(stranded, "ordinary error leaked an owned temporary")
                        if existed:
                            self.assertEqual(output.read_bytes(), old)
                        else:
                            self.assertFalse(output.exists())

    def test_existing_temporary_is_never_truncated_or_unlinked(self):
        for kind in ("file", "symlink", "hardlink"):
            for limited in ("no", "yes"):
                with self.subTest(kind=kind, limited=limited):
                    output = self.root / f"collision-{kind}-{limited}"
                    old = b"old complete destination"
                    output.write_bytes(old)
                    witness = Path(str(output) + ".witness")
                    witness.write_bytes(b"untouched witness")
                    result = subprocess.run([sys.executable, "-c", PLANT, BASM, str(output),
                                             str(self.source), "elf64", kind, limited],
                                            capture_output=True, timeout=15)
                    planted = list(self.root.glob(output.name + ".tmp.*"))
                    self.assertEqual(witness.read_bytes(), b"untouched witness")
                    self.assertEqual(len(planted), 1, "pre-existing temp removed or owned temp leaked")
                    expected = b"pre-existing temporary" if kind == "file" else b"untouched witness"
                    self.assertEqual(planted[0].read_bytes(), expected)
                    if limited == "yes":
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(output.read_bytes(), old)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(output.read_bytes(), self.baseline("elf64"))

    def test_prewrite_validation_does_not_remove_unowned_temp(self):
        self.source.write_text("bits 64\nsection .text\nextern missing\n call missing\n")
        output = self.root / "unresolved"
        result = subprocess.run([sys.executable, "-c", PLANT, BASM, str(output),
                                 str(self.source), "bin", "file", "no"],
                                capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"bin output cannot contain relocations", result.stderr)
        self.assertFalse(output.exists())
        planted = list(self.root.glob(output.name + ".tmp.*"))
        self.assertEqual(len(planted), 1)
        self.assertEqual(planted[0].read_bytes(), b"pre-existing temporary")

    def test_collision_retry_bound_preserves_every_existing_file(self):
        output = self.root / "exhaust"
        output.write_bytes(b"old complete output")
        result = subprocess.run([sys.executable, "-c", PLANT, BASM, str(output),
                                 str(self.source), "elf64", "exhaust", "no"],
                                capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"old complete output")
        planted = list(self.root.glob(output.name + ".tmp.*"))
        self.assertEqual(len(planted), 32)
        self.assertTrue(all(p.read_bytes() == b"pre-existing temporary" for p in planted))

    def test_success_replaces_final_symlink_not_its_target(self):
        expected = self.baseline("elf64")
        witness = self.root / "witness"
        witness.write_bytes(b"untouched")
        output = self.root / "link"
        output.symlink_to(witness)
        subprocess.run(self.command(output), check=True, capture_output=True, timeout=15)
        self.assertFalse(output.is_symlink())
        self.assertEqual(output.read_bytes(), expected)
        self.assertEqual(witness.read_bytes(), b"untouched")

    def test_cold_and_warm_cache_preserve_byte_identity(self):
        key = self.root / "key"
        key.write_bytes(bytes(32))
        for fmt in ("elf64", "bin"):
            expected = self.baseline(fmt)
            cache = self.root / ("cache-" + fmt)
            for phase in ("cold", "warm"):
                output = self.root / (phase + fmt)
                command = self.command(output, fmt) + ["--rel8-escrow", str(cache), "--rel8-key", str(key)]
                result = subprocess.run(command, check=True, capture_output=True, timeout=20)
                actual = output.read_bytes()
                self.assertEqual(hashlib.sha256(actual).digest(), hashlib.sha256(expected).digest(),
                                 f"{fmt}/{phase}: expected {len(expected)} bytes, got {len(actual)}")
                self.assertEqual(b"rel8 escrow hit" in result.stderr, phase == "warm")

    def test_concurrent_final_is_complete_and_each_cache_key_restores_itself(self):
        other = self.root / "other.basm"
        other.write_text(SOURCE.replace("0x90", "0xcc"))
        expected = {self.source: self.baseline("elf64")}
        reference = self.root / "other.o"
        subprocess.run([BASM, "-f", "elf64", "-o", str(reference), str(other)],
                       check=True, capture_output=True, timeout=15)
        expected[other] = reference.read_bytes()
        hashes = {hashlib.sha256(data).digest() for data in expected.values()}
        output = self.root / "shared.o"
        output.write_bytes(expected[self.source])
        cache, key = self.root / "race-cache", self.root / "key"
        key.write_bytes(bytes(32))
        workers = []
        try:
            for index in range(8):
                source = self.source if index % 2 == 0 else other
                workers.append(subprocess.Popen([BASM, "-f", "elf64", "-o", str(output),
                    "--rel8-escrow", str(cache), "--rel8-key", str(key), str(source)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            deadline = time.monotonic() + 20
            while any(proc.poll() is None for proc in workers):
                self.assertLess(time.monotonic(), deadline)
                self.assertIn(hashlib.sha256(output.read_bytes()).digest(), hashes,
                              "observer saw a partial/mixed published object")
                time.sleep(0.001)
            for proc in workers:
                _, errors = proc.communicate(timeout=2)
                self.assertEqual(proc.returncode, 0, errors)
            for index, (source, data) in enumerate(expected.items()):
                restored = self.root / f"restored-{index}"
                result = subprocess.run([BASM, "-f", "elf64", "-o", str(restored),
                    "--rel8-escrow", str(cache), "--rel8-key", str(key), str(source)],
                    check=True, capture_output=True, timeout=15)
                self.assertIn(b"rel8 escrow hit", result.stderr)
                self.assertEqual(restored.read_bytes(), data)
        finally:
            for proc in workers:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate()

    def test_many_incbin_snapshots_close_input_streams(self):
        # W07 snapshots close each input before publication. Use distinct files,
        # since repeating one pathname would only exercise dependency reuse.
        # A 16-descriptor child budget detects retained streams on a host libc
        # as well; the unchanged product gate also exercises Bear's FILE pool.
        payloads = []
        for index in range(64):
            payload = self.root / f"payload-{index}"
            data = bytes([index + 1]) * 4096
            payload.write_bytes(data)
            payloads.append((payload, data))
        key = self.root / "key"
        key.write_bytes(bytes(32))
        for spans in (31, 32, 64):
            with self.subTest(spans=spans):
                selected = payloads[:spans]
                self.source.write_text("bits 64\nsection .text\n" + "".join(
                    f'incbin "{payload}"\n' for payload, _ in selected))
                expected = b"".join(data for _, data in selected)
                cache = self.root / f"snapshot-cache-{spans}"
                for phase in ("ordinary", "cold", "warm"):
                    with self.subTest(spans=spans, phase=phase):
                        output = self.root / f"snapshots-{spans}-{phase}.bin"
                        output.write_bytes(b"previous output")
                        command = self.command(output, "bin")
                        if phase != "ordinary":
                            command += ["--rel8-escrow", str(cache), "--rel8-key", str(key)]

                        def limited_descriptors():
                            resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
                            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

                        result = subprocess.run(command, capture_output=True, timeout=20,
                                                preexec_fn=limited_descriptors)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(output.read_bytes(), expected)
                        self.assertEqual(b"rel8 escrow hit" in result.stderr, phase == "warm")
                        self.assertFalse([p for p in self.root.rglob("*") if ".tmp." in p.name],
                                         "snapshot publication left an owned temporary")


if __name__ == "__main__":
    unittest.main(verbosity=2)
