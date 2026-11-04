#!/usr/bin/env python3
"""Meaningful refusal, native timing/RSS and statistics tests without basm builds."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("perf_campaign", HERE / "perf_campaign.py")
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)

class PerformanceInfrastructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="basm-perf-infrastructure-")
        cls.root = Path(cls.temp.name)
        cls.native = cls.root / "measure_process"
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("host compiler unavailable")
        subprocess.run([cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(HERE / "measure_process.c"), "-o", str(cls.native)], check=True)
        source = cls.root / "resident.c"
        source.write_text('#include <stdlib.h>\nint main(void){size_t n=32u*1024u*1024u; '
                          'volatile unsigned char *p=malloc(n); if(!p)return 2; '
                          'for(size_t i=0;i<n;i+=4096)p[i]=(unsigned char)i; '
                          'int r=p[n-4096];free((void*)p);return r;}\n')
        cls.resident = cls.root / "resident"
        subprocess.run([cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(cls.resident)], check=True)
        cls.sequence = 0

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_child(self, argv, timeout=3):
        type(self).sequence += 1
        tag = str(type(self).sequence)
        stdout = self.root / (tag + ".stdout")
        stderr = self.root / (tag + ".stderr")
        result = subprocess.run([str(self.native), str(stdout), str(stderr), str(timeout), "--"] + argv,
                                capture_output=True, text=True, check=True, timeout=timeout+2)
        return json.loads(result.stdout), stdout.read_text(), stderr.read_text()

    def test_native_literal_argv_and_metrics(self):
        text = "literal ; $(echo unsafe) spaces\n"
        metrics, stdout, stderr = self.run_child([shutil.which("printf"), "%s", text])
        self.assertEqual(stdout, text)
        self.assertEqual(stderr, "")
        self.assertEqual(metrics["returncode"], 0)
        self.assertGreater(metrics["wall_ns"], 0)
        self.assertGreaterEqual(metrics["peak_rss_kib"], 0)
        self.assertFalse(metrics["timed_out"])

    def test_failure_is_not_success(self):
        metrics, _, _ = self.run_child([shutil.which("false")])
        self.assertEqual(metrics["returncode"], 1)
        self.assertFalse(metrics["timed_out"])

    def test_timeout_is_not_sample_success(self):
        metrics, _, _ = self.run_child([shutil.which("sleep"), "2"], timeout=1)
        self.assertTrue(metrics["timed_out"])
        self.assertLess(metrics["returncode"], 0)
        self.assertGreaterEqual(metrics["wall_ns"], 800000000)
        self.assertLess(metrics["wall_ns"], 2500000000)

    def test_native_peak_rss_tracks_child_allocation(self):
        metrics, _, _ = self.run_child([str(self.resident)])
        self.assertEqual(metrics["returncode"], 0)
        self.assertGreater(metrics["peak_rss_kib"], 28 * 1024)
        self.assertLess(metrics["peak_rss_kib"], 64 * 1024)

    def test_statistics_use_median_and_absolute_mad(self):
        result = perf.summary([1, 2, 3, 4, 1000])
        self.assertEqual(result["median"], 3)
        self.assertEqual(result["mad"], 1)
        self.assertAlmostEqual(result["relative_mad"], 1/3)
        paired = perf.summary([a/b for a, b in zip([1, 100, 100], [1, 1, 100])])
        self.assertEqual(paired["median"], 1)
        self.assertNotEqual(paired["median"], 100)

    def test_reject_mismatched_toolchain(self):
        def lane(compiler):
            return {"build": {"compiler": compiler, "compiler_version": "v", "sha_mode": "software",
                              "sanitizers": False, "flags": ["-O2", "-I/snapshot"],
                              "source_inputs": {"bear_ed25519.c": {"sha256": "a"}, "bear_ed25519.h": {"sha256": "b"}}}}
        with self.assertRaisesRegex(ValueError, "compiler"):
            perf.validate_matching_lanes(lane("cc1"), lane("cc2"))

    def test_reject_mismatched_crypto(self):
        def lane(hash_value):
            return {"build": {"compiler": "cc", "compiler_version": "v", "sha_mode": "software",
                              "sanitizers": False, "flags": ["-O2"],
                              "source_inputs": {"bear_ed25519.c": {"sha256": hash_value}, "bear_ed25519.h": {"sha256": "b"}}}}
        with self.assertRaisesRegex(ValueError, "crypto"):
            perf.validate_matching_lanes(lane("a"), lane("different"))

    def test_sha_experiment_cannot_hide_source_or_toolchain_changes(self):
        def lane(mode, source_hash="fixed", optimization="-O2"):
            flags = [optimization] + (["-DSHA256NI_FORCE_SOFTWARE=1"] if mode == "software" else [])
            return {"build": {"compiler": "cc", "compiler_version": "v", "sha_mode": mode,
                              "sanitizers": False, "flags": flags,
                              "source_inputs": {"basm.c": {"bytes": 7, "sha256": source_hash},
                                                "bear_ed25519.c": {"bytes": 8, "sha256": "c"},
                                                "bear_ed25519.h": {"bytes": 9, "sha256": "h"}}}}
        perf.validate_matching_lanes(lane("software"), lane("runtime"), True)
        with self.assertRaisesRegex(ValueError, "sha_mode"):
            perf.validate_matching_lanes(lane("software"), lane("runtime"))
        with self.assertRaisesRegex(ValueError, "identical source"):
            perf.validate_matching_lanes(lane("software"), lane("runtime", "changed"), True)
        with self.assertRaisesRegex(ValueError, "compiler flags"):
            perf.validate_matching_lanes(lane("software"), lane("runtime", optimization="-O3"), True)

    def test_proof_binds_source_output_tool_and_rejects_duplicates(self):
        directory = self.root / "proof-case"
        directory.mkdir()
        tool = directory / "tool"; tool.write_bytes(b"TOOL")
        source = directory / "source"; source.write_bytes(b"SOURCE")
        output = directory / "output"; output.write_bytes(b"OUTPUT")
        proof = directory / "proof"
        fields = {"tool_sha256": hashlib.sha256(b"TOOL").hexdigest(),
                  "source_sha256": hashlib.sha256(b"SOURCE").hexdigest(),
                  "output_sha256": hashlib.sha256(b"OUTPUT").hexdigest(),
                  "source_path": str(source), "output_path": str(output),
                  "output_format": "elf64", "build_epoch": "0", "signature": "unsigned"}
        content = "basm attestation v2\n" + "".join(k + ": " + v + "\n" for k, v in fields.items())
        proof.write_text(content)
        perf.validate_proof(proof, tool, source, output, False)
        source.write_bytes(b"MUTATED")
        with self.assertRaisesRegex(ValueError, "source_sha256"):
            perf.validate_proof(proof, tool, source, output, False)
        source.write_bytes(b"SOURCE")
        proof.write_text(content + "build_epoch: 0\n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            perf.validate_proof(proof, tool, source, output, False)
        fields["signature_alg"] = "ed25519-over-sha256"
        fields["signature_pub"] = "00" * 32
        fields["signature"] = "11" * 64
        proof.write_text("basm attestation v2\n" + "".join(k + ": " + v + "\n" for k, v in fields.items()))
        with self.assertRaisesRegex(ValueError, "requested test identity"):
            perf.validate_proof(proof, tool, source, output, True, perf.TEST_SIGNER_PUB)

if __name__ == "__main__":
    unittest.main(verbosity=2)
