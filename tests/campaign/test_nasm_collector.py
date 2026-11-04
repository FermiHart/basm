#!/usr/bin/env python3
"""Exercise collector control flow with synthetic subprocess results only."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import nasm_benchmark as benchmark
from nasm_protocol import WORKLOADS


class CollectorTests(unittest.TestCase):
    def collect_synthetically(self, directory, corrupt=False):
        directory = Path(directory)
        paths = {key: directory / key for key in ("basm", "nasm", "basm-receipt", "elftool", "cc")}
        for key, path in paths.items():
            path.write_bytes(key.encode())
        lanes = {"nasm": {"binary": benchmark.identity(paths["nasm"])},
                 "basm": {"binary": benchmark.identity(paths["basm"]),
                          "build": {"compiler": benchmark.identity(paths["cc"])}}}
        output = directory / "collection"
        outputs = []

        def fixtures(destination):
            destination.mkdir()
            cases = []
            for name in WORKLOADS:
                source = destination / (name + ".asm")
                source.write_text("synthetic fixture for collector unit test\n")
                cases.append({"name": name, "format": "bin", "source": str(source), "extra": [],
                              "category": "synthetic_unit_test", "description": "not an assembler benchmark"})
            return cases

        def fake_run(argv, **kwargs):
            if argv[0] == str(paths["cc"]):
                Path(argv[-1]).write_bytes(b"synthetic launcher; never executed")
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            stdout, stderr = Path(argv[1]), Path(argv[2])
            command = argv[5:]
            role = "nasm" if command[0] == str(paths["nasm"]) else "basm"
            stdout.write_text("NASM version 3.02\n" if "-v" in command else "{}" if "--capabilities" in command else "")
            stderr.write_text("")
            if "-o" in command:
                object_path = Path(command[command.index("-o") + 1])
                object_path.write_bytes(b"identical synthetic flat bytes")
                outputs.append(object_path)
                if corrupt and stdout.name == "addressing-basm-block-03-after.stdout":
                    outputs[0].write_bytes(b"")
            sample = {"returncode": 1 if "--version" in command else 0, "timed_out": False,
                      "wall_ns": 2000 if role == "nasm" else 1000,
                      "user_us": 20 if role == "nasm" else 10, "system_us": 2,
                      "peak_rss_kib": 200 if role == "nasm" else 100}
            return SimpleNamespace(returncode=0, stdout=json.dumps(sample), stderr="")

        argv = ["nasm_benchmark.py", "--basm", str(paths["basm"]), "--basm-receipt", str(paths["basm-receipt"]),
                "--nasm", str(paths["nasm"]), "--elftool", str(paths["elftool"]), "--output-dir", str(output),
                "--blocks", "3", "--rounds", "5", "--warmups", "1"]
        with patch("sys.argv", argv), patch.object(benchmark, "load_tools", return_value=(lanes, benchmark.identity(paths["elftool"]))), \
             patch.object(benchmark, "generate_fixtures", side_effect=fixtures), patch.object(benchmark.subprocess, "run", side_effect=fake_run), \
             patch.object(benchmark.platform, "system", return_value="Linux"), \
             patch.object(benchmark.platform, "uname", return_value=("Linux", "synthetic", "0", "0", "x86_64", "synthetic")), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            returncode = benchmark.main()
        return returncode, json.loads((output / "result.json").read_text())

    def test_all_blocks_retain_every_unique_output_and_pooled_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            returncode, receipt = self.collect_synthetically(directory)
            self.assertEqual(returncode, 0, receipt.get("error"))
            self.assertEqual(receipt["artifact_integrity"]["status"], "PASS")
            self.assertEqual(len(receipt["cases"]), 16)
            self.assertFalse(receipt["default_protocol_requested"])
            measured = [command for command in receipt["commands"] if command["measured"]]
            self.assertEqual(len(measured), 16 * 3 * 5 * 2)
            output_paths = [command["output_path"] for command in receipt["commands"] if "output_path" in command]
            self.assertEqual(len(output_paths), len(set(output_paths)))
            self.assertEqual(len({len(path) for path in output_paths}), 1)
            for case in receipt["cases"]:
                self.assertEqual(case["pooled"]["sample_count"], 15)
                self.assertEqual([block["sample_count"] for block in case["block_results"]], [5, 5, 5])
                self.assertEqual(len(case["observations"]), 18)

    def test_drift_refuses_otherwise_favorable_complete_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            returncode, receipt = self.collect_synthetically(directory, corrupt=True)
            self.assertEqual(returncode, 1)
            self.assertEqual(receipt["status"], "REFUSED")
            self.assertEqual(receipt["artifact_integrity"]["status"], "DRIFT")
            self.assertTrue(receipt["artifact_integrity"]["failed"])


if __name__ == "__main__":
    unittest.main()
