#!/usr/bin/env python3
"""Adversarial reviewer tests use synthetic observations, never an assembler."""
import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nasm_benchmark import describe_samples
from nasm_review import WORKLOADS, audit_files, distribution, review_result
import nasm_review as reviewer
import test_nasm_collector as collector_tests


def refresh(case):
    measured_all = []
    case["block_results"] = []
    for block in (1, 2, 3):
        measured = [pair for pair in case["observations"] if pair["block"] == block and not pair["warmup"]]
        stats = describe_samples(measured)
        stats.update({"block": block, "validation_before": case["validation_before"], "validation_after": case["validation_after"]})
        case["block_results"].append(stats)
        measured_all += measured
    pooled = describe_samples(measured_all)
    case["pooled"] = pooled
    for role in ("nasm", "basm"):
        case["lanes"][role].update(pooled["lanes"][role])
    for key in ("paired_nasm_over_basm", "paired_cpu_nasm_over_basm"):
        case[key] = pooled[key]
    case["status"] = "STABLE" if all(block["status"] == "STABLE" for block in case["block_results"]) and pooled["status"] == "STABLE" else "INCONCLUSIVE"


def fixture():
    basm_id = {"path": "/tools/basm", "bytes": 1, "sha256": "b" * 64}
    nasm_id = {"path": "/tools/nasm", "bytes": 1, "sha256": "a" * 64}
    basm_build = {"lane": "HOST_DIAGNOSTIC_NOT_SOVEREIGN", "sha_mode": "software", "sanitizers": [],
                  "compiler_version": "GCC 13.3.0", "flags": ["-O2"], "artifacts": {"basm-host": basm_id}}
    receipt = {"schema": "BASM-NASM-BENCHMARK-v2", "status": "STABLE", "mode": "performance", "protocol_purpose": "three_block_comparison",
               "method": {"blocks": 3, "rounds": 15, "warmups": 3, "dispersion_threshold_relative_mad": .25,
                          "per_command_timeout_s": 10, "aggregate_timeout_s": 600,
                          "environment": {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"}},
               "host": {"cpu_requested": 0, "affinity_effective": [0], "affinity_after": [0]},
               "tools": {"basm": {"binary": basm_id, "build": basm_build},
                         "nasm": {"binary": nasm_id, "version": "NASM version 3.02 synthetic", "build_receipt": {"path": "/nasm-receipt"},
                                  "build": {"artifacts": {"nasm": nasm_id}}}},
               "nasm_default_optimization_check": {"comparisons": [{"matches_default_raw_object": True}, {"matches_default_raw_object": True}]},
               "preregistered_protocol": {"content": {"fixture_generator_sha256": "148e1f57d7ab03ade65f702cef6f0bbd78e63c4391a249834d66019eb65402fb"}},
               "artifact_integrity": {"status": "PASS", "failed": []}, "cases": [], "commands": []}
    proof = {"equal": True, "secondary_returncode": 0, "receipt": {"path": "/proof/parity.json", "bytes": 1, "sha256": "d" * 64}}
    for name in WORKLOADS:
        initial = {"path": "/proof/initial.o", "bytes": 32, "sha256": "e" * 64}
        receipt["cases"].append({"name": name, "format": "bin" if name == "flat-bin" else "elf64", "source": "/fixtures/" + name + ".asm", "extra": [],
                                  "eligible": True, "validation_before": proof, "validation_after": proof, "observations": [],
                                  "lanes": {role: {"initial_output": copy.deepcopy(initial)} for role in ("nasm", "basm")}})
    index = 0
    for block in (1, 2, 3):
        for case in receipt["cases"]:
            for round_index in range(18):
                order = ["nasm", "basm"] if (block - 1 + round_index) % 2 == 0 else ["basm", "nasm"]
                pair = {"block": block, "round": round_index, "warmup": round_index < 3, "order": order}
                for role in order:
                    output = "/result/objects/%06d-%s.o" % (index, role)
                    sample = {"case": case["name"], "tool": role, "block": block, "round": round_index,
                              "measured": round_index >= 3, "returncode": 0, "timed_out": False,
                              "wall_ns": 2000000 if role == "nasm" else 1000000,
                              "user_us": 1800 if role == "nasm" else 800, "system_us": 200,
                              "peak_rss_kib": 4096 if role == "nasm" else 3072,
                              "stdout": "/result/logs/%06d.stdout" % index, "stderr": "/result/logs/%06d.stderr" % index,
                              "output_path": output, "object": {"path": output, "bytes": 32, "sha256": "e" * 64},
                              "argv": [receipt["tools"][role]["binary"]["path"], "-f", case["format"], "-o", output, case["source"]]}
                    index += 1
                    receipt["commands"].append(sample)
                    pair[role] = sample
                case["observations"].append(pair)
    for case in receipt["cases"]:
        refresh(case)
    return receipt


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.receipt = fixture()

    def review(self):
        return review_result(self.receipt)

    def test_all_sixteen_gates_required_for_full_goal(self):
        review = self.review()
        self.assertEqual(review["status"], "RECOMPUTED", review["errors"])
        self.assertTrue(review["summary"]["full_goal_met"], review["final_configuration"])
        self.assertEqual(review["summary"]["effective_goal"], "16/16")

    def test_one_rss_loss_prevents_full_goal_even_when_wall_and_cpu_win(self):
        case = self.receipt["cases"][0]
        for pair in case["observations"]:
            if pair["block"] == 2:
                pair["basm"]["peak_rss_kib"] = 8192
        refresh(case)
        review = self.review()
        self.assertEqual(review["status"], "RECOMPUTED")
        self.assertEqual(review["summary"]["effective_goal"], "15/16")
        self.assertEqual(review["cases"][0]["unmet_gates"], ["rss"])

    def test_equal_rss_is_allowed_but_equal_wall_is_not_a_win(self):
        case = self.receipt["cases"][0]
        for pair in case["observations"]:
            pair["basm"]["peak_rss_kib"] = pair["nasm"]["peak_rss_kib"]
            pair["basm"]["wall_ns"] = pair["nasm"]["wall_ns"]
        refresh(case)
        self.assertEqual(self.review()["cases"][0]["unmet_gates"], ["wall"])

    def test_missing_parity_proof_prevents_correctness_win(self):
        self.receipt["cases"][0]["validation_after"] = {"equal": True, "secondary_returncode": 0}
        review = self.review()
        self.assertEqual(review["cases"][0]["unmet_gates"], ["correctness"])
        self.assertFalse(review["summary"]["full_goal_met"])

    def test_cpu_total_is_added_per_sample_and_loss_is_not_hidden(self):
        case = self.receipt["cases"][0]
        for pair in case["observations"]:
            pair["basm"]["system_us"] = 2000
        refresh(case)
        review = self.review()
        self.assertEqual(review["cases"][0]["unmet_gates"], ["cpu"])
        self.assertEqual(review["cases"][0]["pooled"]["lanes"]["basm"]["cpu_total_us"]["median"], 2800)

    def test_inconclusive_block_cannot_be_rescued_by_stable_pool(self):
        case = self.receipt["cases"][0]
        values = [200000] * 4 + [1000000] * 7 + [1800000] * 4
        for pair, value in zip([pair for pair in case["observations"] if pair["block"] == 2 and not pair["warmup"]], values):
            pair["basm"]["wall_ns"] = value
        refresh(case)
        review = self.review()
        self.assertEqual(review["cases"][0]["pooled"]["status"], "STABLE")
        self.assertEqual(review["cases"][0]["verdict"], "INCONCLUSIVE")
        self.assertFalse(review["summary"]["full_goal_met"])

    def test_warmup_metrics_never_enter_reported_statistics(self):
        for pair in self.receipt["cases"][0]["observations"]:
            if pair["warmup"]:
                pair["basm"]["wall_ns"] = 1000000000
                pair["basm"]["peak_rss_kib"] = 1000000
        review = self.review()
        self.assertTrue(review["summary"]["full_goal_met"])
        self.assertEqual(review["cases"][0]["pooled"]["sample_count"], 45)

    def test_tampered_summary_refuses_whole_goal(self):
        self.receipt["cases"][0]["pooled"]["paired_nasm_over_basm"]["median"] = 99
        review = self.review()
        self.assertEqual(review["status"], "REFUSED")
        self.assertFalse(review["summary"]["full_goal_met"])

    def test_native_command_order_cannot_be_relabelled(self):
        commands = self.receipt["commands"]
        commands[0], commands[1] = commands[1], commands[0]
        self.assertEqual(self.review()["status"], "REFUSED")

    def test_wrong_source_default_flags_and_role_binary_are_refused(self):
        for change in ("source", "flags", "tool"):
            receipt = fixture()
            sample = receipt["cases"][0]["observations"][3]["basm"]
            if change == "source":
                sample["argv"][-1] = "/fixtures/different.asm"
            elif change == "flags":
                sample["argv"].insert(1, "-O0")
            else:
                sample["argv"][0] = "/tools/nasm"
            with self.subTest(change=change):
                self.assertEqual(review_result(receipt)["status"], "REFUSED")

    def test_affinity_change_and_public_stub_prevent_full_protocol_claim(self):
        self.receipt["host"]["affinity_after"] = [0, 1]
        self.assertFalse(self.review()["summary"]["full_goal_met"])
        self.receipt["host"]["affinity_after"] = [0]
        self.receipt["tools"]["basm"]["build"]["flags"].append("-DBASM_PUBLIC_ONLY=1")
        self.assertFalse(self.review()["summary"]["full_goal_met"])

    def test_missing_pair_and_integrity_failure_cannot_be_hidden(self):
        self.receipt["cases"][0]["observations"].pop()
        self.assertEqual(self.review()["status"], "REFUSED")
        receipt = fixture()
        receipt["artifact_integrity"]["status"] = "DRIFT"
        review = review_result(receipt)
        self.assertEqual(review["summary"]["goal_status"], "REFUSED")
        self.assertEqual(review["summary"]["effective_goal"], "0/16")

    def test_independent_order_statistic_median_and_mad(self):
        result = distribution([8, 1, 7, 4, 2, 6])
        self.assertEqual(result["median"], 5)
        self.assertEqual(result["mad"], 2.5)

    def test_external_audit_reopens_all_retained_files(self):
        with tempfile.TemporaryDirectory() as directory:
            returncode, receipt = collector_tests.CollectorTests().collect_synthetically(directory)
            self.assertEqual(returncode, 0, receipt.get("error"))
            audit = audit_files(receipt)
            self.assertEqual(audit["status"], "PASS", audit["errors"])
            self.assertGreater(audit["checked"], 2000)
            altered = copy.deepcopy(receipt)
            altered["cases"][0]["validation_before"]["receipt"]["sha256"] = "0" * 64
            self.assertEqual(audit_files(altered)["status"], "REFUSED")
            result_path = Path(directory) / "collection" / "result.json"
            review_path = Path(directory) / "independent"
            with patch("sys.argv", ["nasm_review.py", "--result", str(result_path), "--output-dir", str(review_path)]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(reviewer.main(), 0)
            exported = json.loads((review_path / "independent-review.json").read_text())
            self.assertEqual(exported["file_audit"]["status"], "PASS")
            self.assertFalse(exported["summary"]["full_goal_met"])
            self.assertTrue((review_path / "independent-review.md").is_file())
            Path(receipt["commands"][3]["object"]["path"]).write_bytes(b"")
            self.assertEqual(audit_files(receipt)["status"], "REFUSED")
            refused_path = Path(directory) / "independent-after-drift"
            with patch("sys.argv", ["nasm_review.py", "--result", str(result_path), "--output-dir", str(refused_path)]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(reviewer.main(), 1)
            refused = json.loads((refused_path / "independent-review.json").read_text())
            self.assertEqual(refused["summary"]["goal_status"], "REFUSED")
            self.assertEqual(refused["summary"]["gate_counts"]["integrity"], 0)


if __name__ == "__main__":
    unittest.main()
