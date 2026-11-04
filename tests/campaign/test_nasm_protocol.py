#!/usr/bin/env python3
"""Protocol tests use synthetic observations, never timing an assembler."""
from pathlib import Path
import unittest

from nasm_benchmark import describe_samples
from nasm_protocol import (WORKLOADS, block_schedule, load_protocol,
                           retention_reserve_bytes)


class ProtocolTests(unittest.TestCase):
    def test_frozen_original_sixteen_case_generator(self):
        protocol = load_protocol(Path(__file__).parent)
        self.assertEqual(len(protocol["workloads"]), 16)
        self.assertEqual(protocol["workloads"], list(WORKLOADS))
        self.assertEqual(protocol["final_blocks"], 3)
        self.assertEqual(protocol["original_dispersion_gate"]["relative_mad_maximum"], .25)

    def test_three_blocks_have_all_predeclared_pairs(self):
        schedule = block_schedule(3, 15, 3)
        self.assertEqual([item["block"] for item in schedule], [1, 2, 3])
        for block in schedule:
            self.assertEqual([pair["round"] for pair in block["pairs"]], list(range(18)))
            self.assertEqual(sum(pair["warmup"] for pair in block["pairs"]), 3)
            self.assertEqual(sum(not pair["warmup"] for pair in block["pairs"]), 15)
            for first, second in zip(block["pairs"], block["pairs"][1:]):
                self.assertEqual(first["order"], list(reversed(second["order"])))
        self.assertEqual(schedule[0]["pairs"][0]["order"], ["nasm", "basm"])
        self.assertEqual(schedule[1]["pairs"][0]["order"], ["basm", "nasm"])
        self.assertEqual(schedule[2]["pairs"][0]["order"], ["nasm", "basm"])

    def test_only_fixed_final_or_single_diagnostic_block(self):
        self.assertEqual(len(block_schedule(1, 15, 3)), 1)
        for arguments in ((2, 15, 3), (4, 15, 3), (3, 16, 3), (3, 15, 0)):
            with self.assertRaises(ValueError):
                block_schedule(*arguments)

    def test_disk_budget_covers_every_output(self):
        self.assertEqual(retention_reserve_bytes(3, False), 2 * 1024 ** 3)
        self.assertEqual(retention_reserve_bytes(1, False), 768 * 1024 ** 2)
        self.assertEqual(retention_reserve_bytes(3, True), 192 * 1024 ** 2)

    def test_paired_median_is_not_ratio_of_lane_medians(self):
        nasm, basm = [10, 30, 40, 50, 200], [2, 15, 4, 100, 50]
        pairs = [{role: {"wall_ns": value, "user_us": value, "system_us": 0,
                         "peak_rss_kib": 100} for role, value in (("nasm", a), ("basm", b))}
                 for a, b in zip(nasm, basm)]
        result = describe_samples(pairs)
        self.assertEqual(result["paired_nasm_over_basm"]["median"], 4)
        self.assertNotEqual(result["paired_nasm_over_basm"]["median"],
                            result["lanes"]["nasm"]["wall_ns"]["median"] /
                            result["lanes"]["basm"]["wall_ns"]["median"])
        self.assertEqual(result["status"], "INCONCLUSIVE")

    def test_zero_cpu_denominator_cannot_support_cpu_ratio(self):
        pairs = [{"nasm": {"wall_ns": 2, "user_us": 1, "system_us": 1, "peak_rss_kib": 2},
                  "basm": {"wall_ns": 1, "user_us": 0, "system_us": 0, "peak_rss_kib": 1}}] * 5
        self.assertIsNone(describe_samples(pairs)["paired_cpu_nasm_over_basm"])


if __name__ == "__main__":
    unittest.main()
