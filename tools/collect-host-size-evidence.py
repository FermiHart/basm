#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Record declared ELF sizes for explicit diagnostic lanes and a delivered file.

GNU size's Berkeley text/data/bss sums differ from the file size and from RSS.
The delivered binary is read only and is not a matched optimization baseline.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("perf_campaign", ROOT / "tests/campaign/perf_campaign.py")
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--candidate-receipt", type=Path, required=True)
    parser.add_argument("--runtime-receipt", type=Path)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()
    if args.output_json.exists():
        parser.error("output receipt must be new")
    size = shutil.which("size")
    if not size:
        parser.error("GNU size is unavailable")
    paths = {"w12_software": args.baseline_receipt.resolve(), "candidate_software": args.candidate_receipt.resolve()}
    if args.runtime_receipt:
        paths["candidate_runtime"] = args.runtime_receipt.resolve()
    lanes = {}
    for role, path in paths.items():
        build = json.loads(path.read_text())
        lanes[role] = perf.load_lane(Path(build["artifacts"]["basm-host"]["path"]), path)
    if any(lanes[role]["build"]["sha_mode"] != "software" for role in ("w12_software", "candidate_software")):
        parser.error("W12 and candidate software receipts must select software SHA")
    perf.validate_matching_lanes(lanes["w12_software"], lanes["candidate_software"])
    if "candidate_runtime" in lanes:
        perf.validate_matching_lanes(lanes["candidate_software"], lanes["candidate_runtime"], True)
    def collect(path):
        argv = [size, "-B", str(path)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        fields = result.stdout.splitlines()[-1].split() if result.stdout else []
        if result.returncode or len(fields) < 6 or not all(value.isdecimal() for value in fields[:4]):
            raise RuntimeError("GNU size could not report: " + str(path))
        return {"file": perf.identity(path), "berkeley": dict(zip(("text", "data", "bss", "decimal_total"), map(int, fields[:4]))),
                "command": {"argv": argv, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr},
                "interpretation": "DECLARED_HEADER_SUMS_WITH_WARNING" if result.stderr else "DECLARED_HEADER_SUMS"}
    receipt = {"schema": "BASM-HOST-SIZE-EVIDENCE-v1", "scope": "HOST_DIAGNOSTIC_NOT_SOVEREIGN",
               "runner": perf.identity(Path(__file__)), "size_tool": perf.identity(Path(size).resolve()),
               "size_version": subprocess.run([size, "--version"], capture_output=True, text=True, check=True, timeout=5).stdout,
               "lanes": lanes,
               "delivered_original": {"artifact": collect(args.original.resolve()),
                                      "scope": "PROVIDED_PREBUILT_UNREPRODUCED; not a matched optimization baseline"},
               "limits": "File bytes include debug/link metadata. Berkeley text includes read-only data, not just .text. BSS is declared virtual storage, not measured RSS. Original malformed-section warnings remain visible."}
    for role, lane in lanes.items():
        lane["sizes"] = {}
        for name in ("basm-host", "basm-public-host", "elftool-host"):
            expected = lane["build"]["artifacts"][name]
            measured = collect(Path(expected["path"]))
            if measured["file"] != expected:
                raise RuntimeError("artifact no longer matches build receipt: " + name)
            lane["sizes"][name] = measured
    receipt["matched_software_deltas"] = {}
    for name in ("basm-host", "basm-public-host", "elftool-host"):
        before = lanes["w12_software"]["sizes"][name]
        after = lanes["candidate_software"]["sizes"][name]
        baseline = {"file_bytes": before["file"]["bytes"], **before["berkeley"]}
        candidate = {"file_bytes": after["file"]["bytes"], **after["berkeley"]}
        receipt["matched_software_deltas"][name] = {field: {"bytes": candidate[field]-value,
                                                                  "percent": 100*(candidate[field]-value)/value if value else None}
                                                    for field, value in baseline.items()}
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    snapshot = args.output_json.parent / (args.output_json.name + ".collector.py")
    if snapshot.exists():
        parser.error("retained collector snapshot must be new")
    shutil.copyfile(__file__, snapshot)
    receipt["runner_snapshot"] = perf.identity(snapshot)
    args.output_json.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    for role, lane in lanes.items():
        record = lane["sizes"]["basm-host"]
        print(role, record["file"]["bytes"], record["berkeley"])
    print("SIZE RECEIPT", args.output_json)
    return 0

if __name__ == "__main__":
    sys.exit(main())
