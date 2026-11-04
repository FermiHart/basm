#!/usr/bin/env python3
"""Bounded regular-file snapshot reads with deterministic host-only faults."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-root", type=Path, default=ROOT)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--cc", default="gcc-13")
    args = ap.parse_args()
    source = args.source_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cc = Path(shutil.which(args.cc) or args.cc).resolve()
    harness = output / "io_snapshot_fault.c"
    shutil.copyfile(ROOT / "tests/campaign/io_snapshot_fault.c", harness)
    binary = output / "snapshot-host-fault"
    command = [str(cc), "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-misleading-indentation", "-Wno-stringop-truncation", "-Wno-format-truncation",
               "-DSHA256NI_FORCE_SOFTWARE=1", "-ffunction-sections", "-fdata-sections",
               "-Wl,--gc-sections", "-Wl,--wrap=read", "-Wl,--wrap=__read_chk", "-Wl,--wrap=fstat", "-Wl,--wrap=fclose",
               "-I" + str(source), str(harness), "-o", str(binary)]
    inputs = [source / "basm.c", *sorted((source / "modules").glob("*.inc")),
              *sorted((source / "intent").glob("*.inc")), source / "isa/intent_forms.h"]
    receipt = {"schema": "BASM-N19-SNAPSHOT-FAULT-v1", "compiler": identity(cc),
               "source_inputs": [identity(p) for p in inputs], "harness": identity(harness),
               "compile_argv": command, "tests": [],
               "scope": "GNU linker wrappers in a private diagnostic harness; no emitted machine code executes"}
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    with (output / "compile.stdout").open("wb") as stdout, (output / "compile.stderr").open("wb") as stderr:
        built = subprocess.run(command, stdout=stdout, stderr=stderr, env=env, timeout=90)
    receipt["compile_returncode"] = built.returncode
    if built.returncode:
        (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
        raise SystemExit("snapshot harness compile failed: " + str(output / "compile.stderr"))
    receipt["binary"] = identity(binary)
    fixtures = {"empty": b"", "small": b"abcdef", "large": bytes(range(256))*512,
                "source": b"section .text\nnop\n", "nul": b"nop\n\0ret\n"}
    for name, data in fixtures.items():
        (output / (name + ".input")).write_bytes(data)
    cases = [(name, "none", name, "binary", True) for name in ("empty", "small", "large")]
    cases += [(mode, mode, "small", "binary", mode in ("short", "eintr", "short-eintr"))
              for mode in ("short", "eintr", "short-eintr", "growth", "shrink", "read-error",
                           "stat-error", "negative", "huge", "nonregular", "close-error")]
    cases += [("source", "none", "source", "source", True), ("nul-source", "none", "nul", "source", False),
              ("nul-binary", "none", "nul", "binary", True)]
    for name, mode, fixture, kind, succeeds in cases:
        argv = [str(binary), mode, str(output / (fixture + ".input")), kind]
        result = subprocess.run(argv, capture_output=True, env=env, timeout=10)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        log = result.stderr.decode("utf-8", errors="replace")
        match = re.search(r"SNAPSHOT_SPY reads=(\d+) interrupted=(\d+) closed=(\d+) stats=(\d+) bytes=(\d+)", log)
        counts = dict(zip(("reads", "interrupted", "closed", "stats", "bytes"), map(int, match.groups()))) if match else {}
        passed = (result.returncode == 0) == succeeds and result.returncode >= 0 and counts.get("closed") == 1
        if succeeds:
            passed &= json.loads(result.stdout)["bytes"] == len(fixtures[fixture])
        if mode in ("stat-error", "negative", "huge", "nonregular"):
            passed &= counts.get("reads") == 0
        if mode in ("eintr", "short-eintr"):
            passed &= counts.get("interrupted") == 1
        receipt["tests"].append({"name": name, "argv": argv, "returncode": result.returncode,
                                  "expected_success": succeeds, "counters": counts, "pass": bool(passed)})
    receipt["source_drift"] = [record["path"] for record in receipt["source_inputs"]
                               if identity(Path(record["path"]))["sha256"] != record["sha256"]]
    receipt["passed"] = sum(case["pass"] for case in receipt["tests"])
    receipt["failed"] = len(cases) - receipt["passed"]
    receipt["status"] = "PASS" if not receipt["failed"] and not receipt["source_drift"] else "FAIL"
    (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt[key] for key in ("status", "passed", "failed", "source_drift")}))
    return receipt["status"] != "PASS"


if __name__ == "__main__":
    raise SystemExit(main())
