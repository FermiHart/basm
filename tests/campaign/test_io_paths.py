#!/usr/bin/env python3
"""Alias preservation and descriptor-independent path-stat reuse within a phase."""
import argparse
import hashlib
import json
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
    source, output = args.source_root.resolve(), args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cc = Path(shutil.which(args.cc) or args.cc).resolve()
    harness = output / "io_paths_fault.c"
    shutil.copyfile(ROOT / "tests/campaign/io_paths_fault.c", harness)
    binary = output / "paths-host-check"
    command = [str(cc), "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-misleading-indentation", "-Wno-stringop-truncation", "-Wno-format-truncation",
               "-DSHA256NI_FORCE_SOFTWARE=1", "-ffunction-sections", "-fdata-sections",
               "-Wl,--gc-sections", "-Wl,--wrap=stat", "-I" + str(source), str(harness), "-o", str(binary)]
    inputs = [source / "basm.c", *sorted((source / "modules").glob("*.inc")),
              *sorted((source / "intent").glob("*.inc")), source / "isa/intent_forms.h"]
    receipt = {"schema": "BASM-N22-PATH-CHECK-v1", "compiler": identity(cc),
               "source_inputs": [identity(p) for p in inputs], "harness": identity(harness),
               "compile_argv": command, "tests": [],
               "scope": "host metadata checks on owned synthetic paths; no object or machine-code execution"}
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    built = subprocess.run(command, capture_output=True, env=env, timeout=90)
    (output / "compile.stdout").write_bytes(built.stdout)
    (output / "compile.stderr").write_bytes(built.stderr)
    receipt["compile_returncode"] = built.returncode
    if built.returncode:
        (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
        raise SystemExit("path harness compile failed: " + str(output / "compile.stderr"))
    receipt["binary"] = identity(binary)

    def prepare(name, count=1, same_base=False):
        directory = output / name
        directory.mkdir()
        deps = []
        for i in range(count):
            path = directory / ("dep-%d" % i) / "same.inc" if same_base else directory / ("dep-%d.inc" % i)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"input dependency retained\n")
            deps.append(path)
        return directory, deps

    def run(name, directory, target, attest, deps, succeeds, mode="check", expected_stats=None):
        before = {str(path): identity(path) for path in deps}
        argv = [str(binary), mode, str(target), str(attest) if attest else "-", *map(str, deps)]
        result = subprocess.run(argv, capture_output=True, env=env, timeout=10)
        (directory / "run.stdout").write_bytes(result.stdout)
        (directory / "run.stderr").write_bytes(result.stderr)
        match = re.search(rb"PATH_SPY output_stats=(\d+) parent_stats=(\d+)", result.stderr)
        counts = dict(zip(("output_stats", "parent_stats"), map(int, match.groups()))) if match else {}
        passed = (result.returncode == 0) == succeeds and result.returncode >= 0 and bool(counts)
        if mode == "phase-change":
            passed &= result.returncode not in (5, 6)
        passed &= all(identity(path) == before[str(path)] for path in deps)
        if expected_stats:
            passed &= all(counts.get(key) == value for key, value in expected_stats.items())
        receipt["tests"].append({"name": name, "argv": argv, "returncode": result.returncode,
                                 "expected_success": succeeds, "counters": counts,
                                 "expected_counters": expected_stats, "dependencies_before": before, "pass": bool(passed)})

    directory, deps = prepare("absent", 16)
    run("absent", directory, directory / "out.o", None, deps, True, expected_stats={"output_stats": 1, "parent_stats": 0})
    directory, deps = prepare("existing", 16)
    target = directory / "out.o"
    target.write_bytes(b"prior unrelated object")
    run("existing", directory, target, None, deps, True, expected_stats={"output_stats": 1, "parent_stats": 0})
    directory, deps = prepare("parent-reuse", 16, same_base=True)
    run("parent-reuse", directory, directory / "same.inc", None, deps, True, expected_stats={"output_stats": 1, "parent_stats": 1})
    directory, deps = prepare("identical")
    run("identical", directory, deps[0], None, deps, False)
    directory, deps = prepare("hardlink")
    target = directory / "out.o"
    target.hardlink_to(deps[0])
    run("hardlink", directory, target, None, deps, False)
    directory, deps = prepare("symlink")
    target = directory / "out.o"
    target.symlink_to(deps[0])
    run("symlink", directory, target, None, deps, False)
    directory, deps = prepare("parent-symlink")
    alias = directory / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    run("parent-symlink", directory, alias / deps[0].name, None, deps, False)
    directory, deps = prepare("dot-spelling")
    run("dot-spelling", directory, str(directory) + "/./" + deps[0].name, None, deps, False)
    directory, deps = prepare("object-attestation")
    run("object-attestation", directory, directory / "new.o", str(directory) + "/./new.o", deps, False)
    directory, deps = prepare("attestation-input")
    run("attestation-input", directory, directory / "out.o", deps[0], deps, False)
    directory, deps = prepare("secret-object")
    target = directory / "out.o"
    target.hardlink_to(deps[0])
    run("secret-object", directory, target, None, deps, False, mode="secrets")
    directory, deps = prepare("secret-attestation")
    proof = directory / "proof"
    proof.symlink_to(deps[0])
    run("secret-attestation", directory, directory / "out.o", proof, deps, False, mode="secrets")
    directory, deps = prepare("secret-distinct", 3)
    run("secret-distinct", directory, directory / "out.o", None, deps, True, mode="secrets", expected_stats={"output_stats": 1, "parent_stats": 0})
    directory, deps = prepare("phase-change")
    run("phase-change", directory, directory / "out.o", None, deps, False, mode="phase-change", expected_stats={"output_stats": 2})
    receipt["passed"] = sum(test["pass"] for test in receipt["tests"])
    receipt["failed"] = len(receipt["tests"]) - receipt["passed"]
    receipt["source_drift"] = [record["path"] for record in receipt["source_inputs"]
                               if identity(Path(record["path"]))["sha256"] != record["sha256"]]
    receipt["status"] = "PASS" if not receipt["failed"] and not receipt["source_drift"] else "FAIL"
    (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt[key] for key in ("status", "passed", "failed", "source_drift")}))
    return receipt["status"] != "PASS"


if __name__ == "__main__":
    raise SystemExit(main())
