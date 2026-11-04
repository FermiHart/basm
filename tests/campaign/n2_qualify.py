#!/usr/bin/env python3
"""N26/N27 retained integration gates; never execute assembled machine code.

This orchestrates existing regression gates with explicit, versioned binaries.
It is not a performance benchmark. Every invocation has separate logs, a
checkpointed receipt, and before/after identities for tracked source and tools.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def identity(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            digest.update(block)
    st = path.stat()
    return {"path": str(path), "bytes": st.st_size, "sha256": digest.hexdigest()}


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--normal", type=Path, required=True)
    ap.add_argument("--sanitize", type=Path, required=True)
    ap.add_argument("--nasm", type=Path, required=True)
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--cc", default="/usr/bin/x86_64-linux-gnu-gcc-13")
    ap.add_argument("--jobs", type=int, choices=(1, 2, 3), default=3)
    ap.add_argument("--group", choices=("legacy", "security", "waves", "all"), default="all")
    ap.add_argument("--only", help="comma-separated gate names for a retained, explicitly scoped follow-up")
    ap.add_argument("--list", action="store_true", help="print planned commands without running")
    args = ap.parse_args()
    normal, sanitized = args.normal.resolve(), args.sanitize.resolve()
    nasm, baseline = args.nasm.resolve(), args.baseline.resolve()
    out = args.output_dir.resolve()
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0",
           "BASM": str(normal / "basm-host"), "PUBLIC": str(normal / "basm-public-host"),
           "ELFTOOL": str(normal / "elftool-host"), "NASM": str(nasm), "CC": args.cc,
           "HOST_CC": args.cc}
    # BASM_CANDIDATE is intentionally absent: the legacy contract test which
    # executes a C consumer linked to emitted code is explicitly skipped.
    # test_main covers actual assembler objects + contract publication without
    # executing those objects. All other contract checks inspect bytes only.
    commands = []

    def add(name, argv, overrides=None, timeout=180):
        commands.append({"name": name, "argv": list(map(str, argv)),
                         "environment_overrides": overrides or {}, "timeout_s": timeout})

    if args.group in ("legacy", "all"):
        for name in ("isa_schema", "critical_regression", "expression_cache_capacity",
                     "text_capacity", "batch", "rel8_escrow", "intent_encoding",
                     "intent_trace", "intent_cfg", "reproducibility", "subset_spec",
                     "target_profiles", "target_profile_proof", "profile"):
            add("legacy-" + name, ["bash", ROOT / "tests" / (name + "_test.sh")])
        add("sha-known-answers", [normal / "test-sha-host"])
        add("sign-known-answers", [normal / "test-sign-host"])
        add("repository-assembly-corpus", ["bash", ROOT / "tests/run_tests.sh", normal / "basm-host"])

    if args.group in ("security", "all"):
        for lane_name, lane in (("normal", normal), ("sanitize", sanitized)):
            sanitizer_env = ({"ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:abort_on_error=1",
                              "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1"}
                             if lane_name == "sanitize" else {})
            binary = lane / "basm-host"
            common = ["--basm", binary]
            for test in ("inputs", "preprocessor", "writer", "trust", "review_regressions",
                         "main", "profile", "batch", "generation_version"):
                name = lane_name + "-" + test
                extra = []
                if test == "inputs":
                    extra = ["--profiles", "public,beyond,compatibility", "--json-out", out / name / "cases.json"]
                elif test == "preprocessor":
                    extra = ["--snapshot-api", "--cc", args.cc, "--output-dir", out / name / "cases"]
                elif test == "writer":
                    extra = ["--baseline", baseline]
                elif test == "trust":
                    extra = ["--elftool", lane / "elftool-host", "--json", out / name / "cases.json",
                             "--work-dir", out / name / "retained-cases"]
                elif test in ("review_regressions", "generation_version"):
                    extra = ["--json", out / name / "cases.json"]
                add(name, [sys.executable, ROOT / "tests/campaign" / ("test_" + test + ".py"), *common, *extra], sanitizer_env)
            add(lane_name + "-elf-parser", [sys.executable, ROOT / "tests/campaign/test_elf.py",
                "--binary", lane / "elftool-host"], sanitizer_env)
            add(lane_name + "-atomic-publication", [sys.executable, ROOT / "tests/atomic_publish_test.py", binary], sanitizer_env)
            fault_env = {**sanitizer_env, "BASM_PUBLICATION_KEEP": "1", "BASM_PUBLICATION_DIAGNOSTIC": "1"}
            if lane_name == "sanitize":
                fault_env["BASM_PUBLICATION_SANITIZE"] = "1"
            add(lane_name + "-publication-faults", ["bash", ROOT / "tests/publication_fault_test.sh"], fault_env, 240)
        add("public-only-inputs", [sys.executable, ROOT / "tests/campaign/test_inputs.py",
            "--basm", normal / "basm-public-host", "--profiles", "public", "--json-out", out / "public-only-inputs/cases.json"])
        add("contracts-inspection-only", [sys.executable, ROOT / "tests/campaign/test_contracts.py"])

    if args.group in ("waves", "all"):
        for lane_name, lane in (("normal", normal), ("sanitize", sanitized)):
            checks_env = ({"ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:abort_on_error=1",
                           "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1"}
                          if lane_name == "sanitize" else {})
            name = lane_name + "-wave-relocations"
            add(name, [sys.executable, ROOT / "tests/campaign/relocation_nasm_test.py",
                "--basm", lane / "basm-host", "--nasm", nasm, "--wave", "4",
                "--output-dir", out / name / "cases",
                *(["--asan-no-leaks"] if lane_name == "sanitize" else [])], checks_env)
            name = lane_name + "-wave-encoding"
            add(name, [sys.executable, ROOT / "tests/campaign/n2_encoding_regressions.py",
                "--basm", lane / "basm-host", "--public", lane / "basm-public-host",
                "--nasm", nasm, "--through", "8", "--output-dir", out / name / "cases",
                *(["--asan-no-leaks"] if lane_name == "sanitize" else [])], checks_env)
            name = lane_name + "-closure-equ-scale"
            add(name, [sys.executable, ROOT / "tests/campaign/equ_scale_closure_test.py",
                "--basm", lane / "basm-host", "--nasm", nasm, "--output-dir", out / name / "cases",
                *(["--asan-no-leaks"] if lane_name == "sanitize" else [])], checks_env)
            name = lane_name + "-closure-immediates"
            add(name, [sys.executable, ROOT / "tests/campaign/n26_immediate_relocations.py",
                "--basm", lane / "basm-host", "--public", lane / "basm-public-host",
                "--nasm", nasm, "--output-dir", out / name / "cases",
                *(["--asan-no-leaks"] if lane_name == "sanitize" else [])], checks_env)
            name = lane_name + "-wave-symbols"
            add(name, [sys.executable, ROOT / "tests/campaign/test_symbol_storage.py",
                "--basm", lane / "basm-host", "--receipt", lane / "build-receipt.json",
                "--nasm", nasm, "--cc", args.cc, "--out", out / name / "cases",
                *(["--sanitize"] if lane_name == "sanitize" else [])], checks_env)
            name = lane_name + "-wave-preprocessor"
            add(name, [sys.executable, ROOT / "tests/campaign/test_preprocessor_nasm_waves.py",
                "--basm", lane / "basm-host", "--nasm", nasm, "--cc", args.cc,
                "--output-dir", out / name / "cases",
                *(["--sanitize-probe"] if lane_name == "sanitize" else [])], checks_env)
            name = lane_name + "-wave-buffers"
            add(name, [sys.executable, ROOT / "tests/campaign/test_io_buffers.py",
                "--basm", lane / "basm-host", "--output-dir", out / name / "cases",
                *(["--asan-no-leaks"] if lane_name == "sanitize" else [])], checks_env)
        for suffix, script in (("snapshot", "test_io_snapshot.py"), ("paths", "test_io_paths.py")):
            name = "wave-io-" + suffix
            add(name, [sys.executable, ROOT / "tests/campaign" / script,
                "--source-root", normal / "source", "--cc", args.cc,
                "--output-dir", out / name / "cases"])

    if args.only:
        selected = args.only.split(",")
        unknown = set(selected) - {spec["name"] for spec in commands}
        if unknown or len(selected) != len(set(selected)):
            ap.error("unknown or duplicate follow-up gates: " + args.only)
        commands = [spec for spec in commands if spec["name"] in selected]
    if args.list:
        print(json.dumps({"environment": env, "commands": commands}, indent=2))
        return 0
    out.mkdir(parents=True, exist_ok=False)
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    paths = [ROOT / name for name in tracked if name]
    paths.extend([nasm, baseline, Path(args.cc), Path(sys.executable)])
    for lane in (normal, sanitized):
        paths.extend(lane / filename for filename in ("basm-host", "basm-public-host", "elftool-host", "test-sha-host", "test-sign-host", "build-receipt.json"))
    unique = sorted({p.resolve() for p in paths})
    before = {str(p): identity(p) for p in unique}
    receipt = {"schema": "BASM-N26-N27-QUALIFICATION-v1", "lane": "HOST_DIAGNOSTIC_NOT_SOVEREIGN",
               "purpose": "correctness and security qualification, not performance timing",
               "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
               "source_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=ROOT)).hexdigest(),
               "environment": env, "identities_before": before, "commands": commands,
               "explicit_scope_exclusion": "legacy C-consumer execution test is skipped; generated code is not executed",
               "results": [], "status": "RUNNING"}
    write_json(out / "result.json", receipt)
    shutil.copyfile(__file__, out / "runner.py")

    def run(spec):
        folder = out / spec["name"]
        folder.mkdir()
        temporary = folder / "tmp"
        temporary.mkdir()
        child_env = {**env, **spec["environment_overrides"], "TMPDIR": str(temporary),
                     "BASM_PUBLICATION_TMPDIR": str(temporary)}
        # Keep reports outside temporary case directories. A UBSan failure may
        # otherwise return the same code as an expected input refusal, or be
        # captured by a nested publisher. It must still fail this entire gate.
        if "ASAN_OPTIONS" in child_env:
            child_env["ASAN_OPTIONS"] += ":log_path=" + str(folder / "asan-report")
        if "UBSAN_OPTIONS" in child_env:
            child_env["UBSAN_OPTIONS"] += ":log_path=" + str(folder / "ubsan-report")
        # A writable private copy allows the reviewed cache identity test to
        # modify its own non-loaded trailer copy without touching the candidate.
        if spec["name"] == "legacy-rel8_escrow":
            clone = folder / "basm-host-private"
            shutil.copyfile(normal / "basm-host", clone)
            clone.chmod(0o700)
            child_env["BASM"] = str(clone)
        started = time.monotonic()
        with (folder / "stdout.log").open("wb") as stdout, (folder / "stderr.log").open("wb") as stderr:
            try:
                p = subprocess.run(spec["argv"], cwd=ROOT, env=child_env, stdout=stdout, stderr=stderr, timeout=spec["timeout_s"])
                code = p.returncode
            except subprocess.TimeoutExpired:
                code = "TIMEOUT"
            except OSError as exc:
                stderr.write((repr(exc) + "\n").encode())
                code = "LAUNCH_ERROR"
        sanitizer_reports = [identity(p) for pattern in ("asan-report*", "ubsan-report*")
                             for p in sorted(folder.glob(pattern)) if p.is_file()]
        row = {**spec, "returncode": code, "status": "PASS" if code == 0 and not sanitizer_reports else "REVIEW_REQUIRED",
               "diagnostic_elapsed_s": time.monotonic() - started,
               "effective_environment": child_env,
               "sanitizer_reports": sanitizer_reports,
               "stdout": identity(folder / "stdout.log"), "stderr": identity(folder / "stderr.log")}
        write_json(folder / "receipt.json", row)
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run, spec): spec["name"] for spec in commands}
        for future in concurrent.futures.as_completed(futures):
            row = future.result()
            receipt["results"].append(row)
            write_json(out / "result.json", receipt)
            print(row["name"], row["status"], row["returncode"], flush=True)
    after = {str(p): identity(p) for p in unique}
    receipt["identities_after"] = after
    receipt["integrity_passed"] = before == after
    receipt["passed_gates"] = sum(row["status"] == "PASS" for row in receipt["results"])
    receipt["status"] = ("PASS_WITH_EXPLICIT_EXECUTION_EXCLUSION" if before == after and
                         receipt["passed_gates"] == len(commands) else "REVIEW_REQUIRED")
    write_json(out / "result.json", receipt)
    print(json.dumps({key: receipt[key] for key in ("status", "passed_gates", "integrity_passed")}), flush=True)
    return 0 if receipt["status"] == "PASS_WITH_EXPLICIT_EXECUTION_EXCLUSION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
