#!/usr/bin/env python3
"""Bounded comparison of a retained BearBasm host build and real NASM defaults.

Only independently validated common-output cases can be timed. This compares
these executable identities on this corpus; it is not a Bear compiler result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

from nasm_elf import ElfFormatError, compare_elf
from nasm_artifacts import ArtifactLedger
from nasm_protocol import (PROTOCOL_FILE, WORKLOADS, block_schedule, load_protocol,
                           retention_reserve_bytes)
from nasm_review import review_result

SCHEMA = "BASM-NASM-BENCHMARK-v2"
STACK_MARKER = "section .note.GNU-stack noalloc noexec nowrite progbits align=1\n"
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"}


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def same_bytes(actual, expected):
    return all(actual[key] == expected.get(key) for key in ("sha256", "bytes"))


def summary(values):
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    return {"median": median, "mad": mad,
            "relative_mad": mad / median if median else 0,
            "minimum": min(values), "maximum": max(values)}


def describe_samples(pairs):
    """Descriptive per-case statistics; the independent N25 reviewer recomputes."""
    lanes = {}
    for role in ("nasm", "basm"):
        lanes[role] = {field: summary([pair[role][field] for pair in pairs])
                       for field in ("wall_ns", "user_us", "system_us", "peak_rss_kib")}
        lanes[role]["cpu_total_us"] = summary([pair[role]["user_us"] + pair[role]["system_us"]
                                                for pair in pairs])
    wall = summary([pair["nasm"]["wall_ns"] / pair["basm"]["wall_ns"] for pair in pairs])
    cpu_denominators = [pair["basm"]["user_us"] + pair["basm"]["system_us"] for pair in pairs]
    cpu = (summary([(pair["nasm"]["user_us"] + pair["nasm"]["system_us"]) / denominator
                    for pair, denominator in zip(pairs, cpu_denominators)])
           if all(denominator > 0 for denominator in cpu_denominators) else None)
    stable = wall["relative_mad"] <= .25 and all(lanes[role]["wall_ns"]["relative_mad"] <= .25
                                                for role in ("nasm", "basm"))
    return {"sample_count": len(pairs), "lanes": lanes, "paired_nasm_over_basm": wall,
            "paired_cpu_nasm_over_basm": cpu, "status": "STABLE" if stable else "INCONCLUSIVE",
            "lower_paired_median": ("basm" if wall["median"] > 1 else "nasm" if wall["median"] < 1 else "equal") if stable else None}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def generate_fixtures(directory):
    """Versioned, predetermined corpus. Never alter it after observing a mismatch."""
    directory.mkdir()
    cases = []
    header = "bits 64\nsection .text\nglobal entry\nentry:\n"

    def add(name, text, category="matrix", fmt="elf64", extra=None, description=""):
        source = directory / (name + ".asm")
        source.write_text(text + (STACK_MARKER if fmt == "elf64" else ""))
        cases.append({"name": name, "source": str(source), "format": fmt,
                      "category": category, "extra": extra or [], "description": description})

    add("tiny", header + "mov rax,rbx\nadd rax,7\nxor rcx,rcx\nret\n",
        description="Four instructions; process-startup control.")
    for name, count, category in (("instructions", 4000, "matrix"),
                                  ("instructions-large", 32000, "scaling")):
        add(name, header + "".join("add rax,%d\nxor rcx,%d\n" % (i % 997, i % 127)
                                   for i in range(count)) + "ret\n", category,
            description="%d ALU instructions plus ret; default immediate sizing." % (count * 2))
    add("branches", header + "".join("cmp rax,%d\njne .L%d\nnop\n.L%d:\n" % (i, i, i)
                                      for i in range(1000)) + "ret\n",
        description="1,000 conditional branches with default relaxation.")
    for name, count, category in (("macros", 2000, "matrix"),
                                  ("macros-large", 16000, "scaling")):
        add(name, "bits 64\n%macro MIX 1\nadd rax,%1\n%endmacro\n" + header +
            "".join("MIX %d\n" % (i % 997) for i in range(count)) + "ret\n", category,
            description="%d simple positional macro invocations." % count)
    include_dir = directory / "include"
    include_dir.mkdir()
    source = header
    for part in range(12):
        filename = "part%02d.inc" % part
        (include_dir / filename).write_text("".join("add rax,%d\nxor rbx,%d\n" % (part * 32 + i, i)
                                                    for i in range(32)))
        source += '%%include "%s"\n' % filename
    add("includes", source + "ret\n", extra=["-I" + str(include_dir) + "/"],
        description="Twelve includes, each containing 32 pairs of instructions.")
    reloc = "bits 64\nextern external_target\n" + header
    reloc += "call external_target\n" * 2000
    reloc += ("mov rax,external_target\nmov eax,[abs external_target]\n"
              "mov rax,[abs external_target]\nmov eax,[rel external_target]\nret\n"
              "section .data\ndq external_target,entry\ndd external_target,entry\n")
    add("relocations", reloc,
        description="2,000 external calls plus mixed PC-relative and 64/32-bit absolute relocations.")
    custom = "bits 64\n"
    for section in range(8):
        custom += "section .campaign%d alloc noexec nowrite progbits align=16\n" % section
        custom += "global data%d\ndata%d:\n" % (section, section)
        custom += "".join("dq %d\n" % (section * 256 + i) for i in range(128))
    add("custom-sections", custom + header + "ret\n",
        description="Eight declared data sections, each with 128 quadwords.")
    add("flat-bin", "bits 64\norg 0x1000\nsection .text\n" +
        "".join("add rax,%d\njne next%d\nnop\nnext%d:\n" % (i, i, i)
                for i in range(128)) + "ret\n", fmt="bin",
        description="128 branch blocks in a flat binary with fixed origin.")
    for name, megabytes, category in (("incbin", 1, "matrix"),
                                     ("incbin-large", 8, "scaling")):
        payload = directory / (name + "-payload.bin")
        payload.write_bytes(bytes(range(256)) * (4096 * megabytes))
        add(name, 'bits 64\nsection .rodata\nglobal payload\npayload:\nincbin "%s"\n' % payload,
            category, description="%d MiB included payload; warm-filesystem I/O control." % megabytes)
    labels = "".join("L%d:\nnop\n" % i for i in range(10000)) + "ret\n"
    add("labels-10000", header + labels, "microbenchmark",
        description="10,000 ordered application-local labels; no BASM-specific static directive.")
    add("globals-reversed-10000", "bits 64\n" +
        "".join("global L%d\n" % i for i in range(9999, -1, -1)) + header + labels,
        "microbenchmark", description="10,000 standard globals declared in reverse definition order.")
    add("contextual-expressions", "bits 64\nsection .data\n" + "dd $\n" * 1000,
        "microbenchmark", description="1,000 location-counter expressions and relocations.")
    addresses = ["rbx", "rsp", "rsp+8", "r12+r9*4+128", "eax+ecx*2", "fs:rbx"]
    addressing = "".join("mov rax,[%s]\nmov [%s],rax\n" % (address, address)
                          for address in addresses)
    add("addressing", header + (addressing + "lea r10,[r12+r9*4+128]\n") * 128 + "ret\n",
        "coverage", description="GPR, stack/base, SIB, address-size and segment-prefix forms.")
    return cases


def load_tools(args):
    basm_receipt = json.loads(args.basm_receipt.read_text())
    if (basm_receipt.get("lane") != "HOST_DIAGNOSTIC_NOT_SOVEREIGN" or
            basm_receipt.get("status") != "BUILT_FROM_RETAINED_HOST_SNAPSHOT" or
            basm_receipt.get("sanitizers")):
        raise ValueError("BASM must be an unsanitized retained host diagnostic build")
    basm = identity(args.basm)
    if not same_bytes(basm, basm_receipt.get("artifacts", {}).get("basm-host", {})):
        raise ValueError("BASM executable differs from its build receipt")
    nasm = identity(args.nasm)
    lanes = {"nasm": {"binary": nasm},
             "basm": {"binary": basm, "build": basm_receipt,
                      "build_receipt": identity(args.basm_receipt)}}
    if args.nasm_receipt:
        nasm_receipt = json.loads(args.nasm_receipt.read_text())
        if not same_bytes(nasm, nasm_receipt.get("artifacts", {}).get("nasm", {})):
            raise ValueError("NASM executable differs from its acquisition/build receipt")
        lanes["nasm"].update({"build": nasm_receipt, "build_receipt": identity(args.nasm_receipt)})
    for lane in lanes.values():
        if not os.access(lane["binary"]["path"], os.X_OK):
            raise ValueError("assembler is not executable")
    inspector = identity(args.elftool)
    if not same_bytes(inspector, basm_receipt.get("artifacts", {}).get("elftool-host", {})):
        raise ValueError("ELF inspector differs from the retained BASM build receipt")
    return lanes, inspector


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--basm-receipt", type=Path, required=True)
    parser.add_argument("--nasm", type=Path, required=True)
    parser.add_argument("--nasm-receipt", type=Path)
    parser.add_argument("--elftool", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=15)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--blocks", type=int, choices=(1, 3), default=3,
                        help="three predeclared final blocks; one block is explicitly diagnostic")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cases", help="comma-separated predeclared cases; default is all 16")
    parser.add_argument("--validate-only", action="store_true", help="assemble and validate twice; no performance samples")
    parser.add_argument("--cpu", type=int, help="pin the runner and inherited child affinity to this permitted CPU")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("native wait4 measurement currently requires Linux")
    if not 5 <= args.rounds <= 15 or not 1 <= args.warmups <= 3 or not 1 <= args.timeout <= 10:
        parser.error("rounds must be 5..15, warmups 1..3 and timeout 1..10")
    schedule = block_schedule(args.blocks, args.rounds, args.warmups)
    affinity_before = sorted(os.sched_getaffinity(0))
    if args.cpu is not None:
        if args.cpu not in affinity_before:
            parser.error("requested CPU is not in the effective allowed affinity: " + str(affinity_before))
        os.sched_setaffinity(0, {args.cpu})
    affinity_effective = sorted(os.sched_getaffinity(0))
    if args.cpu is not None and affinity_effective != [args.cpu]:
        parser.error("requested CPU pinning was not effective")
    out = args.output_dir.resolve()
    if out.exists():
        parser.error("output directory must be fresh; preserve all previous results")
    for key in ("basm", "basm_receipt", "nasm", "elftool"):
        setattr(args, key, getattr(args, key).resolve())
    if args.nasm_receipt:
        args.nasm_receipt = args.nasm_receipt.resolve()
    lanes, inspector = load_tools(args)
    out.mkdir(parents=True, mode=0o700)
    receipt = {"schema": SCHEMA, "scope": "RETAINED_BASM_HOST_DIAGNOSTIC_VS_NASM_COMMON_CORPUS_ONLY",
               "status": "PREPARING", "mode": "validation_only" if args.validate_only else "performance",
               "tools": lanes, "elftool": inspector, "commands": [], "cases": [],
               "default_protocol_requested": not args.cases and not args.validate_only and args.blocks == 3 and args.rounds == 15 and args.warmups == 3 and args.timeout == 10 and args.cpu == 0,
               "protocol_purpose": "validation_only" if args.validate_only else "single_block_diagnostic" if args.blocks == 1 else "three_block_comparison",
               "complete_default_protocol": False,
               "host": {"uname": list(platform.uname()), "affinity_before": affinity_before,
                        "cpu_requested": args.cpu, "affinity_effective": affinity_effective,
                        "cpuinfo_first_processor": Path("/proc/cpuinfo").read_text().split("\n\n")[0],
                        "loadavg_before": list(os.getloadavg())},
               "method": {"blocks": args.blocks, "rounds": args.rounds, "warmups": args.warmups,
                          "paired_order": "alternating NASM/BASM and BASM/NASM, inverted starting order in block two",
                          "primary_statistic": "median of paired NASM/BASM native wall ratios; above one favors BASM",
                          "dispersion_threshold_relative_mad": 0.25,
                          "interpretation": "STABLE requires the original dispersion rule in every block and pooled within each case; it is not statistical significance. No cross-product 15% regression gate and no cross-case aggregated speedup.",
                          "clock": "CLOCK_MONOTONIC around native fork/exec/wait4",
                          "rss": "native child ru_maxrss in KiB, including small native pre-exec image, never Python image",
                          "configuration": "Both assembler optimization defaults, no explicit -O; no optional BASM profile, evidence, signing, cache or batch flags.",
                          "source": "Identical sources and include flags for both tools; explicit non-executable GNU stack marker in every ELF source.",
                          "cache": "Warm filesystem/page cache; fresh processes and fresh output paths; no object-cache options.",
                          "frequency": "not fixed", "isolation": "shared host; affinity pinning does not isolate a physical core",
                          "environment": ENVIRONMENT,
                          "inherited_environment": "allowlist only; parent environment is not passed to tools",
                          "sensitive_environment_names_removed": sorted(k for k in os.environ if k == "NASMENV" or k.startswith(("BASM_", "LD_", "ASAN_", "UBSAN_", "MSAN_", "TSAN_", "LSAN_", "HWASAN_"))),
                          "per_command_timeout_s": args.timeout, "aggregate_timeout_s": 600,
                          "validation": "Strict independent ELF content/linkage/relocation parity before and after timing, exact flat bytes, per-lane raw object identity on every invocation; elftool diff is a secondary check only.",
                          "limits": "No emitted code is executed. No proof of arbitrary program semantics, no Bear-compiler performance inference, and no matched-compiler-flags claim between products."}}
    started = None
    artifacts = None
    try:
        here = Path(__file__).resolve().parent
        artifacts = ArtifactLedger(out)
        protocol = load_protocol(here)
        receipt["preregistered_protocol"] = {"identity": identity(here / PROTOCOL_FILE), "content": protocol}
        receipt["sampling_schedule"] = schedule
        reserve = retention_reserve_bytes(args.blocks, args.validate_only)
        free = shutil.disk_usage(out).free
        receipt["disk_preflight"] = {"free_bytes_before": free, "required_reserve_bytes": reserve,
                                     "status": "PASS" if free >= reserve else "INSUFFICIENT"}
        if free < reserve:
            raise RuntimeError("insufficient free disk space for all retained benchmark objects")
        helper_names = ("nasm_benchmark.py", "nasm_elf.py", "nasm_artifacts.py", "nasm_protocol.py", "nasm_review.py", PROTOCOL_FILE, "measure_process.c")
        for filename in helper_names:
            shutil.copyfile(here / filename, out / filename)
            artifacts.capture(here / filename, "original_helper")
            artifacts.capture(out / filename, "retained_helper", single_link=True)
        receipt["runner"] = identity(here / "nasm_benchmark.py")
        receipt["checker"] = identity(here / "nasm_elf.py")
        receipt["retained_helpers"] = [identity(out / n) for n in helper_names]
        for role, lane in lanes.items():
            artifacts.capture(lane["binary"]["path"], "assembler")
            snapshot = out / (role + ".executable")
            shutil.copyfile(lane["binary"]["path"], snapshot)
            snapshot.chmod(0o500)
            lane["snapshot"] = identity(snapshot)
            artifacts.capture(snapshot, "retained_assembler", single_link=True)
            if not same_bytes(lane["snapshot"], lane["binary"]):
                raise RuntimeError("tool changed while retaining snapshot: " + role)
            if "build_receipt" in lane:
                artifacts.capture(lane["build_receipt"]["path"], "build_receipt")
                shutil.copyfile(lane["build_receipt"]["path"], out / (role + ".build-receipt.json"))
                artifacts.capture(out / (role + ".build-receipt.json"), "retained_build_receipt", single_link=True)
        artifacts.capture(inspector["path"], "elf_inspector")
        cc = Path(lanes["basm"]["build"]["compiler"]["path"])
        receipt["launcher_compiler"] = identity(cc)
        artifacts.capture(cc, "compiler")
        if not same_bytes(receipt["launcher_compiler"], lanes["basm"]["build"]["compiler"]):
            raise RuntimeError("launcher compiler changed from retained BASM build identity")
        launcher = out / "measure_process"
        compile_argv = [str(cc), "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(out / "measure_process.c"), "-o", str(launcher)]
        compiled = subprocess.run(compile_argv, capture_output=True, text=True, env=ENVIRONMENT, timeout=30)
        (out / "launcher-build.stdout").write_text(compiled.stdout)
        (out / "launcher-build.stderr").write_text(compiled.stderr)
        artifacts.capture(out / "launcher-build.stdout", "compiler_stdout", single_link=True)
        artifacts.capture(out / "launcher-build.stderr", "compiler_stderr", single_link=True)
        receipt["launcher_build"] = {"argv": compile_argv, "returncode": compiled.returncode}
        if compiled.returncode:
            raise RuntimeError("native launcher compilation failed")
        receipt["launcher"] = identity(launcher)
        artifacts.capture(launcher, "native_launcher", single_link=True)
        receipt["python"] = {"executable": identity(Path(sys.executable).resolve()), "version": sys.version}
        artifacts.capture(Path(sys.executable).resolve(), "python")
        cases = generate_fixtures(out / "fixtures")
        if [case["name"] for case in cases] != list(WORKLOADS):
            raise RuntimeError("original sixteen-case corpus or order changed")
        if args.cases:
            selected = args.cases.split(",")
            unknown = set(selected) - {case["name"] for case in cases}
            if unknown or len(selected) != len(set(selected)):
                raise ValueError("unknown or duplicate selected cases: " + args.cases)
            cases = [case for case in cases if case["name"] in selected]
        receipt["fixtures"] = [identity(path) for path in sorted((out / "fixtures").rglob("*")) if path.is_file()]
        for fixture in receipt["fixtures"]:
            artifacts.capture(fixture["path"], "fixture", single_link=True)
        receipt["method"]["selected_workloads"] = [case["name"] for case in cases]
        receipt["method"]["workload_count"] = len(cases)
        started = time.monotonic()

        def execute(argv, tag, stage, role=None, case=None, measured=False):
            if time.monotonic() - started >= 600 - args.timeout - 2:
                raise RuntimeError("aggregate 600-second protocol budget exhausted")
            stdout = out / (tag + ".stdout")
            stderr = out / (tag + ".stderr")
            artifacts.expect_absent(stdout, "command_stdout", single_link=True)
            artifacts.expect_absent(stderr, "command_stderr", single_link=True)
            argv = [str(arg) for arg in argv]
            launch = [str(launcher), str(stdout), str(stderr), str(args.timeout), "--"] + argv
            done = subprocess.run(launch, capture_output=True, text=True, env=ENVIRONMENT,
                                  cwd=out, timeout=args.timeout + 2)
            for path, kind in ((stdout, "command_stdout"), (stderr, "command_stderr")):
                if os.path.lexists(path):
                    artifacts.capture(path, kind, single_link=True)
            if done.returncode:
                raise RuntimeError("native launcher failed: " + done.stderr)
            sample = json.loads(done.stdout)
            sample.update({"argv": argv, "stdout": str(stdout), "stderr": str(stderr),
                           "measured": measured, "stage": stage, "tool": role, "case": case})
            receipt["commands"].append(sample)
            return sample

        def successful(sample):
            return sample["returncode"] == 0 and not sample["timed_out"]

        def assemble(case, role, stage, measured=False, optimization=None):
            output = artifacts.reserve_object(role)
            argv = [lanes[role]["binary"]["path"], "-f", case["format"], "-o", str(output)]
            if optimization:
                argv.append(optimization)
            argv += case["extra"] + [case["source"]]
            tag = case["name"] + "-" + role + "-" + stage
            sample = execute(argv, tag, stage, role, case["name"], measured)
            sample["output_path"] = str(output)
            if os.path.lexists(output):
                sample["object"] = artifacts.capture(output, "assembly_output", single_link=True)
            if successful(sample):
                if not output.is_file() or not output.stat().st_size:
                    raise RuntimeError("assembler succeeded without nonempty fresh output: " + tag)
                if "BASM_PROFILE " in Path(sample["stderr"]).read_text(errors="replace"):
                    raise RuntimeError("unexpected optional profiling in defaults comparison")
            return sample

        def validate_pair(case, stage, samples):
            failures = {role: sample["returncode"] for role, sample in samples.items() if not successful(sample)}
            if failures:
                return {"equal": False, "failure": "ASSEMBLER_REJECTED_SOURCE", "returncodes": failures,
                        "artifacts": {role: sample.get("object") for role, sample in samples.items()}}
            paths = {role: Path(sample["object"]["path"]) for role, sample in samples.items()}
            retained = {}
            for role, path in paths.items():
                copy = out / (case["name"] + "-" + role + "-" + stage + ".object")
                shutil.copyfile(path, copy)
                retained[role] = artifacts.capture(copy, "parity_snapshot", single_link=True)
            if case["format"] == "bin":
                check = {"equal": paths["nasm"].read_bytes() == paths["basm"].read_bytes(),
                         "comparison": "exact flat-binary bytes"}
            else:
                try:
                    check = compare_elf(paths["nasm"], paths["basm"])
                except (ElfFormatError, ValueError) as exc:
                    check = {"equal": False, "failure": "ELF_REJECTED_BY_INDEPENDENT_CHECKER", "error": str(exc)}
                secondary = execute([inspector["path"], "diff", str(paths["nasm"]), str(paths["basm"])],
                                    case["name"] + "-" + stage + "-elftool-diff", stage + "-secondary-diff", case=case["name"])
                check["secondary_elftool_diff"] = {"returncode": secondary["returncode"],
                                                     "timed_out": secondary["timed_out"],
                                                     "stdout": secondary["stdout"], "stderr": secondary["stderr"],
                                                     "authority": "Secondary diagnostic only; its broader normalization does not override independent parity."}
                if secondary["timed_out"]:
                    raise RuntimeError("secondary ELF comparison timed out")
            check["artifacts"] = retained
            destination = out / (case["name"] + "-" + stage + "-parity.json")
            destination.write_text(json.dumps(check, indent=2, sort_keys=True) + "\n")
            artifacts.capture(destination, "parity_receipt", single_link=True)
            secondary_rc = check.get("secondary_elftool_diff", {}).get("returncode")
            return {"equal": check["equal"], "receipt": identity(destination),
                    "failure": check.get("failure"), "secondary_returncode": secondary_rc,
                    "requires_review": bool(check["equal"] and secondary_rc not in (None, 0))}

        version_nasm = execute([args.nasm, "-v"], "nasm-version", "identity", "nasm")
        if not successful(version_nasm):
            raise RuntimeError("NASM version probe failed")
        lanes["nasm"]["version_probe"] = version_nasm
        lanes["nasm"]["version"] = (Path(version_nasm["stdout"]).read_text() + Path(version_nasm["stderr"]).read_text()).strip()
        version_basm = execute([args.basm, "--version"], "basm-version", "identity", "basm")
        lanes["basm"]["version_probe"] = version_basm
        lanes["basm"]["version_limit"] = "Retained BASM build has no --version interface; executable hash and build receipt are authoritative, not an invented version."
        capabilities = execute([args.basm, "--capabilities"], "basm-capabilities", "identity", "basm")
        if not successful(capabilities):
            raise RuntimeError("BASM capabilities probe failed")
        lanes["basm"]["capabilities"] = json.loads(Path(capabilities["stdout"]).read_text())

        # Every selected case is checked before any measured sample is collected.
        records = {}
        for case in cases:
            record = {**case, "status": "VALIDATING", "observations": [], "block_results": [], "lanes": {}}
            receipt["cases"].append(record)
            records[case["name"]] = record
            samples = {role: assemble(case, role, "before") for role in ("nasm", "basm")}
            for role, sample in samples.items():
                record["lanes"][role] = {"initial_assembly": sample,
                                          "initial_output": sample.get("object")}
            record["validation_before"] = validate_pair(case, "before", samples)
            record["eligible"] = record["validation_before"]["equal"] and not record["validation_before"].get("requires_review")
            record["status"] = ("VALIDATED" if record["eligible"] else
                                "SECONDARY_REVIEW_REQUIRED" if record["validation_before"].get("requires_review") else
                                "EXCLUDED_INCOMPATIBLE")
            print(case["name"], record["status"], flush=True)

        # One explicit, untimed default/-Ox/-Oxv check records NASM's pass report.
        check_case = next((case for case in cases if case["name"] == "branches"), cases[0])
        default = records[check_case["name"]]["lanes"]["nasm"]["initial_assembly"]
        config_check = {"case": check_case["name"], "default_argv": default["argv"],
                        "purpose": "Untimed verification only; all measured assembler commands retain defaults.", "comparisons": []}
        if successful(default):
            for option in ("-Ox", "-Oxv"):
                sample = assemble(check_case, "nasm", "defaults-check-" + option[1:], optimization=option)
                equal = successful(sample) and same_bytes(sample["object"], default["object"])
                config_check["comparisons"].append({"option": option, "matches_default_raw_object": equal, "command": sample})
                if not equal:
                    raise RuntimeError("NASM default and explicit -Ox output differ; do not present this as the expected defaults comparison")
        else:
            config_check["status"] = "DEFAULT_SOURCE_REJECTED; no optimization-default assertion"
        receipt["nasm_default_optimization_check"] = config_check

        # No performance sample precedes the refined all-output retention check.
        initial_bytes = sum(record["lanes"][role]["initial_output"]["bytes"]
                            for record in records.values() if record["eligible"]
                            for role in ("nasm", "basm"))
        remaining_copies = 2 if args.validate_only else args.blocks * (args.rounds + args.warmups + 2)
        remaining_estimate = initial_bytes * remaining_copies + 128 * 1024 * 1024
        free = shutil.disk_usage(out).free
        receipt["disk_preflight"].update({"eligible_initial_output_bytes": initial_bytes,
                                          "estimated_remaining_bytes_with_margin": remaining_estimate,
                                          "free_bytes_after_preflight": free})
        if free < remaining_estimate:
            raise RuntimeError("insufficient disk space after corpus preflight; no measured samples collected")

        collection_blocks = [{"block": 0, "pairs": []}] if args.validate_only else schedule
        for scheduled_block in collection_blocks:
            block = scheduled_block["block"]
            for case in cases:
                record = records[case["name"]]
                if not record["eligible"]:
                    continue
                observations = []
                for planned_pair in scheduled_block["pairs"]:
                    pair = dict(planned_pair)
                    for role in pair["order"]:
                        stage = "block-%02d-sample-%02d" % (block, pair["round"])
                        sample = assemble(case, role, stage, measured=not pair["warmup"])
                        sample["block"] = block
                        sample["round"] = pair["round"]
                        pair[role] = sample
                        if not successful(sample) or not same_bytes(sample["object"], record["lanes"][role]["initial_output"]):
                            raise RuntimeError("assembly failed or per-lane output changed: " + case["name"] + "/" + role)
                    record["observations"].append(pair)
                    observations.append(pair)
                stage = "validation-after" if args.validate_only else "block-%02d-after" % block
                after = {role: assemble(case, role, stage) for role in ("nasm", "basm")}
                for role, sample in after.items():
                    if not successful(sample) or not same_bytes(sample["object"], record["lanes"][role]["initial_output"]):
                        raise RuntimeError("post-validation assembly failed or changed: " + case["name"] + "/" + role)
                validation = validate_pair(case, stage, after)
                if not validation["equal"] or validation.get("requires_review"):
                    raise RuntimeError("independent post-measurement parity failed: " + case["name"])
                prior_validation = record.get("validation_after", record["validation_before"])
                record["validation_after"] = validation
                if args.validate_only:
                    record["status"] = "VALIDATED"
                    continue
                measured = [pair for pair in observations if not pair["warmup"]]
                description = describe_samples(measured)
                description.update({"block": block, "validation_before": prior_validation,
                                    "validation_after": validation})
                record["block_results"].append(description)
                print(case["name"], "block", block, description["status"], "paired NASM/BASM",
                      round(description["paired_nasm_over_basm"]["median"], 6), flush=True)

        for case in cases:
            record = records[case["name"]]
            if not record["eligible"] or args.validate_only:
                continue
            measured = [pair for pair in record["observations"] if not pair["warmup"]]
            pooled = describe_samples(measured)
            record["pooled"] = pooled
            for role in ("nasm", "basm"):
                record["lanes"][role].update(pooled["lanes"][role])
            record["paired_nasm_over_basm"] = pooled["paired_nasm_over_basm"]
            record["paired_cpu_nasm_over_basm"] = pooled["paired_cpu_nasm_over_basm"]
            stable = pooled["status"] == "STABLE" and all(item["status"] == "STABLE" for item in record["block_results"])
            record["status"] = "STABLE" if stable else "INCONCLUSIVE"
            record["lower_paired_median"] = pooled["lower_paired_median"] if stable else None
            print(case["name"], "pooled", record["status"], "paired NASM/BASM",
                  round(pooled["paired_nasm_over_basm"]["median"], 6), flush=True)

        for role, lane in lanes.items():
            if identity(lane["binary"]["path"]) != lane["binary"] or identity(lane["snapshot"]["path"]) != lane["snapshot"]:
                raise RuntimeError("assembler identity drifted: " + role)
            if "build_receipt" in lane and identity(lane["build_receipt"]["path"]) != lane["build_receipt"]:
                raise RuntimeError("build receipt identity drifted: " + role)
        for record in receipt["fixtures"] + receipt["retained_helpers"] + [receipt["runner"], receipt["checker"], receipt["launcher"], inspector]:
            if identity(record["path"]) != record:
                raise RuntimeError("fixture, checker or helper identity drifted: " + record["path"])
        receipt["excluded_cases"] = [case["name"] for case in receipt["cases"] if not case["eligible"]]
        receipt["secondary_review_required_cases"] = [case["name"] for case in receipt["cases"] if case["status"] == "SECONDARY_REVIEW_REQUIRED"]
        receipt["inconclusive_cases"] = [case["name"] for case in receipt["cases"] if case["status"] == "INCONCLUSIVE"]
        receipt["eligible_cases"] = [case["name"] for case in receipt["cases"] if case["eligible"]]
        receipt["complete_default_protocol"] = receipt["default_protocol_requested"] and not receipt["excluded_cases"]
        if receipt["excluded_cases"]:
            receipt["status"] = "VALIDATED_WITH_EXCLUSIONS" if args.validate_only else "PARTIAL_INCOMPATIBLE"
        elif receipt["inconclusive_cases"]:
            receipt["status"] = "INCONCLUSIVE"
        else:
            receipt["status"] = "VALIDATED_ALL" if args.validate_only else "STABLE"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        receipt["status"] = "REFUSED"
        receipt["error"] = str(exc)
        print(str(exc), file=sys.stderr)
    finally:
        if artifacts is not None:
            integrity = artifacts.verify()
            integrity_path = out / "artifact-integrity.json"
            integrity_path.write_text(json.dumps(integrity, indent=2, sort_keys=True) + "\n")
            receipt["artifact_integrity"] = {"status": integrity["status"], "tracked": integrity["tracked"],
                                             "failed": integrity["failed"], "receipt": identity(integrity_path)}
            if integrity["status"] != "PASS":
                receipt["status"] = "REFUSED"
                receipt["error"] = receipt.get("error", "") + " Evidence identity drifted; all speed verdicts refused."
        receipt["host"]["affinity_after"] = sorted(os.sched_getaffinity(0))
        independent = review_result(receipt)
        receipt["independent_review"] = independent
        receipt["dominance"] = independent["summary"]
        if independent["status"] == "REFUSED":
            receipt["status"] = "REFUSED"
            receipt["error"] = receipt.get("error", "") + " Independent review refused: " + "; ".join(independent["errors"][:12])
        receipt["elapsed_s"] = time.monotonic() - started if started is not None else None
        receipt["host"]["loadavg_after"] = list(os.getloadavg())
        receipt["host"]["affinity_after"] = sorted(os.sched_getaffinity(0))
        (out / "result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print("RESULT", out / "result.json", receipt["status"], flush=True)
        print("DOMINANCE", receipt["dominance"]["effective_goal"], receipt["dominance"]["goal_status"], flush=True)
    return {"STABLE": 0, "VALIDATED_ALL": 0, "REFUSED": 1,
            "PARTIAL_INCOMPATIBLE": 2, "VALIDATED_WITH_EXCLUSIONS": 2,
            "INCONCLUSIVE": 3}[receipt["status"]]


if __name__ == "__main__":
    sys.exit(main())
