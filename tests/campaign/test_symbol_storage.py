#!/usr/bin/env python3
"""N13 symbol lifetime, growth, exact output, NASM parity and native-capacity gates.

All inputs and command outputs are retained. The native helper exercises
assembler storage only; no assembled code is linked or executed. Use an exact
build receipt so its direct-state checks compile the same product snapshot.
No execution time or memory usage from this suite is a benchmark measurement.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from nasm_elf import compare_elf

if not __debug__:
    sys.exit("remove -O/PYTHONOPTIMIZE: symbol gates require assertions")

ROOT = Path(__file__).resolve().parents[2]
STACK = "section .note.GNU-stack noalloc noexec nowrite progbits align=1\n"


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--basm", type=Path, required=True)
    ap.add_argument("--receipt", type=Path, required=True)
    ap.add_argument("--nasm", type=Path, required=True)
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--cc", default="/usr/bin/x86_64-linux-gnu-gcc-13")
    ap.add_argument("--sanitize", action="store_true", help="also instrument the native storage helper")
    args = ap.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        ap.error("--out must be empty; evidence is never overwritten")
    basm, nasm, receipt_path = args.basm.resolve(), args.nasm.resolve(), args.receipt.resolve()
    baseline = args.baseline.resolve() if args.baseline else None
    receipt = json.loads(receipt_path.read_text())
    expected = receipt["artifacts"]["basm-host"]
    if expected["sha256"] != identity(basm)["sha256"]:
        ap.error("--basm does not match --receipt")
    source_root = Path(receipt["source_snapshot"])
    for relative, expected_source in receipt["source_inputs"].items():
        if identity(source_root / relative)["sha256"] != expected_source["sha256"]:
            ap.error("source snapshot drift: " + relative)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0", "MALLOC_PERTURB_": "165"}
    if args.sanitize:
        # Arena/pool allocations intentionally live for the assembler process;
        # this gate tests bounds/lifetimes, not leak-free teardown.
        env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1"
    report = {"schema": "BASM-N13-SYMBOL-STORAGE-v1", "tools": {"basm": identity(basm), "nasm": identity(nasm)},
              "receipt": identity(receipt_path), "suite": identity(Path(__file__).resolve()), "environment": env, "cases": [], "commands": [], "errors": []}
    if baseline:
        report["tools"]["baseline"] = identity(baseline)

    def command(label, argv, expected_status=0):
        argv = [str(x) for x in argv]
        run = subprocess.run(argv, env=env, capture_output=True, timeout=90)
        (out / (label + ".stdout")).write_bytes(run.stdout)
        (out / (label + ".stderr")).write_bytes(run.stderr)
        report["commands"].append({"label": label, "argv": argv, "returncode": run.returncode,
                                   "expected_returncode": expected_status,
                                   "stdout": label + ".stdout", "stderr": label + ".stderr"})
        assert run.returncode == expected_status, (label, run.returncode, run.stderr.decode(errors="replace"))
        assert b"AddressSanitizer" not in run.stderr and b"runtime error:" not in run.stderr, label
        return run

    def accept(label, text, parity=True):
        source = out / (label + ".asm")
        source.write_text(text + STACK)
        obj = out / (label + ".basm.o")
        command(label + "-basm", [basm, "-f", "elf64", "-o", obj, source])
        record = {"case": label, "source": identity(source), "object": identity(obj)}
        if parity:
            oracle = out / (label + ".nasm.o")
            command(label + "-nasm", [nasm, "-f", "elf64", "-o", oracle, source])
            comparison = compare_elf(obj, oracle)
            (out / (label + ".parity.json")).write_text(json.dumps(comparison, indent=2) + "\n")
            assert comparison["equal"], (label, comparison["differences"])
            record["nasm_parity"] = True
        if baseline:
            previous = out / (label + ".before.o")
            command(label + "-baseline", [baseline, "-f", "elf64", "-o", previous, source])
            assert obj.read_bytes() == previous.read_bytes(), (label, "baseline bytes changed")
            record["baseline_exact_bytes"] = True
        report["cases"].append(record)

    def refuse(label, text):
        source = out / (label + ".asm")
        source.write_text(text)
        for existing in (False, True):
            tag = label + ("-existing" if existing else "-absent")
            obj, proof = out / (tag + ".o"), out / (tag + ".proof")
            if existing:
                obj.write_bytes(b"PRIOR OBJECT\n"); proof.write_bytes(b"PRIOR PROOF\n")
            result = command(tag, [basm, "--target-profile", "public", "-f", "elf64",
                                  "--emit-attestation", proof, "-o", obj, source], 1)
            assert result.stderr, tag
            if existing:
                assert obj.read_bytes() == b"PRIOR OBJECT\n" and proof.read_bytes() == b"PRIOR PROOF\n", tag
            else:
                assert not obj.exists() and not proof.exists(), tag
            assert not list(out.glob(obj.name + ".tmp.*")), tag
        report["cases"].append({"case": label, "refused_and_prior_outputs_preserved": True})

    try:
        for count in (63, 64, 65, 127, 128, 129, 2049, 10000, 65537):
            accept(f"labels-{count}", "bits 64\nsection .text\n" +
                   "".join(f"label_{i:06}: nop\n" for i in range(count)))
        for count in (63, 64, 65, 127, 128, 129):
            fill = "".join(f"seed_{i:06}: db 0\n" for i in range(count - 1))
            accept(f"inline-wrt-grow-{count}", "bits 64\nsection .data\n" + fill +
                   "slot: dq external_target wrt ..sym\nextern external_target\n")
            accept(f"inline-relative-grow-{count}", "bits 64\nsection .data\n" + fill +
                   "slot: dd later - $\nlater: db 0\n")
            accept(f"scope-size-grow-{count}", "bits 64\nsection .text\n" + fill +
                   "scope: nop\nstatic .method:function (.end-.method)\n.method: nop\nret\n.end:\n")
        accept("equal-length-fnv-collision", "bits 64\nsection .text\n"
               "entry: jmp declinate\njmp macallums\ndeclinate: nop\nmacallums: ret\n")
        long_name = "n" * 255
        accept("name-255", f"bits 64\nglobal {long_name}\nsection .text\njmp {long_name}\n{long_name}: ret\n")
        accept("qualified-name-255", "bits 64\nsection .text\n" + "q" * 253 + ": nop\n.x: ret\n")
        interleaved = "bits 64\nsection .text\n" + "".join(
            f"constant_{i} equ {i}\nlocal_{i}: nop\n" for i in range(128))
        accept("constant-label-order", interleaved)
        reverse = "bits 64\n" + "".join(f"global item_{i}\n" for i in reversed(range(10000)))
        reverse += "section .text\n" + "".join(f"item_{i}: nop\n" for i in range(10000))
        accept("globals-reversed-10000", reverse)
        accept("external-and-section-index", "bits 64\nextern ext\nglobal entry:function\n"
               "section .text\nentry: call ext\nlea rax,[rel datum]\nret\n"
               "section .data\ndatum: dq entry\ndq ext\n")
        refuse("name-256", "bits 64\nsection .text\n" + "n" * 256 + ": ret\n")
        refuse("global-name-256", "bits 64\nglobal " + "n" * 256 + "\nsection .text\nret\n")
        refuse("qualified-name-256", "bits 64\nsection .text\n" + "q" * 254 + ": nop\n.x: ret\n")
        refuse("inconsistent-redefinition", "bits 64\nsection .text\nlabel: nop\nlabel: ret\n")
        refuse("forward-wrt-not-global", "bits 64\nsection .data\nslot: dq target wrt ..sym\ntarget: dq 0\n")
        refuse("size-missing-term-after-growth", "bits 64\nsection .text\n" +
               "".join(f"seed_{i}: nop\n" for i in range(129)) +
               "static method:function (end-missing)\nmethod: ret\nend:\n")
        helper_source = ROOT / "tests/campaign/symbol_storage_probe.c"
        helper = out / "symbol-storage-probe"
        compile_argv = [args.cc, "-std=gnu11", "-O1", "-g", "-ffunction-sections", "-fdata-sections",
                        "-Wl,--gc-sections", "-DSHA256NI_FORCE_SOFTWARE=1",
                        '-DBASM_SOURCE="' + str(source_root / "basm.c") + '"', "-I" + str(source_root),
                        helper_source, "-o", helper]
        if args.sanitize:
            compile_argv[1:1] = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
        command("compile-native-probe", compile_argv)
        report["probe_source"] = identity(helper_source)
        report["probe_binary"] = identity(helper)
        for mode, expected_status in (("ordinary", 0), ("hard-cap", 0), ("overflow", 1), ("long-refusal", 1)):
            result = command("probe-" + mode, [helper, mode], expected_status)
            record = {"case": "native-" + mode, "expected_refusal": bool(expected_status)}
            if result.stdout:
                record["state"] = json.loads(result.stdout)
            report["cases"].append(record)
        report["status"] = "PASS"
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError) as exc:
        report["errors"].append(str(exc)); report["status"] = "FAIL"
    report["case_count"] = len(report["cases"])
    report["command_count"] = len(report["commands"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "case_count", "command_count", "errors")}))
    return report["status"] != "PASS"


if __name__ == "__main__":
    sys.exit(main())
