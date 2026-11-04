#!/usr/bin/env python3
"""Exact output checks for fills, incbin interleaving and writer boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def section(data, wanted):
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    at = struct.unpack_from("<Q", data, 40)[0]
    width, count, strings = struct.unpack_from("<HHH", data, 58)
    assert width == 64 and at + width*count <= len(data)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, at + i*width) for i in range(count)]
    name_row = rows[strings]
    names = data[name_row[4]:name_row[4]+name_row[5]]
    for row in rows:
        name = names[row[0]:].split(b"\0", 1)[0].decode()
        if name == wanted:
            assert row[4]+row[5] <= len(data)
            return data[row[4]:row[4]+row[5]]
    raise AssertionError("missing section " + wanted)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--basm", required=True, type=Path)
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--asan-no-leaks", action="store_true",
                    help="keep ASan/UBSan checks, disable unavailable LeakSanitizer explicitly")
    args = ap.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    lanes = {"candidate": args.basm.resolve()}
    if args.baseline:
        lanes["baseline"] = args.baseline.resolve()
    report = {"schema": "BASM-N20-BUFFER-CHECK-v1", "tools": {key: identity(value) for key, value in lanes.items()},
              "scope": "known output bytes and independent section parsing; no generated code execution", "cases": []}
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"}
    if args.asan_no_leaks:
        env.update(ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1")
    report["environment"] = env
    blob = bytes(range(256))*32
    (output / "blob.bin").write_bytes(blob)

    def run(name, source, expected, selected, succeeds=True):
        directory = output / name
        directory.mkdir()
        path = directory / "input.asm"
        path.write_text(source)
        case = {"name": name, "source": identity(path), "commands": [], "pass": True}
        for fmt in ("bin", "elf64"):
            previous = None
            for lane, tool in lanes.items():
                if not succeeds and lane == "baseline":
                    continue
                target = directory / (lane + "." + fmt)
                target.write_bytes(b"prior artifact")
                argv = [str(tool), "-f", fmt, "-o", str(target), str(path)]
                proc = subprocess.run(argv, capture_output=True, env=env, timeout=20)
                (directory / (lane + "." + fmt + ".stdout")).write_bytes(proc.stdout)
                (directory / (lane + "." + fmt + ".stderr")).write_bytes(proc.stderr)
                data = target.read_bytes()
                passed = (proc.returncode == 0) == succeeds and proc.returncode >= 0
                sanitizer_diagnostic = any(marker in proc.stderr for marker in
                    (b"AddressSanitizer", b"LeakSanitizer", b"UndefinedBehaviorSanitizer", b"runtime error:"))
                passed &= not sanitizer_diagnostic
                if succeeds and proc.returncode == 0:
                    passed &= (data if fmt == "bin" else section(data, selected)) == expected
                    if previous is not None:
                        passed &= data == previous
                    previous = data
                if not succeeds:
                    passed &= data == b"prior artifact"
                passed &= not list(directory.glob(target.name + ".tmp.*"))
                case["commands"].append({"argv": argv, "returncode": proc.returncode, "output": identity(target),
                                         "sanitizer_diagnostic": sanitizer_diagnostic, "pass": bool(passed)})
                case["pass"] &= bool(passed)
        report["cases"].append(case)

    for selected in (".text", ".data", ".rodata", ".payload"):
        declaration = selected + (" progbits alloc noexec nowrite align=1" if selected == ".payload" else "")
        for length in (0, 1, 4095, 4096, 4097, 65535, 65536, 65537, 131071):
            prefix = b"\xa3" + bytes(length)
            padding = (-len(prefix)) % 256
            expected = prefix + b"\x90"*padding + b"\x5a"
            source = "bits 64\nsection " + declaration + "\ndb 0xa3\nresb " + str(length) + "\nalign 256\ndb 0x5a\n"
            run(selected[1:] + "-" + str(length), source, expected, selected)
        expected = b"\xa3" + blob[7:4108] + bytes(4097) + blob[13:4132] + b"\x5a"
        source = ('bits 64\nsection ' + declaration + '\ndb 0xa3\nincbin "' + str(output / "blob.bin") + '",7,4101\n'
                  'resb 4097\nincbin "' + str(output / "blob.bin") + '",13,4119\ndb 0x5a\n')
        run(selected[1:] + "-incbin", source, expected, selected)
        maximum = 4194304 if selected == ".text" else 33554432
        source = "bits 64\nsection " + declaration + "\nresb " + str(maximum+1) + "\n"
        run(selected[1:] + "-overflow", source, b"", selected, succeeds=False)
    report["passed"] = sum(case["pass"] for case in report["cases"])
    report["failed"] = len(report["cases"]) - report["passed"]
    report["tool_drift"] = [name for name, path in lanes.items() if identity(path) != report["tools"][name]]
    report["status"] = "PASS" if not report["failed"] and not report["tool_drift"] else "FAIL"
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "passed", "failed", "tool_drift")}))
    return report["status"] != "PASS"


if __name__ == "__main__":
    raise SystemExit(main())
