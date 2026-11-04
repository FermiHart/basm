#!/usr/bin/env python3
"""W06/W07: exact preprocessing, immutable inputs and bounded amplification.

Assembles data only. No generated machine code is executed. Optional C API test
mutates and removes its own synthetic binary dependency between snapshot reads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--snapshot-api", action="store_true")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--quick", action="store_true", help="omit sparse-file resource cases")
    args = parser.parse_args()
    basm = args.basm.resolve()
    root = Path(__file__).resolve().parents[2]
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="basm-pp-"))
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema": "BASM-PREPROCESSOR-REGRESSION-v1", "binary": str(basm),
              "binary_sha256": hashlib.sha256(basm.read_bytes()).hexdigest(),
              "scope": "assembly-only; synthetic local inputs; no generated code execution",
              "sanitizer_environment": {key: os.environ.get(key) for key in ("ASAN_OPTIONS", "UBSAN_OPTIONS")},
              "tests": []}
    sentinel = b"previous artifact must remain intact\n"

    def case(name, source, expected=None, diagnostic=None, files=None, profile="public", prepare=None):
        folder = output / name
        folder.mkdir(exist_ok=True)
        for filename, content in (files or {}).items():
            (folder / filename).write_bytes(content)
        if prepare:
            prepare(folder)
        source_file = folder / "input.basm"
        source_file.write_bytes(source.encode() if isinstance(source, str) else source)
        result_file = folder / "output.bin"
        result_file.write_bytes(sentinel)
        argv = [str(basm), "-f", "bin", "-o", str(result_file)]
        if profile:
            argv += ["--target-profile", profile]
        argv.append(str(source_file))
        began = time.perf_counter()
        try:
            result = subprocess.run(argv, cwd=folder, capture_output=True, timeout=20)
            elapsed = time.perf_counter() - began
            stderr = result.stderr.decode(errors="replace")
            actual = result_file.read_bytes() if result_file.exists() else b""
            if expected is not None:
                ok = result.returncode == 0 and actual == expected
            else:
                ok = result.returncode > 0 and actual == sentinel
                if diagnostic:
                    ok = ok and diagnostic in stderr
            sanitizer_diagnostic = any(marker in stderr for marker in
                ("AddressSanitizer", "LeakSanitizer", "UndefinedBehaviorSanitizer", "runtime error:"))
            ok = ok and not sanitizer_diagnostic
            record = {"name": name, "pass": bool(ok), "argv": argv,
                      "returncode": result.returncode, "elapsed_seconds": elapsed,
                      "stderr": stderr, "expected_hex": expected.hex() if expected is not None else None,
                      "actual_hex": actual.hex() if len(actual) < 1024 else None,
                      "sanitizer_diagnostic": sanitizer_diagnostic,
                      "diagnostic_contains": diagnostic}
        except subprocess.TimeoutExpired:
            record = {"name": name, "pass": False, "timeout_seconds": 20, "argv": argv}
        report["tests"].append(record)
        print(("PASS " if record["pass"] else "FAIL ") + name)

    def data(source):
        return "section .data\n" + source

    def qword(*values):
        return b"".join(struct.pack("<Q", n) for n in values)

    long_value = "1" + " " * 254 + "+1"
    case("define_preserves_tail", data(f"%define NUM {long_value}\ndq NUM\n"), qword(2))
    case("macro_argument_preserves_tail", data(f"%macro M 1\ndq %1\n%endmacro\nM {long_value}\n"), qword(2))
    case("variadic_seventeen_arguments", data("%macro M 0-*\ndq %0\ndq %17\n%endmacro\nM " + ",".join(map(str, range(17))) + "\n"), qword(17, 16))
    case("variadic_sixtyfour_arguments", data("%macro M 0-*\ndq %0\ndq %64\n%endmacro\nM " + ",".join(map(str, range(64))) + "\n"), qword(64, 63))
    case("quoted_define_names", data("%define WORD 1\ndb \"WORD\", 'WORD', `WORD`\n"), b"WORDWORDWORD")
    case("quoted_semicolon_in_definition", data('%define STR "a;b" ; actual comment\ndb STR\n'), b"a;b")
    case("quoted_function_parameter", data('%define F(x) "x",x\ndb F(1)\n'), b"x\x01")
    case("function_quoted_comma", data('%define F(x,y) x,y\ndb F("a,b",4)\n'), b"a,b\x04")
    case("macro_quoted_comma", data('%macro M 2\ndb %1,%2\n%endmacro\nM "a,b",4\n'), b"a,b\x04")
    case("function_nested_expression", data("%define F(x,y) x+y\ndq F((1+2),3)\n"), qword(6))
    case("object_parenthesized_value", data("%define VALUE (1+2)\ndq VALUE\n"), qword(3))
    case("define_redefinition", data("%define N 1\n%define N 2\ndb N\n"), b"\x02")
    case("macro_rotate_full_count", data("%macro M 0-*\n%rotate -1\ndb %1\n%rotate 2\ndb %1\n%endmacro\nM 1,2,3\n"), b"\x03\x02")
    case("quote_preserves_local_labels_and_paste", data('db "@F @B @@ %+"\n'), b"@F @B @@ %+")
    case("structure_zero_and_expression", "struc S\n.zero resq 0\n.a resw 1+2\n.b resq 1\nendstruc\n" + data("dq S.zero,S.a,S.b,S_size\n"), qword(0, 0, 6, 14))
    case("rep_expression", data("%define N 2\n%rep N+1\ndb 7\n%endrep\n"), b"\x07" * 3)
    case("include_shared_definition", '%include "values.inc"\n' + data("db N\n"), b"\x03", files={"values.inc": b"%define N 3\n"})
    case("incbin_snapshot_bytes", data('incbin "blob.bin",1,3\n'), b"bcd", files={"blob.bin": b"abcdef"})
    case("function_missing_close", data("%define F(a,b) a+b\ndb F(1,2\n"), diagnostic="unterminated macro argument")
    case("function_missing_argument", data("%define F(a,b) a+b\ndb F(1)\n"), diagnostic="argument count mismatch")
    case("function_extra_argument", data("%define F(a,b) a+b\ndb F(1,2,3)\n"), diagnostic="argument count mismatch")
    case("function_definition_missing_comma", "%define F(a b) a+b\n" + data("db 1\n"), diagnostic="parameters require commas")
    case("function_duplicate_parameter", "%define F(a,a) a\n" + data("db 1\n"), diagnostic="duplicate %define parameter")
    case("function_missing_definition_close", "%define F(a,b\n" + data("db 1\n"), diagnostic="parameters require commas")
    case("macro_sixtyfive_arguments", data("%macro M 0-*\ndq %0\n%endmacro\nM " + ",".join("1" for _ in range(65)) + "\n"), diagnostic="too many macro arguments")
    case("macro_missing_argument_count", "%macro M\ndb 1\n%endmacro\n", diagnostic="needs an argument count")
    case("macro_huge_argument_count", "%macro M 18446744073709551615\ndb 1\n%endmacro\n", diagnostic="argument count exceeds budget")
    case("macro_invalid_argument_suffix", "%macro M 1-*junk\ndb 1\n%endmacro\n", diagnostic="invalid %macro argument specification")
    case("macro_argument_missing_delimiter", data("%macro M 1\ndb %1\n%endmacro\nM (1\n"), diagnostic="unterminated macro argument delimiter")
    case("macro_unprovided_parameter", data("%macro M 0\ndb %1\n%endmacro\nM\n"), diagnostic="parameter has no argument")
    case("macro_missing_terminator_at_eof", "%macro M 0\ndb 1", diagnostic="without %endmacro")
    case("rep_missing_terminator_at_eof", "%rep 2\ndb 1", diagnostic="without %endrep")
    case("structure_missing_terminator_at_eof", "struc S\n.a resb 1", diagnostic="without endstruc")
    case("macro_terminator_trailing_tokens", "%macro M 0\ndb 1\n%endmacro extra\n", diagnostic="trailing tokens after body terminator")
    case("define_expansion_over_line_capacity", "%define A " + "1" + " " * 700 + "+1\n" + data("dq A+A\n"), diagnostic="expansion exceeds line capacity")
    case("ifdef_trailing_tokens", "%define N 1\n%ifdef N junk\ndb 1\n%endif\n", diagnostic="takes one identifier")
    case("ifidn_missing_comma", "%ifidn one two\ndb 1\n%endif\n", diagnostic="two comma-separated tokens")
    case("ifidn_extra_argument", "%ifidn one,two,three\ndb 1\n%endif\n", diagnostic="too many macro arguments")
    case("duplicate_else", "%if 1\n%else\n%else\n%endif\n", diagnostic="duplicate %else")
    case("elif_after_else", "%if 1\n%else\n%elif 0\n%endif\n", diagnostic="%elif after %else")
    case("endif_trailing_tokens", "%if 1\n%endif extra\n", diagnostic="takes no arguments")
    case("undef_trailing_tokens", "%undef N junk\n", diagnostic="takes one identifier")
    case("include_trailing_tokens", '%include "a.inc" junk\n', diagnostic="takes one filename", files={"a.inc": b"db 1\n"})
    case("structure_field_product_overflow", "struc S\n.a resq 536870912\nendstruc\n" + data("dq S_size\n"), diagnostic="structure field count")
    case("structure_offset_sum_overflow", "struc S\n.a resb 2147483647\n.b resb 1\nendstruc\n", diagnostic="structure size exceeds supported range")
    case("structure_negative_count", "struc S\n.a resb -1\nendstruc\n", diagnostic="structure field count")
    case("rep_work_amplification", "%rep 1048576\n;" + "x" * 900 + "\n%endrep\n", diagnostic="repetition exceeds work budget")
    case("rep_count_overflow", "%rep 18446744073709551616\ndb 1\n%endrep\n", diagnostic="integer")
    case("rep_negative_count", "%rep -1\ndb 1\n%endrep\n", diagnostic="%rep count")
    case("root_nul_public", b"section .data\ndb 1\0\ndb 2\n", diagnostic="NUL")
    case("root_nul_compatibility", b"section .data\ndb 1\0\ndb 2\n", diagnostic="NUL", profile=None)
    case("include_nul_public", '%include "bad.inc"\n', diagnostic="NUL", files={"bad.inc": b"db 1\0\ndb 2\n"})
    case("alternate_include_nul", '%macro I 0\n%include "bad.inc"\n%endmacro\nI\n', diagnostic="NUL", files={"bad.inc": b"db 1\0\ndb 2\n"})
    case("macro_recursion_budget", "%macro M 0\nM\n%endmacro\nM\n", diagnostic="macro expansion too deep")
    case("compatibility_bits_trailing", "[BITS 64] extra\ndb 1\n", diagnostic="trailing BITS directive tokens", profile=None)

    if not args.quick:
        case("root_input_budget", b";" + b"x" * (16 * 1024 * 1024), diagnostic="byte budget")
        def sparse(folder, name, size):
            with (folder / name).open("wb") as stream:
                stream.truncate(size)
        case("include_input_budget", '%include "huge.inc"\n', diagnostic="byte budget",
              prepare=lambda folder: sparse(folder, "huge.inc", 16 * 1024 * 1024 + 1))
        # Keep the former112MiB single-binary boundary as an exact-slice positive.
        # Actual source bytes, not a blanket16MiB reservation, consume the
        # unchanged128MiB aggregate alongside each immutable binary snapshot.
        case("binary_input_budget_boundary", data('incbin "huge.bin",117440511,1\n'), expected=b'\0',
              prepare=lambda folder: sparse(folder, "huge.bin", 112 * 1024 * 1024))
        case("binary_input_remaining_budget", data('incbin "huge.bin",125829119,1\n'), expected=b'\0',
              prepare=lambda folder: sparse(folder, "huge.bin", 120 * 1024 * 1024))
        case("binary_input_budget", data('incbin "huge.bin",0,1\n'), diagnostic="byte budget",
              prepare=lambda folder: sparse(folder, "huge.bin", 128 * 1024 * 1024 + 1))
        def aggregate(folder):
            for index in range(3):
                sparse(folder, f"blob{index}.bin", 48 * 1024 * 1024)
        case("aggregate_dependency_budget", data("".join(f'incbin "blob{i}.bin",0,1\n' for i in range(3))),
             diagnostic="dependency byte budget", prepare=aggregate)

    if args.snapshot_api:
        folder = output / "snapshot_api"
        folder.mkdir(exist_ok=True)
        harness = folder / "snapshot_api.c"
        harness.write_text(r'''#define main basm_assembly_main
#include "basm.c"
#undef main
int main(int argc,char **argv) {
    if (argc!=2) return 2;
    const BasmDependency *first=basm_snapshot_open(argv[1],BASM_DEP_INCBIN);
    const unsigned char *frozen=first->data;
    if (first->len!=6 || memcmp(frozen,"abcdef",6)) return 3;
    FILE *stream=fopen(argv[1],"wb"); if (!stream) return 4;
    if (fwrite("mutated",1,7,stream)!=7 || fclose(stream)) return 5;
    const BasmDependency *second=basm_snapshot_open(argv[1],BASM_DEP_INCBIN);
    if (second->data!=frozen || second->len!=6 || memcmp(second->data,"abcdef",6)) return 6;
    if (remove(argv[1])) return 7;
    const BasmDependency *third=basm_snapshot_open(argv[1],BASM_DEP_INCBIN);
    if (third->data!=frozen || third->len!=6 || memcmp(third->data,"abcdef",6)) return 8;
    for (int i=0;i<100;i++) {
        char name[32]; snprintf(name,sizeof(name),"synthetic-%d",i);
        basm_snapshot_record(name,"xy",2,BASM_DEP_INCBIN);
    }
    if (memcmp(frozen,"abcdef",6) || basm_dependency_count()!=101) return 9;
    basm_dependencies_reset();
    return 0;
}
''')
        blob = folder / "input.bin"
        blob.write_bytes(b"abcdef")
        binary = folder / "snapshot_api"
        cc = shutil.which(args.cc)
        command = [cc or args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-misleading-indentation", "-Wno-stringop-truncation", "-Wno-format-truncation",
                   "-DSHA256NI_FORCE_SOFTWARE=1", "-ffunction-sections", "-fdata-sections",
                   "-Wl,--gc-sections", "-I" + str(root), str(harness), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
        result = subprocess.run([str(binary), str(blob)], capture_output=True, text=True, timeout=10) if compiled.returncode == 0 else compiled
        passed = compiled.returncode == 0 and result.returncode == 0
        report["tests"].append({"name": "snapshot_api_freezes_used_bytes_after_mutation_and_unlink",
                                "pass": passed, "compile_command": command,
                                "compile_returncode": compiled.returncode, "compile_stderr": compiled.stderr,
                                "returncode": result.returncode, "stderr": result.stderr,
                                "scope": "host C API test; not a sovereign toolchain claim"})
        print(("PASS " if passed else "FAIL ") + "snapshot_api_freezes_used_bytes_after_mutation_and_unlink")

    report["passed"] = sum(record["pass"] for record in report["tests"])
    report["failed"] = len(report["tests"]) - report["passed"]
    destination = output / "results.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Preprocessor: {report['passed']} passed; {report['failed']} failed. Evidence: {destination}")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
