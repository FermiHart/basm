#!/usr/bin/env python3
"""INV-703: bounded LOCAL NOTYPE extents, NASM ELF parity and fail-closed output.

Syntax: static NAME:notype SIZE (an explicit size, including zero, is required).
NASM 2.16.01 accepts this exact spelling and emits STB_LOCAL/STT_NOTYPE; this
is not a BearBasm extension. The supported SIZE subset is intentionally narrower
than NASM: decimal/0x integers, same-section labels, unary/binary +/- and up to
16 nested parentheses, at most 255 characters, nonnegative and within section.
Unannotated labels keep their default zero size. No GLOBAL NOTYPE declaration,
EQU size alias, visibility attribute, implicit extent or FUNC workaround is added.

This test never builds/promotes basm. --basm selects the executable under test;
all generated sources, objects and full command logs remain in --out.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if not __debug__:
    sys.exit("remove -O/PYTHONOPTIMIZE: this test requires assertions")

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", default=os.environ.get("BASM", str(ROOT / "basm")))
    parser.add_argument("--nasm", default=os.environ.get("NASM", "nasm"))
    parser.add_argument("--elftool", default=os.environ.get("ELFTOOL", str(ROOT / "elftool")))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    out = args.out or Path(tempfile.mkdtemp(prefix="basm-notype-"))
    out.mkdir(parents=True, exist_ok=True)
    assert not any(out.iterdir()), "--out must be empty; evidence is never overwritten"
    print(f"NOTYPE evidence: {out}", flush=True)

    def run(name, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        (out / (name + ".log")).write_text(
            json.dumps({"command": command, "returncode": result.returncode}) + "\n"
            + result.stdout + result.stderr)
        assert not re.search(r"AddressSanitizer|runtime error:", result.stdout + result.stderr), name
        return result

    version = run("nasm-version", [args.nasm, "-v"])
    assert version.returncode == 0, version.stderr
    print(version.stdout.strip(), flush=True)
    executable = Path(args.basm)
    if executable.is_file():
        (out / "basm.sha256").write_text(hashlib.sha256(executable.read_bytes()).hexdigest() + "\n")

    # Expected tuples are (value, size, ELF type, binding); readelf is independent
    # of the normalized ELF comparator, so neither can hide a FUNC substitution.
    positive = {
        "tina-probe": ("""bits 64
section .text
static probe:notype (probe_end-probe)
probe: ret
probe_end:
""", {"probe": (0, 1, "NOTYPE", "LOCAL"), "probe_end": (1, 0, "NOTYPE", "LOCAL")}),
        "handlers-layout": ("""section .text
times 16 db 0x90
static __get_user_handle_exception:notype (__get_user_handle_exception_end-__get_user_handle_exception)
__get_user_handle_exception:
jmp done
times 130 db 0x90
done: ret
__get_user_handle_exception_end:
align 16
static __put_user_handle_exception:notype (__put_user_handle_exception_end-__put_user_handle_exception)
__put_user_handle_exception:
xor ecx, ecx
ret
__put_user_handle_exception_end:
align 16
""", {"__get_user_handle_exception": (16, 136, "NOTYPE", "LOCAL"),
       "__put_user_handle_exception": (160, 3, "NOTYPE", "LOCAL")}),
        "late-scoped": ("""section .text.hot progbits alloc exec nowrite
scope: nop
static .handler:notype (.end-.handler)
.handler: nop
ret
.end:
other: ret
static other:notype (other_end-other)
other_end:
""", {"scope.handler": (1, 2, "NOTYPE", "LOCAL"), "other": (3, 1, "NOTYPE", "LOCAL")}),
        "zero-default-function": ("""section .text
static zero:notype 0
zero: nop
plain: ret
global public
public: ret
global unspecified:function
unspecified: ret
static localfunc:function (localfunc_end-localfunc)
localfunc: ret
localfunc_end:
static empty:notype (empty-empty)
empty:
""", {"zero": (0, 0, "NOTYPE", "LOCAL"), "plain": (1, 0, "NOTYPE", "LOCAL"),
       "public": (2, 0, "NOTYPE", "GLOBAL"), "unspecified": (3, 0, "FUNC", "GLOBAL"),
       "localfunc": (4, 1, "FUNC", "LOCAL"), "empty": (5, 0, "NOTYPE", "LOCAL")}),
        "duplicate": ("""section .text
static f:notype 1
static f:notype 1
f: ret
""", {"f": (0, 1, "NOTYPE", "LOCAL")}),
        "bounds": ("section .text\nstatic f:notype " + "(" * 16 + "1" + ")" * 16
                   + "\nstatic g:notype " + "+" * 254 + "1\nf: ret\ng: ret\n",
                   {"f": (0, 1, "NOTYPE", "LOCAL"), "g": (1, 1, "NOTYPE", "LOCAL")}),
        "arithmetic": ("""section .text
static f:notype ((f_end - (f + 0x1)) + 1 + (9223372036854775807-9223372036854775807))
f: nop
ret
f_end:
""", {"f": (0, 2, "NOTYPE", "LOCAL")}),
    }
    for name, section, storage in (
        ("data", ".data", "db 0, 0"), ("rodata", ".rodata", "db 0, 0"),
        ("bss", ".bss", "resb 2"),
        ("custom-data", ".payload progbits alloc noexec nowrite", "db 0, 0"),
        ("custom-bss", ".storage nobits alloc noexec write", "resb 2"),
    ):
        positive[name] = (f"section {section}\nstatic f:notype (f_end-f)\nf: {storage}\nf_end:\n",
                          {"f": (0, 2, "NOTYPE", "LOCAL")})

    failures = []
    for name, (source, expected) in positive.items():
        src = out / (name + ".basm")
        src.write_text(source)
        native, oracle = (out / (name + suffix) for suffix in (".b.o", ".n.o"))
        try:
            nasm = run(name + "-nasm", [args.nasm, "-f", "elf64", "-o", str(oracle), str(src)])
            assert nasm.returncode == 0, nasm.stderr
            for label, command, obj in (
                ("nasm-symbols", None, oracle),
                ("basm-symbols", [args.basm, "--target-profile", "public", "-f", "elf64",
                                  "-o", str(native), str(src)], native),
            ):
                if command:
                    result = run(name + "-basm", command)
                    assert result.returncode == 0, result.stderr
                result = run(name + "-" + label, ["readelf", "-Ws", str(obj)])
                assert result.returncode == 0, result.stderr
                for symbol, wanted in expected.items():
                    rows = re.findall(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+"
                                      r"DEFAULT\s+(\d+)\s+" + re.escape(symbol) + r"$",
                                      result.stdout, re.M)
                    assert len(rows) == 1, f"{label}: missing/duplicate {symbol}"
                    value, size, typ, bind, section = rows[0]
                    actual = (int(value, 16), int(size), typ, bind)
                    assert int(section) > 0 and actual == wanted, f"{label}: {symbol}: {actual} != {wanted}"
            diff = run(name + "-diff", [args.elftool, "diff", str(native), str(oracle)])
            assert diff.returncode == 0, diff.stdout + diff.stderr
        except AssertionError as error:
            failures.append(f"{name}: {error}")

    invalid = {}
    for index, expr in enumerate((
        "-1", "2", "f-f_end", "f", "missing-f", "(missing-missing)+1", "()", "0x", "0xg",
        "f_end-f 1", "f_end-f,1", "(f_end,f)", "(f_end-f", "f_end-f)", "f_end-", "1*1",
        "$-f", "$$", "9223372036854775808", "9223372036854775807+1",
        "-9223372036854775807-2", "18446744073709551617-18446744073709551616",
        "(" * 17 + "1" + ")" * 17, "+" * 255 + "1",
    )):
        invalid[f"size-{index:02}"] = f"section .text\nstatic f:notype {expr}\nf: ret\nf_end:\n"
    for index, declaration in enumerate((
        "static f:notype", "static f:notype, 1", "static f:notype 1,", "static f:notypex 1",
        "static f:notype hidden 1", "static f 1", "static :notype 1", "global f:notype",
    )):
        invalid[f"declaration-{index:02}"] = "section .text\n" + declaration + "\nf: ret\n"
    for binding in ("global f", "global f:function 1", "weak f", "extern f", "weak f:function"):
        for before in (False, True):
            lines = ["static f:notype 1", binding]
            if before:
                lines.reverse()
            invalid[f"binding-{len(invalid)}"] = "section .text\n" + "\n".join(lines) + "\nf: ret\n"
    for first, second in (("notype 1", "function 1"), ("function 1", "notype 1"),
                          ("notype 1", "notype 0")):
        invalid[f"conflict-{len(invalid)}"] = (
            f"section .text\nstatic f:{first}\nstatic f:{second}\nf: ret\n")
    for section in (".data", ".other progbits alloc exec", ".bss"):
        for expr in ("other-f", "other-other+1"):
            invalid[f"cross-section-{len(invalid)}"] = (
                f"section .text\nstatic f:notype {expr}\nf: ret\nsection {section}\nother:\n")
    invalid.update({
        "undefined": "section .text\nstatic f:notype 0\nret\n",
        "external-term": "section .text\nstatic f:notype (ext-ext)+1\nf: ret\nextern ext\n",
        "equ-alias": "section .text\nstatic f:notype extent\nf: ret\nextent equ 1\n",
        "equ-symbol": "section .text\nstatic f:notype 0\nf equ 0\nret\n",
        "beyond-end": "section .text\nnop\nstatic f:notype 2\nf: ret\n",
        "function-data": "section .data\nstatic f:function 1\nf: db 0\n",
        "function-nobits": "section .other nobits alloc exec\nstatic f:function 1\nf: resb 1\n",
        "noncode-beyond-end": "section .data\nstatic f:notype 2\nf: db 0\n",
    })
    rejected = 0
    for name, source in invalid.items():
        src = out / (name + ".basm")
        src.write_text(source)
        for fmt in ("elf64", "bin"):
            for existing in (False, True):
                tag = f"{name}-{fmt}-{'existing' if existing else 'absent'}"
                target, proof = out / (tag + ".o"), out / (tag + ".basmproof")
                if existing:
                    target.write_bytes(b"unchanged object\n")
                    proof.write_bytes(b"unchanged proof\n")
                result = run(tag, [args.basm, "--target-profile", "public", "-f", fmt,
                                   "--emit-attestation", str(proof), "-o", str(target), str(src)])
                preserved = ((target.read_bytes() == b"unchanged object\n" and
                              proof.read_bytes() == b"unchanged proof\n") if existing else
                             (not target.exists() and not proof.exists()))
                if (result.returncode <= 0 or not preserved or list(out.glob(target.name + ".tmp.*"))
                        or not re.search(r"size|static|global|attribute|binding", result.stderr)):
                    failures.append(f"{tag}: accepted, wrong diagnostic, or partial publication")
                else:
                    rejected += 1
    for failure in failures:
        print("FAIL " + failure, flush=True)
    summary = f"NOTYPE extent: {len(positive)} NASM parity cases, {rejected}/{len(invalid)*4} refusal checks, {len(failures)} failures"
    (out / "summary.txt").write_text(summary + "\n" + "\n".join(failures))
    print(summary, flush=True)
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
