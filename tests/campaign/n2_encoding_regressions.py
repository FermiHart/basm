#!/usr/bin/env python3
"""N05–N08 differential and rejection regressions; never executes emitted code.

The independent NASM binary is supplied explicitly. Each command, source,
stdout/stderr and output digest is retained in the caller-owned evidence dir.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def identity(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--nasm", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--through", type=int, choices=(5, 6, 7, 8), default=8)
    parser.add_argument("--asan-no-leaks", action="store_true",
                        help="keep ASan/UBSan active but disable unsupported LeakSanitizer under ptrace")
    args = parser.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    tools = {name: getattr(args, name).resolve() for name in ("basm", "public", "nasm")}
    records, checks, failures = [], [], []
    tool_start = {name: identity(path) for name, path in tools.items()}
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"}
    if args.asan_no_leaks:
        env.update(ASAN_OPTIONS="detect_leaks=0:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    (root / "runner-used.py").write_bytes(Path(__file__).read_bytes())

    def run(label, tool, source, extra=()):
        out = root / (label + "." + tool + ".bin")
        argv = [str(tools[tool]), *extra, "-f", "bin", "-o", str(out), str(source)]
        proc = subprocess.run(argv, env=env, capture_output=True, timeout=20)
        (root / (label + "." + tool + ".stdout")).write_bytes(proc.stdout)
        (root / (label + "." + tool + ".stderr")).write_bytes(proc.stderr)
        record = {"label": label, "tool": tool, "argv": argv,
                  "returncode": proc.returncode, "source": identity(source),
                  "output": identity(out) if out.exists() else None}
        records.append(record)
        if any(marker in proc.stderr for marker in (b"AddressSanitizer", b"LeakSanitizer", b"runtime error:")):
            check(False, label + " " + tool + " sanitizer diagnostic", proc.stderr.decode(errors="replace"))
        return proc, out

    def check(ok, label, detail=None):
        checks.append({"label": label, "passed": bool(ok), "detail": detail})
        if not ok:
            failures.append(label)

    def compare(label, text, bits=64, terminated=True):
        source = root / (label + ".asm")
        source.write_text("bits %d\nsection .text\n" % bits + text + ("\n" if terminated else ""))
        oracle, expected = run(label, "nasm", source)
        check(oracle.returncode == 0, label + " NASM accepts", oracle.stderr.decode(errors="replace"))
        for tool in (("basm", "public") if bits == 64 else ("basm",)):
            proc, output = run(label, tool, source)
            check(proc.returncode == 0, label + " " + tool + " accepts", proc.stderr.decode(errors="replace"))
            check(proc.returncode == oracle.returncode == 0 and output.read_bytes() == expected.read_bytes(),
                  label + " " + tool + " exact bytes")

    def reject(label, text, oracle=True, bits=64):
        source = root / (label + ".asm")
        source.write_text("bits %d\nsection .text\n" % bits + text + "\n")
        for tool in (("nasm", "basm", "public") if oracle else ("basm", "public")):
            if bits != 64 and tool == "basm":
                continue  # Non-long-mode sources are admitted only by the compatibility product.
            proc, output = run(label, tool, source)
            check(proc.returncode != 0 and not output.exists(), label + " " + tool + " rejects without output",
                  proc.stderr.decode(errors="replace"))

    strings = "insb insw insd outsb outsw outsd movsb movsd movsq stosb stosw stosd stosq lodsb lodsd scasb".split()
    for bits in (16, 32, 64):
        lines = [prefix + name for prefix in ("", "rep ", "repe ", "repz ", "repne ", "repnz ", "rep rep rep ")
                 for name in strings if bits == 64 or not name.endswith("q")]
        compare("n05-string-mode-%d" % bits, "\n".join(lines), bits)
    compare("n05-invpcid", "\n".join("invpcid " + operands for operands in (
        "rdi,[rsp]", "r8,[r9]", "r15,[r13+r14*8+128]", "rax,[fs:rbx+16]", "r9,[eax+ecx*4+32]")))
    for i, bad in enumerate(("rep", "repne", "rep , insw", "rep insw ax", "insw ax", "outsw rdx",
                             "repne rep insw", "repz repnz stosb", "invpcid eax,[rax]",
                             "invpcid rax", "invpcid rax,[rbx],1", "invpcid rax [rbx]")):
        # A bare prefix is accepted as a byte by NASM; BearBasm deliberately
        # requires an instruction and must reject it safely, without a crash.
        reject("n05-negative-%02d" % i, bad, oracle=i >= 2)

    compare("n05-movsd-sse", "\n".join(("movsd [r13+128],xmm15", "movsd xmm15,[r13+128]",
        "movsd xmm15,xmm8", "movsd", "rep movsd")))
    compare("n05-movx-302", "\n".join(("movzx rdi,eax", "movzx r8,r9d", "movzx rdi,dword [rbx]",
        "movsx di,ax", "movsx edi,eax", "movsx ax,bx", "movzx ax,bx", "movsx rax,eax",
        "movsx eax,ax", "movsx ax,al", "movsx r15,dword [r13+8]")))

    if args.through >= 6:
        register_groups = (
            "rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15".split(),
            "eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d".split(),
            "ax cx dx bx sp bp si di r8w r9w r10w r11w r12w r13w r14w r15w".split(),
            "al cl dl bl ah ch dh bh spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b".split())
        high = {"ah", "ch", "dh", "bh"}
        rex_byte = {"spl", "bpl", "sil", "dil"} | set(register_groups[3][12:])
        for group_no, regs in enumerate(register_groups):
            lines = [op + " " + a + "," + b for op in ("mov", "add", "or", "and", "sub", "xor", "cmp")
                     for a in regs for b in regs
                     if not ((a in high and b in rex_byte) or (b in high and a in rex_byte))]
            compare("n06-all-gpr-width-%d" % group_no, "\n".join(lines))
        compare("n06-register-like-symbols", "\n".join(("r8_long equ 17", "rax_identifier equ 23",
            "r15b_suffix equ 29", "add rax,r8_long", "xor r8,rax_identifier", "cmp r9,r15b_suffix")))
        # These misses exercise exact length/byte verification, including
        # register-like nonnames that hash to populated slots.
        for i, bad in enumerate(("r", "r0", "r7", "r16", "r08", "r10x", "r15bb", "r8wq",
                                 "rax_suffix", "r15d_suffix", "eaxx", "silx", "r1b", "r99")):
            # NASM 3.02 also supports APX r16; it is intentionally outside
            # this product's unchanged 68-name vocabulary, not a near-match.
            reject("n06-name-miss-%02d" % i, "mov " + bad + ",rax", oracle=bad != "r16")

    if args.through >= 7:
        compare("n07-dispatch-transitions", "\n".join(("rep insw", "movsd xmm15,xmm8", "movsd",
            "pshufd xmm15,xmm8,17", "ldmxcsr [r9]", "stmxcsr [r10]", "vmovdqa ymm1,[r8]",
            "vmovdqu [r9],ymm4", "o64 push rax", "nop", "o64 sysret", "nop", "o64 iret", "nop",
            "adc rax,rbx", "sbb r8,r9", "cmp rax,rbx", "rep rep stosw", "ret")))
        for i, bad in enumerate(("nopx", "nopabcdefghijklm", "movssz xmm0,xmm1", "pshufdextra xmm0,xmm1,0")):
            reject("n07-mnemonic-miss-%02d" % i, bad + " rax" if i < 2 else bad)
        for i, bad in enumerate(("mov rax,ebx", "mov ah,r8b", "mov spl,ah", "add eax,rbx",
                                 "xor bh,r9b", "cmp al,ax", "nop rax", "cpuid rbx", "ret 8",
                                 "mov rax,rbx,rcx", "add rax,rbx,rcx")):
            label = "n07-public-constraints-%02d" % i
            source = root / (label + ".asm")
            source.write_text("bits 64\nsection .text\n" + bad + "\n")
            for tool in ("basm", "public"):
                proc, out = run(label, tool, source, ("--target-profile", "public") if tool == "basm" else ())
                check(proc.returncode != 0 and not out.exists(), label + " " + tool + " rejects without output")

    if args.through >= 8:
        compare("n08-final-nul", "mov rax,rbx\nadd r8,-128\nnop\nret", terminated=False)
        compare("n08-crlf", "mov rax,rbx\r\nadd r8,127\r\nnop\r\nret\r")
        compare("n08-comment-boundaries", "mov rax,rbx; brackets [, are comments\n"
            "\tadd r8,-128 \t; ' also a comment\nret\t; end")
        prefix = "mov rax,rbx ;"
        compare("n08-line-limit-valid", prefix + "a" * (1023 - len(prefix)))
        reject("n08-line-limit-refused", prefix + "a" * (1024 - len(prefix)), oracle=False)
        compare("n08-expanded-macros", "%define OP add\n%define DST r8\nOP DST,5\n"
            "%if 0\nmov invalid,invalid\n%endif\nnop\nret")
        for i, bad in enumerate(("o64", "rep o64")):
            reject("n08-missing-prefixed-insn-%d" % i, bad, oracle=False)
        for bits in (16, 32):
            reject("n08-public-bits-%d" % bits, "nop\nret", oracle=False, bits=bits)
        for i, bad in enumerate(("nop,", "ret,", "entry: nop,", "o64 , nop")):
            label = "n08-fixed-separators-%d" % i
            source = root / (label + ".asm")
            source.write_text("bits 64\nsection .text\n" + bad + "\n")
            for tool in ("basm", "public"):
                proc, out = run(label, tool, source, ("--target-profile", "public") if tool == "basm" else ())
                check(proc.returncode != 0 and not out.exists(), label + " " + tool + " rejects without output")

    # Later waves extend this same independent entry point with their cases.
    report = {"schema": "BASM-N2-ENCODING-REGRESSIONS-v1", "through": args.through,
              "runner": identity(Path(__file__)), "argv": sys.argv, "environment": env,
              "tools": tool_start, "tool_drift": [name for name, path in tools.items()
                  if identity(path) != tool_start[name]], "commands": records,
              "checks": checks, "passed": sum(c["passed"] for c in checks),
              "failed": failures, "executes_emitted_code": False}
    report["status"] = "PASS" if not failures and not report["tool_drift"] else "FAIL"
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "through", "passed", "failed", "tool_drift")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
