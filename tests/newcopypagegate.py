#!/usr/bin/env python3
"""NASM parity/refusal gate for copy_page's minimal assembler prerequisites."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if not __debug__:
    sys.exit("remove -O/PYTHONOPTIMIZE: this gate requires assertions")

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", default=str(ROOT / "basm"))
    parser.add_argument("--nasm", default="nasm")
    args = parser.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="basm-copy-page-", dir="/tmp/opencode"))
    print(f"assembler evidence: {tmp}", flush=True)
    positive = {
        "static": """section .text
global public:function (public_end-public)
public: jmp local
public_end:
static local:function (local_end-local)
local: ret
local_end:
""",
        "static-late": """section .text.hot progbits alloc exec nowrite
f: nop
static f:function (.end-f)
ret
.end:
static zero:function 0
zero:
""",
        "pc32": """section .text
times 17 db 0x90
orig: jmp done
done: ret
section .altinstructions progbits alloc noexec nowrite align=1
db 0
dd orig - $
dd replacement - $
dd 112
db 2, 0
section .altinstr_replacement progbits alloc exec nowrite align=1
replacement:
""",
        "pc32-forward": """section .rodata
db 0, 0, 0
dd target-$
dd ext - $
section .text
times 19 db 0x90
target: ret
extern ext
""",
        "pc32-same": """section .text
f: nop
dd f-$
dd later - $
later: ret
""",
        "pc32-local": """section .text
scope: nop
.target: ret
section .rodata
dd .target-$
""",
        "prefetch": """bits 64
section .text
prefetcht0 [rsi+320]
prefetcht0 [r12+r9*4-128]
prefetcht0 [rbp]
prefetcht0 [rsp+127]
prefetcht0 [r15+128]
prefetcht0 [eax+ecx*2+16]
prefetcht0 [rel f]
prefetcht0 [rel ext]
prefetcht0 [fs:rax]
f: ret
extern ext
""",
    }
    failures = []
    for name, source in positive.items():
        src, native, oracle = (tmp / (name + suffix) for suffix in (".basm", ".b.o", ".n.o"))
        src.write_text(source)
        subprocess.run([args.nasm, "-f", "elf64", "-o", str(oracle), str(src)], check=True)
        result = subprocess.run([args.basm, "--target-profile", "public", "-f", "elf64",
                                 "-o", str(native), str(src)], capture_output=True, text=True)
        (tmp / (name + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            failures.append(f"{name}: rejected: {result.stderr.strip()}")
            continue
        diff = subprocess.run([str(ROOT / "elftool"), "diff", str(native), str(oracle)],
                              capture_output=True, text=True)
        if diff.returncode:
            failures.append(f"{name}: ELF parity: {diff.stdout}{diff.stderr}")
        if name == "static":
            symbols = subprocess.check_output(["readelf", "-Ws", str(native)], text=True)
            if not re.search(r"\b1 FUNC\s+LOCAL\s+DEFAULT\s+\d+ local$", symbols, re.M):
                failures.append("static: missing sized STB_LOCAL STT_FUNC")
        if name == "pc32":
            relocs = subprocess.check_output(["readelf", "-Wr", str(native)], text=True)
            if len(re.findall("R_X86_64_PC32", relocs)) != 2 or "R_X86_64_32 " in relocs:
                failures.append("pc32: wrong relocation kind/count")
        print(f"checked NASM parity: {name}", flush=True)

    invalid = []
    for declaration in ("static", "static f", "static f:object 1", "static f:function ,",
                        "static f:function 1,", "static f:function 1 2", "static f,other"):
        invalid.append("section .text\n" + declaration + "\nf: ret\n")
    for expr in ("2", "-1", "missing-f", "f", "9223372036854775807+1", "$-f",
                 "(end-f", "end-f)", "()", "end-f*1", "other-other+1"):
        invalid.append(f"section .text\nstatic f:function {expr}\nf: ret\nend:\nsection .data\nother:\n")
    invalid += ["section .text\nstatic f:function 1\nret\n",
                "section .data\nstatic f:function 1\nf: db 0\n",
                "extern f\nstatic f:function 0\n",
                "global f\nstatic f:function 1\nf: ret\n",
                "static f:function 1\nglobal f\nf: ret\n",
                "static f:function 1\nweak f\nf: ret\n",
                "static f:function 1\nextern f\nf: ret\n"]
    for data in ("db f-$", "dw f-$", "dq f-$", "dd f-$+1", "dd f-$$",
                 "dd f-($)", "dd f-$, 0", "dd f-$ 0", "dd missing-$"):
        invalid.append("section .text\nf: ret\nsection .rodata\n" + data + "\n")
    for operand in ("", "rax", "1", "[rax], rbx", "[rax],", ",[rax]", "qword [rax]",
                    "[rax+rsp*2]", "[rax+eax]", "[rax+rcx*3]", "[rax+2147483648]",
                    "[rax+rcx+rdx]", "[rax-rcx]", "[rax]junk", "[rel f junk]",
                    "[rax+missing]", "[rax+f]", "[rax*4+rcx*2]"):
        invalid.append("bits 64\nsection .text\nprefetcht0 " + operand + "\nf: ret\n")
    rejected = 0
    for index, source in enumerate(invalid):
        src = tmp / f"invalid-{index}.basm"
        src.write_text(source)
        for fmt in ("elf64", "bin"):
            out = tmp / "unchanged.o"
            out.write_bytes(b"unchanged output\n")
            result = subprocess.run([args.basm, "--target-profile", "public", "-f", fmt,
                                     "-o", str(out), str(src)], capture_output=True, text=True)
            (tmp / f"invalid-{index}-{fmt}.log").write_text(result.stdout + result.stderr)
            if (result.returncode <= 0 or out.read_bytes() != b"unchanged output\n" or
                    "AddressSanitizer" in result.stderr or "runtime error:" in result.stderr):
                failures.append(f"invalid-{index} ({fmt}): accepted or overwrote output")
            else:
                rejected += 1
    if failures:
        sys.exit("\n".join(failures))
    print(f"PASS copy-page prerequisites: {len(positive)} NASM parity, {rejected} refusals")


if __name__ == "__main__":
    main()
