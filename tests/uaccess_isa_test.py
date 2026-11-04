#!/usr/bin/env python3
"""INV-703: bounded uaccess ISA forms and ELF branch relocations against NASM."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if not __debug__:
    sys.exit("assertions required")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--basm", default=str(ROOT / "basm"))
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    assert not any(out.iterdir()), "use a new evidence directory"
    positive = {
        "sbb": "sbb rdx,rdx\nsbb r8,r15\nsbb eax,r9d\nsbb r10w,dx\nsbb al,cl\nsbb ah,bh\nsbb spl,r8b\n",
        "movnti": "movnti [rdi],r8\nmovnti [rdi+24],r11\nmovnti [rbp],eax\nmovnti [rsp-128],rax\nmovnti [r12+r9*4+128],r15d\nmovnti [eax+ecx*2],edx\nmovnti [fs:rax],edx\nmovnti dword [rdi],eax\nmovnti qword [rdi],rdx\nsfence\n",
        "movnti-rel": "movnti [rel other+8],rax\nmovnti [rel ext],eax\nsection .data\nother: dq 0,0\nextern ext\n",
        "cross-forward": "global entry\nentry: jb near other\njne other\nsection .text.cold progbits alloc exec nowrite\nnop\nother: ret\n",
        "cross-backward": "global entry\nentry: nop\n.tail: ret\nsection .altinstr_replacement progbits alloc exec nowrite\njb near entry.tail\nje entry\n",
        "external": "jne near ext\nextern ext\n",
        "same": "start: jb short end\njne near start\ntimes 120 db 0x90\nend: ret\n",
        "cross-jmp": "jmp other\nsection .text.cold progbits alloc exec nowrite\nother: ret\n",
        "sized-load": "mov edx,dword [rax]\nmov rdx,qword [rax]\n",
        "dotted-extents": "entry: nop\n.begin: times 20 db 0x90\n.end:\nsection .rodata\ndb entry.end-entry.begin\ndb 0\n",
        "pp-expression": "%define ALIGNMENT 8\n%if ALIGNMENT >> 4\ndb 0x11\n%endif\n%if ALIGNMENT > 8\ndb 0x22\n%endif\n%if 1+2 == 3\ndb 0x33\n%endif\nret\n",
        "pp-macro": "%define ALIGNMENT 8\n%define PREFIX (ALIGNMENT >> 4)\n%if PREFIX\ndb 0x11\n%endif\n%macro ENTRY 0\n%if ALIGNMENT >> 4\ndb 0x22\n%endif\n%if ALIGNMENT > 8\ndb 0x33\n%endif\nret\n%endmacro\nENTRY\n",
        "pc32-addend": "entry: mov rdx,0x0123456789abcdef\nend:\nsection runtime_ptr_USER_PTR_MAX alloc noexec nowrite progbits align=1\ndd entry+2-$\ndd end-8-$\ndd ext+2-$\nextern ext\n",
    }
    bad = [f"{op}\n" for op in (
        "sbb", "sbb rax", "sbb rax,ebx", "sbb rax,1", "sbb rax,[rdi]", "sbb [rdi],rax",
        "sbb ah,r8b", "sbb spl,ah", "sbb xmm0,xmm1", "sbb rax,rbx,rcx", "sbb rax,rbx,",
        "movnti", "movnti [rax]", "movnti rax,rbx", "movnti [rax],ax", "movnti [rax],al",
        "movnti [rax],xmm0", "movnti [rax],1", "movnti [rax],[rbx]", "movnti word [rax],eax",
        "movnti dword [rax],rax", "movnti qword [rax],eax", "movnti [rax],eax,", "sfence rax",
        "movnti [rax]junk,eax", "movnti [rax-rcx],eax", "movnti [rax+rcx+rdx],eax",
        "movnti [rax+rsp*2],eax", "movnti [rax+ecx],eax", "movnti [rax+rcx*3],eax",
        "movnti [rax+2147483648],eax", "movnti [rax+missing],eax", "movnti [rel ext junk],eax",
        "jb near missing", "jb short ext\nextern ext", "jb short other\nsection .data\nother: db 0",
        "jmp short other\nsection .data\nother: db 0",
        "mov edx,qword [rax]", "mov rdx,dword [rax]", "mov edx,dword xmm0", "db 1junk",
        "dd ext+2147483648-$\nextern ext", "dd ext+2+2-$\nextern ext", "dd ext+2-$+1\nextern ext",
    )]
    errors = []
    report = {"positive": {}, "refusals": 0}
    for name, text in positive.items():
        source = out / f"{name}.basm"
        source.write_text("bits 64\nsection .text\n" + text)
        native, oracle = out / f"{name}.o", out / f"{name}.nasm.o"
        subprocess.run(["nasm", "-f", "elf64", "-o", str(oracle), str(source)], check=True)
        run = subprocess.run([args.basm, "--target-profile", "public", "-f", "elf64", "-o", str(native), str(source)], capture_output=True, text=True)
        (out / f"{name}.log").write_text(run.stdout + run.stderr)
        if not run.returncode:
            run = subprocess.run([str(ROOT / "elftool"), "diff", str(native), str(oracle)], capture_output=True, text=True)
            (out / f"{name}.diff.log").write_text(run.stdout + run.stderr)
        report["positive"][name] = run.returncode == 0
        if run.returncode:
            errors.append(f"{name}: {run.stdout}{run.stderr}")
    for index, text in enumerate(bad):
        source = out / f"invalid-{index}.basm"
        source.write_text("bits 64\nsection .text\n" + text)
        for fmt in ("elf64", "bin"):
            target = out / "sentinel.o"
            target.write_bytes(b"preserved")
            run = subprocess.run([args.basm, "--target-profile", "public", "-f", fmt, "-o", str(target), str(source)], capture_output=True, text=True)
            (out / f"invalid-{index}-{fmt}.log").write_text(run.stdout + run.stderr)
            if run.returncode <= 0 or target.read_bytes() != b"preserved" or "runtime error:" in run.stderr or "AddressSanitizer" in run.stderr:
                errors.append(f"invalid {index}/{fmt}: accepted, crashed or altered output")
            else:
                report["refusals"] += 1
    report["failures"] = errors
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if errors:
        p.exit(1, "\n".join(errors) + "\n")
    print(f"PASS uaccess ISA: {len(positive)} NASM object cases, {report['refusals']} refusals")


if __name__ == "__main__":
    main()
