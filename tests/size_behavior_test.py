#!/usr/bin/env python3
"""INV-572: size refactors preserve full-product behavior, including bootstrap.

Compare exact objects/binaries and refusal diagnostics against a pinned before
binary. Generated machine code is NEVER linked or executed. NASM independently
checks the modern memory-only emitter matrix.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MEMORY = ("fldcw", "fnstcw", "frstor", "fnsave", "fxsave", "fxrstor",
          "fxsave64", "fxrstor64", "invlpg", "lgdt", "lidt", "sgdt", "sidt", "xsave", "xrstor")
JCC = ("jz", "js", "jnz", "jns", "jne", "jnc", "jle", "jl", "jge", "jg", "je", "jc", "jbe", "jb", "jae", "ja")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--basm", type=Path, required=True)
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--csum-copy-extension", action="store_true", help="INV-730: allow only the four new inventory rows")
    p.add_argument("--tina26-extension", action="store_true", help="INV-740: exact 26 SSE form delta from cca94")
    p.add_argument("--tina26-followup", action="store_true", help="exact unmodeled ENDBR64 vocabulary delta from 8b322")
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        p.error("use a new evidence directory")
    basm, before = args.basm.resolve(), args.before.resolve()
    report = {"basm": str(basm), "before": str(before), "cases": [], "errors": []}
    report["sha256"] = {str(b): hashlib.sha256(b.read_bytes()).hexdigest() for b in (basm, before)}

    def run(label, command):
        r = subprocess.run([str(x) for x in command], capture_output=True, timeout=20)
        (out / (label + ".log")).write_bytes(r.stdout + r.stderr)
        if r.returncode not in (0, 1):
            raise RuntimeError(f"{label}: abnormal return {r.returncode}")
        return r

    for profile in ([], ["--target-profile", "public"], ["--target-profile", "beyond"],
                    ["--target-profile", "beyond", "--bootstrap", "ap-trampoline-v1"]):
        for option in ("--capabilities", "--list-instructions", "--list-forms"):
            label = "cli-" + (profile[-1] if profile else "default") + option
            a = run(label + "-before", [before, *profile, option])
            b = run(label + "-after", [basm, *profile, option])
            old_stdout, new_stdout = a.stdout, b.stdout
            if args.tina26_followup and a.returncode == b.returncode == 0 and option == '--list-instructions':
                old, new = json.loads(old_stdout), json.loads(new_stdout)
                added = [f for f in new['instructions'] if f['mnemonic'] == 'endbr64']
                assert added == [{'mnemonic': 'endbr64', 'modeled_forms': 0}]
                assert not any(f['mnemonic'] == 'endbr64' for f in old['instructions'])
                new['instructions'].remove(added[0])
                new['count'] -= 1
                for value in (old, new):
                    value['instructions'].sort(key=lambda f: f['mnemonic'])
                old_stdout, new_stdout = old, new
            if args.tina26_extension and a.returncode == b.returncode == 0:
                old, new = json.loads(old_stdout), json.loads(new_stdout)
                if option == '--capabilities':
                    assert old['modeled_forms'] == 69 and new['modeled_forms'] == 95
                    new['modeled_forms'] = 69
                elif option == '--list-forms':
                    ids = {f['id'] for f in old['forms']}
                    added = [f for f in new['forms'] if f['id'] not in ids]
                    expected = {f'{m}_{e}' for m in ('movaps', 'movups', 'movdqa', 'movdqu') for e in ('mr', 'rm', 'rr')}
                    expected.update(('movq_gx movq_mr movq_rm movq_xg paddd_rr paddq_rr pmuludq_rr por_rr pshufd_shuf pslld_shift psrld_shift punpckhqdq_rr punpcklqdq_rr pxor_rr').split())
                    assert len(added) == 26 and {f['id'] for f in added} == expected
                    new['forms'] = [f for f in new['forms'] if f['id'] in ids]
                else:
                    old_names = {f['mnemonic'] for f in old['instructions']}
                    added = [f for f in new['instructions'] if f['mnemonic'] not in old_names]
                    assert len(added) == 14
                    assert {f['mnemonic'] for f in added} == set('movaps movups movdqa movq paddd paddq pxor por pslld psrld pshufd pmuludq punpcklqdq punpckhqdq'.split())
                    new['instructions'] = [f for f in new['instructions'] if f['mnemonic'] in old_names]
                    item = next(f for f in new['instructions'] if f['mnemonic'] == 'movdqu')
                    assert item['modeled_forms'] == 3
                    item['modeled_forms'] = 0
                    new['count'] -= 14
                    for value in (old, new):
                        value['instructions'].sort(key=lambda f: f['mnemonic'])
                old_stdout, new_stdout = old, new
            if args.csum_copy_extension and a.returncode == b.returncode == 0:
                old, new = json.loads(old_stdout), json.loads(new_stdout)
                if option == '--capabilities':
                    assert old['modeled_forms'] == 65 and new['modeled_forms'] == 69
                    new['modeled_forms'] = 65
                elif option == '--list-forms':
                    added = [f for f in new['forms'] if f['id'] not in {f['id'] for f in old['forms']}]
                    assert [(f['id'], f['operands'], f['width']) for f in added] == [
                        ('adc_rr32', 'gpr,gpr', 32), ('adc_rr64', 'gpr,gpr', 64),
                        ('rol_r32_8', 'gpr,8', 32), ('ror_r64_1', 'gpr,1', 64)]
                    new['forms'] = [f for f in new['forms'] if f not in added]
                else:
                    added = [f for f in new['instructions'] if f['mnemonic'] in ('adc', 'rol', 'ror')]
                    assert sorted((f['mnemonic'], f['modeled_forms']) for f in added) == [('adc', 2), ('rol', 1), ('ror', 1)]
                    new['instructions'] = [f for f in new['instructions'] if f not in added]
                    new['count'] -= 3
                    for value in (old, new):
                        value['instructions'].sort(key=lambda f: f['mnemonic'])
                old_stdout, new_stdout = old, new
            if (a.returncode, old_stdout, a.stderr) != (b.returncode, new_stdout, b.stderr):
                report["errors"].append(label)

    configs = [(64, []), (64, ["--target-profile", "public"]),
               (64, ["--target-profile", "beyond"]), (16, []), (32, [])]
    for config, (bits, flags) in enumerate(configs):
        cases = {}
        if bits == 64:
            addresses = ["rax", "rsp", "rbp", "r8", "r12", "r13", "r15+127", "rdi-128",
                         "rsi+128", "r12+r9*4+128", "rax+rcx*2", "eax+ecx*2", "fs:rax",
                         "gs:r12+16", "0x1000"]
        else:
            addresses = ["eax", "esp", "ebp", "eax+ecx*2", "edi-128", "fs:eax", "0x1000"]
        for op in MEMORY:
            cases[op] = "section .text\n" + "\n".join(f"{op} [{addr}]" for addr in addresses) + "\n"
            cases[op + "-rel"] = f"section .text\n{op} [rel target]\n{op} [rel ext]\nsection .data\ntarget: dq 0\nextern ext\n"
            for index, addr in enumerate(("rax+rcx*3", "rel missing", "rax+", "rax+rcx+rdx")):
                cases[f"{op}-invalid-{index}"] = f"section .text\n{op} [{addr}]\n"
        for directive in ("db", "dw", "dd", "dq", "resb", "resw", "resd", "resq"):
            section = ".bss" if directive.startswith("res") else ".data"
            cases[directive] = f"section {section}\n{directive} 1\na: {directive} 2\nb {directive} 3\ntimes 2 {directive} 4\nc: times 2 {directive} 1\nd times 2 {directive} 1\n"
            for prefix in ("", "label: ", "implicit ", "times 2 "):
                label = directive + "-negative-" + str(len(prefix))
                cases[label] = f"section {section}\n{prefix}{directive} -1\n"
                if directive.startswith("res"):
                    cases[label + "-overflow"] = f"section {section}\n{prefix}{directive} 9223372036854775807\n"
        cases["pp"] = """%define A 3
%assign N 2
%macro M 0
%if A == 3
db 'a'
%elifndef A
db 'b'
%endif
%endmacro
struc S
.a resb 1
.b resw 2
endstruc
section .data
M
%rep N
db S_size
%endrep
%undef A
%ifndef A
db 'c'
%endif
%ifidn x,x
db 'd'
%elifnidn x,y
db 'e'
%else
db 'f'
%endif
"""
        cases["bytes"] = "section .data\ndb 'a',`b`,\"c\",0,255\ndw 0x1234\ndd 0x12345678\ndq 0x123456789abcdef0\n"
        # INV-586: every shared Jcc dispatch arm preserves force, target and CC.
        for op in JCC:
            prefix = "jcc-" + op
            cases[prefix + "-local"] = f"section .text\nstart: {op} short forward\n{op} near start\n{op} forward\nforward: {op} start\n{op} $\n"
            for n in (127, 128):
                cases[f"{prefix}-forward-{n}"] = f"section .text\n{op} short target\ntimes {n} db 0x90\ntarget: ret\n"
            for n in (126, 127):
                cases[f"{prefix}-backward-{n}"] = f"section .text\ntarget: times {n} db 0x90\n{op} short target\n"
            for force in ("", "near ", "short "):
                cases[prefix + "-external-" + force.strip()] = f"section .text\n{op} {force}ext\nextern ext\n"
                cases[prefix + "-cross-" + force.strip()] = f"section .text\n{op} {force}target\nsection .text.cold progbits alloc exec nowrite\ntarget: ret\n"
            for operand in ("", "short", "near", "missing", "short missing", "near missing", "near target, target"):
                cases[prefix + "-invalid-" + operand.replace(" ", "_")] = f"section .text\n{op} {operand}\ntarget: ret\n"
        for name, text in cases.items():
            source = out / f"{config}-{name}.basm"
            source.write_text(f"bits {bits}\n" + text)
            for fmt in ("elf64", "bin"):
                label = f"{config}-{name}-{fmt}"
                outputs = []
                for arm, binary in (("before", before), ("after", basm)):
                    target = out / f"{label}-{arm}.o"
                    target.write_bytes(b"sentinel")
                    result = run(label + "-" + arm, [binary, *flags, "-f", fmt, "-o", target, source])
                    outputs.append((result.returncode, result.stdout, result.stderr, target.read_bytes()))
                    if result.returncode and target.read_bytes() != b"sentinel":
                        report["errors"].append(label + "-publication-" + arm)
                if outputs[0] != outputs[1]:
                    report["errors"].append(label)
                # ELF metadata may intentionally differ from NASM for legacy
                # modes; use modern raw instruction bytes as the independent arm.
                oracle = False
                if config == 0 and fmt == "bin" and (name in MEMORY or (name.startswith("jcc-") and name.endswith("-local"))):
                    target = out / f"{label}-nasm.bin"
                    r = run(label + "-nasm", ["nasm", "-f", "bin", "-o", target, source])
                    if r.returncode or outputs[1][0] or target.read_bytes() != outputs[1][3]:
                        report["errors"].append(label + "-nasm")
                    oracle = True
                if name.startswith("jcc-") and fmt == "bin":
                    if name.endswith(("-local", "-forward-127", "-backward-126")) and outputs[1][0] != 0:
                        report["errors"].append(label + "-expected-accept")
                    if name.endswith(("-forward-128", "-backward-127")) and outputs[1][0] != 1:
                        report["errors"].append(label + "-expected-refusal")
                report["cases"].append({"name": label, "accepted": outputs[1][0] == 0, "nasm": oracle})
    # Bootstrap is source-pinned, not a general switch for legacy bitness.
    source = ROOT.parents[1] / "ring0/arch/amd64/ap_trampoline.basm"
    if hashlib.sha256(source.read_bytes()).hexdigest() != "f0f6ba9d486c1ee1620ccbd6bfaff9f95584a90cb60a3df35fc98aed473cf02e":
        p.exit(1, "FAIL size behavior: bootstrap source pin differs\n")
    for fmt in ("elf64", "bin"):
        outputs = []
        for arm, binary in (("before", before), ("after", basm)):
            label = "bootstrap-" + fmt + "-" + arm
            target = out / (label + ".o")
            result = run(label, [binary, "--target-profile", "beyond", "--bootstrap", "ap-trampoline-v1",
                                 "-f", fmt, "-o", target, source])
            outputs.append((result.returncode, result.stdout, result.stderr, target.read_bytes() if target.exists() else None))
        if outputs[0] != outputs[1] or outputs[1][0] != 0:
            report["errors"].append("bootstrap-" + fmt)
        report["cases"].append({"name": "bootstrap-" + fmt, "accepted": outputs[1][0] == 0, "nasm": False})
    report["passed"] = not report["errors"]
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["errors"]:
        p.exit(1, "FAIL size behavior: " + ", ".join(report["errors"]) + "\n")
    print(f"PASS size behavior: {len(report['cases'])} exact before/after cases, 12 CLI comparisons, {sum(c['nasm'] for c in report['cases'])} NASM matrices; no code executed")


if __name__ == "__main__":
    main()
