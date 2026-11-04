#!/usr/bin/env python3
"""Batch26 follow-up: literal ENDBR, alignment, explicit errors, closed CR MOV.

All fixtures are encoding/ELF/diagnostic checks only. NEVER execute CR/ENDBR
or kernel port code. Original algorithm harnesses remain port-agent-owned.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
import subprocess
from tina26_backend_test import elf

REGS64 = 'rax rcx rdx rbx rsp rbp rsi rdi'.split() + [f'r{i}' for i in range(8, 16)]
REGS32 = 'eax ecx edx ebx esp ebp esi edi'.split() + [f'r{i}d' for i in range(8, 16)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--basm', type=Path, required=True)
    p.add_argument('--before', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--red', action='store_true')
    args = p.parse_args()
    args.out.mkdir(parents=True)
    out = args.out
    report = dict(basm=str(args.basm), sha256=hashlib.sha256(args.basm.read_bytes()).hexdigest(),
                  red=args.red, assertions=0, refusals=0, byte_cases=0, exact_before_after=0)

    def run(label, argv):
        r = subprocess.run(list(map(str, argv)), capture_output=True, timeout=30)
        (out / (label + '.log')).write_bytes(r.stdout + r.stderr)
        return r

    def assemble(label, text, profile='public', bad=False, explain=False, tool=None, fmt='elf64'):
        src, dst = out / (label + '.basm'), out / (label + '.' + fmt)
        proof = out / (label + '.proof')
        src.write_text(text + '\n')
        dst.write_bytes(b'preserved object')
        proof.write_bytes(b'preserved proof')
        r = run(label, [tool or args.basm, *(['--target-profile', profile] if profile else []),
                       *(['--explain'] if explain else []), '-f', fmt, '--emit-attestation', proof, '-o', dst, src])
        if bad:
            assert r.returncode == 1 and b'error:' in r.stderr, (label, r.returncode, r.stderr)
            assert dst.read_bytes() == b'preserved object' and proof.read_bytes() == b'preserved proof', label
            assert not list(out.glob(dst.name + '.tmp.*'))
            report['refusals'] += 1
        else:
            assert r.returncode == 0, (label, r.returncode, r.stderr)
        return src, dst, r

    invalid = ['mov edx,cr4', 'mov cr4,edx', 'mov rdx,cr4,rax', 'mov cr4,rdx,rax',
               'mov rdx cr4', 'mov cr4,,rdx', 'lock mov rdx,cr4', 'lock mov cr4,rdx']
    if args.red:
        assemble('red-endbr', 'bits 64\nsection .text\nendbr64', bad=True)
        _, dst, _ = assemble('red-align', 'bits 64\nsection .text align=4\nret')
        assert elf(dst)[0]['.text'][0][8] == 16
        _, _, r = assemble('red-error', '%error "Batch26 refusal marker"', bad=True)
        assert b'unknown instruction' in r.stderr and b'Batch26 refusal marker' not in r.stderr
        assemble('red-literal-condition', '%if 1\n%error "Batch26 refusal marker"\n%endif')
        for i, text in enumerate(invalid):
            assemble('red-cr-' + str(i), 'bits 64\nsection .text\n' + text)
        _, dst, _ = assemble('covered-symbols', 'bits 64\nsection .text\nglobal entry:notype 1\nentry: ret\nsection .data\nstatic gdt:data 4\ngdt: dd 0')
        _, syms = elf(dst)
        assert syms['entry'][0] == 0x10 and syms['entry'][-1] == 1
        assert syms['gdt'][0] == 1 and syms['gdt'][-1] == 4
        report['assertions'] += 13
    else:
        for profile in ('', 'public', 'beyond'):
            for bits, regs in ((64, REGS64), (32, REGS32[:8]), (16, REGS32[:8])):
                if profile and bits != 64:
                    continue
                lines = [f'mov {r},cr{cr}\nmov cr{cr},{r}' for cr, r in itertools.product((0, 2, 3, 4), regs)]
                text = f'bits {bits}\nsection .text\n' + '\n'.join(lines)
                label = f'cr-matrix-{profile or "default"}-{bits}'
                src, dst, _ = assemble(label, text, profile)
                oracle = out / (label + '.nasm.o')
                assert run(label + '-nasm', ['nasm', '-f', 'elf64', '-o', oracle, src]).returncode == 0
                assert elf(dst)[0]['.text'][1] == elf(oracle)[0]['.text'][1]
                gas, gas_obj = out / (label + '.S'), out / (label + '.gas.o')
                gas.write_text(f'.intel_syntax noprefix\n.code{bits}\n.text\n' + '\n'.join(lines) + '\n')
                assert run(label + '-gas', ['as', '--64', '-o', gas_obj, gas]).returncode == 0
                assert elf(dst)[0]['.text'][1] == elf(gas_obj)[0]['.text'][1]
                report['byte_cases'] += 2*len(lines)
            for text in ('endbr64', 'label: endbr64', '%macro M 0\nendbr64\n%endmacro\nM'):
                label = f'endbr-{profile or "default"}-{report["assertions"]}'
                _, dst, _ = assemble(label, 'bits 64\nsection .text\n' + text, profile)
                assert elf(dst)[0]['.text'][1] == bytes.fromhex('f3 0f 1e fa')
                report['assertions'] += 1
        bad = invalid + [f'mov {a},{b}' for a, b in (('dx','cr4'), ('cr4','dx'), ('[rax]','cr4'), ('cr4','[rax]'),
                        ('cr4','cr3'), ('cr8','rax'), ('rax','cr8'), ('xmm0','cr0'))]
        bad += ['mov cr4,rdx,', 'mov ,cr4 rdx', 'mov cr4 rdx,', 'mov cr4,rdx junk', 'mov cr4',
                'mov rax,cr0+0', 'mov cr0,rax+0']
        bad += [f'{prefix} mov {a},{b}' for prefix in ('rep', 'repne', 'o64') for a, b in (('cr4','rdx'), ('rdx','cr4'))]
        bad += [f'endbr64{suffix}' for suffix in (' rax', ',', ',rax', ' 1', ' endbr64')]
        bad += [f'{prefix} endbr64' for prefix in ('lock', 'rep', 'repne', 'o64')]
        bad += [f'bits {bits}\n{instruction}' for bits in (16, 32) for instruction in ('endbr64', 'mov rax,cr4', 'mov cr4,r8', 'mov r8d,cr4')]
        for i, text in enumerate(bad):
            for profile in ('', 'public', 'beyond'):
                for fmt in ('elf64', 'bin'):
                    assemble(f'bad-{i}-{profile or "default"}-{fmt}', 'bits 64\nsection .text\n' + text, profile, bad=True, fmt=fmt)
        for context in ('%error "Batch26 refusal marker"', '%define MESSAGE "Batch26 refusal marker"\n%error MESSAGE',
                        '%macro M 0\n%error "Batch26 refusal marker"\n%endmacro\nM',
                        '%if 1\n%error "Batch26 refusal marker"\n%endif', '%rep 1\n%error "Batch26 refusal marker"\n%endrep'):
            for profile in ('', 'public', 'beyond'):
                label = f'error-{report["refusals"]}'
                _, _, r = assemble(label, context, profile, bad=True)
                assert b'Batch26 refusal marker' in r.stderr and b'unknown instruction' not in r.stderr
        for text in ('%if 0\n%error "inactive"\n%endif\nret', '%macro M 0\n%error "unused"\n%endmacro\nret',
                     '%rep 0\n%error "zero"\n%endrep\nret', 'db "%error not a directive",0',
                     '%macro M 0\n%if 0\n%error "inactive macro"\n%endif\n%endmacro\nM\nret'):
            assemble(f'inactive-{report["assertions"]}', text)
            report['assertions'] += 1
        for value in ('0', '1', '16', '0x10', '-1'):
            _, dst, _ = assemble('condition-' + value, f'%if {value}\ndb 1\n%else\ndb 0\n%endif')
            assert elf(dst)[0]['.text'][1] == bytes([int(int(value, 0) != 0)])
            report['assertions'] += 1
        for profile in ('public', 'beyond'):
            _, dst, r = assemble('endbr-trace-' + profile, 'endbr64\nret', profile, explain=True)
            trace = json.loads(r.stdout)
            assert trace['records'][0]['form'] is None and trace['coverage']['unmodeled'] == 1
            assert trace['semantic_verification'] == 'unimplemented' and not trace['cfg']['complete']
        align_cases = [('.text', 'section .text align=4\nret', 4),
                       ('.text', 'section .text\nret', 16),
                       ('.text', 'align 64\nsection .text align=4\nret', 64),
                       ('.text', 'alignb 8\nsection .text align=4\nret', 8),
                       ('.text', 'section .text align=4\nsection .data\ndb 0\nsection .text\nret', 4),
                       ('.text', 'section .text align=4\nsection .text align=32\nsection .text align=4\nret', 32),
                       ('.text', 'section .text align=4\nret\nalign 64\nsection .text align=4\nret', 64),
                       ('.data', 'section .data align=32\ndb 0', 32),
                       ('.rodata', 'section .rodata align=16\ndb 0', 16),
                       ('.bss', 'section .bss align=64\nresb 1', 64),
                       ('.note.Linux', 'section .note.Linux alloc noexec nowrite note align=4\ndd 1\nalignb 16\nsection .note.Linux alloc noexec nowrite note align=4\ndd 2', 16)]
        for i, (section, text, expected) in enumerate(align_cases):
            _, dst, _ = assemble('align-' + str(i), 'bits 64\n' + text)
            assert elf(dst)[0][section][0][8] == expected, (i, expected)
            report['assertions'] += 1
        for prefix in ('lock', 'rep', 'repne'):
            for body in ('add rax,rbx', 'movsb', 'nop', 'pxor xmm0,xmm1'):
                label = f'prefix-{prefix}-{body.split()[0]}'
                src, dst = out / (label + '.basm'), out / (label + '.out')
                src.write_text('bits 64\nsection .text\n' + prefix + ' ' + body + '\n')
                results = []
                for arm, tool in (('before', args.before), ('after', args.basm)):
                    dst.write_bytes(b'preserved')
                    r = run(label + arm, [tool, '-f', 'elf64', '-o', dst, src])
                    results.append((r.returncode, r.stdout, r.stderr, dst.read_bytes()))
                assert results[0] == results[1], label
                report['exact_before_after'] += 1
        # Old/new exact behavior for the emitters considered for size sharing.
        for bits in (16, 32, 64):
            for op in ('rdrand', 'rdseed', 'rdfsbase', 'wrfsbase'):
                for reg in ('ax', 'eax', 'rax', 'r8w', 'r8d', 'r8', 'al', 'xmm0', '[rax]'):
                    label = f'exact-{bits}-{op}-{reg.replace("[", "").replace("]", "")}'
                    src, dst = out / (label + '.basm'), out / (label + '.out')
                    src.write_text(f'bits {bits}\nsection .text\n{op} {reg}\n')
                    results = []
                    for arm, tool in (('before', args.before), ('after', args.basm)):
                        dst.write_bytes(b'preserved')
                        r = run(label + arm, [tool, '-f', 'elf64', '-o', dst, src])
                        results.append((r.returncode, r.stdout, r.stderr, dst.read_bytes()))
                    assert results[0] == results[1], label
                    report['exact_before_after'] += 1
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
