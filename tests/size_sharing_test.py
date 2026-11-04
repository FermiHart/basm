#!/usr/bin/env python3
"""INV-586: exact differential for shared memory/relocation/ELF/body handling.

Requires explicit full before/after tools; never links or executes generated ISA.
This supplements, rather than replaces, the original 4362-case size differential.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--basm', type=Path, required=True)
    p.add_argument('--before', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--csum-copy-extension', action='store_true', help='INV-730: allow only schema coverage 65 -> 69')
    p.add_argument('--tina26-extension', action='store_true', help='INV-740: exact schema coverage 69 -> 95')
    p.add_argument('--tina26-followup', action='store_true', help='exact three canonical alignment field corrections from 8b322')
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        p.error('use a new evidence directory')
    tools = (args.before.resolve(), args.basm.resolve())
    report = {'tools': {str(b): hashlib.sha256(b.read_bytes()).hexdigest() for b in tools},
              'cases': [], 'errors': []}
    cases = {}
    for name, head, body, end, use in (
            ('macro', '%macro M 0', 'nop', '%endmacro', 'M'),
            ('struc', 'struc S', '.field resq 1', 'endstruc', 'dq S_size'),
            ('rep', '%rep 2', 'nop', '%endrep', 'ret')):
        for ending in ('\n', '\r\n', ''):
            for suffix in ('', ' ; comment', '\t'):
                label = f'{name}-end-{len(cases)}'
                # A bare CR is not a pp_keyword delimiter in the baseline.
                expected = 1 if ending == '\r\n' and not suffix else 0
                cases[label] = (f'{head}\n{body}\n{end}{suffix}{ending}', expected)
        cases[name + '-used'] = (f'{head}\n{body}\n{end}\n{use}\n', 0)
        # Preserve existing EOF behavior too, without reinterpreting its policy.
        for text in (head, head+'\n', head+'\n'+body, head+'\n'+body+'\n',
                     head+'\n'+body+'\n'+end+'junk\n', head+'\n'+end+'\n'+use+'\n'):
            cases[f'{name}-eof-{len(cases)}'] = (text, None)
        for length in (1023, 1024):
            cases[f'{name}-line-{length}'] = (f'{head}\n;'+'x'*(length-1)+f'\n{body}\n{end}\n{use}\n',
                                             0 if length == 1023 else 1)
    (out / 'inner.inc').write_text('%macro INNER 0\nnop\n%endmacro\nINNER\n')
    (out / 'outer.inc').write_text('%include "inner.inc"\n%rep 2\nINNER\n%endrep\n')
    cases['include-trace'] = ('%include "outer.inc"\nret\n', 0)
    for addr in ('rax', 'rsp', 'r12+r9*4+128', 'eax+ecx*2', 'gs:0x1000', 'fs:rax',
                 'rel local', 'rel ext', 'abs local', 'abs ext', 'local', 'ext'):
        cases['memory-' + str(len(cases))] = (f'mov rax,[{addr}]\nmov [{addr}],rax\n'
                                            'extern ext\nsection .data\nlocal: dq 0\n', 0)
    cases['relocation-kinds'] = ('''extern ext
mov rax,ext
mov rax,local
mov eax,[abs ext]
mov eax,[abs local]
mov eax,[ext]
mov eax,[local]
mov eax,[rel ext]
mov eax,[rel local]
call ext
section .data
dq ext,local
dd ext,local
local: dq 0
''', 0)
    cases['section-headers'] = ('''global entry:function
entry: ret
section .data align=32
dq entry
section .rodata align=16
dd entry
section .bss align=64
resq 3
section .cold progbits alloc exec nowrite align=32
call entry
section .scratch nobits alloc noexec write align=128
resb 17
section .debug progbits noalloc noexec nowrite align=1
db 1,2,3
''', 0)
    for count in (4096, 4097, 65536, 65537):
        cases[f'relocation-capacity-{count}'] = (f'extern ext\nsection .data\ntimes {count} dq ext\n',
                                                 0 if count <= 65536 else 1)
    for flags in ([], ['--target-profile', 'public'], ['--target-profile', 'beyond'],
                  ['--target-profile', 'public', '--explain', '--diagnostics-json']):
        for name, (body, expected) in cases.items():
            for fmt in ('elf64', 'bin'):
                label = f'{len(report["cases"]):04d}-{name}-{fmt}'
                source = out / (label + '.basm')
                source.write_text('bits 64\nsection .text\n' + body)
                target = out / (label + '.out')
                results = []
                for arm, binary in zip(('before', 'after'), tools):
                    target.write_bytes(b'preserved')
                    argv = [str(binary), *flags, '-f', fmt, '-o', str(target), str(source)]
                    r = subprocess.run(argv, capture_output=True, timeout=30)
                    data = target.read_bytes()
                    (out / (label + '-' + arm + '.stdout')).write_bytes(r.stdout)
                    (out / (label + '-' + arm + '.stderr')).write_bytes(r.stderr)
                    (out / (label + '-' + arm + '.out')).write_bytes(data)
                    stdout = r.stdout
                    if args.tina26_extension and '--explain' in flags and r.returncode == 0:
                        trace = json.loads(stdout)
                        assert trace['coverage']['schema_forms'] == (69 if arm == 'before' else 95)
                        if arm == 'after':
                            assert stdout.count(b'"schema_forms":95') == 1
                            stdout = stdout.replace(b'"schema_forms":95', b'"schema_forms":69')
                    if args.csum_copy_extension and '--explain' in flags and r.returncode == 0:
                        trace = json.loads(stdout)
                        assert trace['coverage']['schema_forms'] == (65 if arm == 'before' else 69)
                        # Preserve every other byte, including provenance and CFG taint.
                        if arm == 'after':
                            assert stdout.count(b'"schema_forms":69') == 1
                            stdout = stdout.replace(b'"schema_forms":69', b'"schema_forms":65')
                    results.append((r.returncode, stdout, r.stderr, data))
                    if r.returncode not in (0, 1) or (r.returncode and data != b'preserved'):
                        report['errors'].append(label + '-' + arm + '-publication/exit')
                    if fmt == 'elf64' and expected is not None and r.returncode != expected:
                        report['errors'].append(label + '-' + arm + '-expected-exit')
                if args.tina26_followup and name == 'section-headers' and fmt == 'elf64':
                    # An exact expected byte delta, not a metadata normalization:
                    # only these three sh_addralign fields may change. Everything
                    # else, including stdout/diagnostics/trace and all ELF bytes,
                    # must remain identical to the pinned before result.
                    expected_bytes = bytearray(results[0][3])
                    shoff = struct.unpack_from('<Q', expected_bytes, 40)[0]
                    shsize, shnum, shstr = struct.unpack_from('<HHH', expected_bytes, 58)
                    assert shsize == 64
                    row = struct.unpack_from('<IIQQQQIIQQ', expected_bytes, shoff+shstr*64)
                    names = expected_bytes[row[4]:row[4]+row[5]]
                    changes = {'.data': (4, 32), '.rodata': (4, 16), '.bss': (4, 64)}
                    changed = []
                    for i in range(shnum):
                        at = shoff+i*64
                        ni = struct.unpack_from('<I', expected_bytes, at)[0]
                        section = names[ni:names.index(0, ni)].decode()
                        if section in changes:
                            old_align, new_align = changes[section]
                            assert struct.unpack_from('<Q', expected_bytes, at+48)[0] == old_align
                            struct.pack_into('<Q', expected_bytes, at+48, new_align)
                            changed.append(section)
                    assert set(changed) == set(changes)
                    if results[1] != (*results[0][:3], bytes(expected_bytes)):
                        report['errors'].append(label + '-exact-alignment-delta')
                elif results[0] != results[1]:
                    report['errors'].append(label + '-differential')
                report['cases'].append({'name': label, 'flags': flags, 'accepted': results[1][0] == 0})
    report['passed'] = not report['errors']
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if not report['passed']:
        p.exit(1, 'FAIL size sharing: ' + ', '.join(report['errors']) + '\n')
    print(f'PASS size sharing: {len(report["cases"])} exact output/diagnostic/trace comparisons; no generated code executed')


if __name__ == '__main__':
    main()
