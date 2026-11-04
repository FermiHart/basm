#!/usr/bin/env python3
"""INV-730: only ADC RR32/64, ROR r64,1 and ROL r32,8; no kernel execution."""
import argparse
import ctypes
import hashlib
import itertools
import json
import mmap
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REGS = {64: 'rax rcx rdx rbx rsp rbp rsi rdi'.split() + [f'r{i}' for i in range(8, 16)],
        32: 'eax ecx edx ebx esp ebp esi edi'.split() + [f'r{i}d' for i in range(8, 16)]}
FORMS = {'adc_rr32': ('adc eax,ecx', 'cf,dst,src', 'af,cf,dst,of,pf,sf,zf',
                      'af:write,cf:write,of:write,pf:write,sf:write,zf:write'),
         'adc_rr64': ('adc rax,rcx', 'cf,dst,src', 'af,cf,dst,of,pf,sf,zf',
                      'af:write,cf:write,of:write,pf:write,sf:write,zf:write'),
         'rol_r32_8': ('rol eax,8', 'dst', 'cf,dst,of', 'cf:write,of:undefined'),
         'ror_r64_1': ('ror rax,1', 'dst', 'cf,dst,of', 'cf:write,of:write')}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--basm', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--red', action='store_true', help='require unavailable forms and preserved output')
    args = p.parse_args()
    assert __debug__, 'assertions required'
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert not any(out.iterdir()), 'fresh evidence directory required'
    basm = args.basm.resolve()
    report = {'basm': str(basm), 'sha256': hashlib.sha256(basm.read_bytes()).hexdigest(),
              'red': args.red, 'byte_cases': 0, 'refusals': 0, 'semantic_cases': 0}

    def run(label, argv):
        r = subprocess.run([str(x) for x in argv], capture_output=True, timeout=30)
        (out / (label + '.log')).write_bytes(r.stdout + r.stderr)
        assert r.returncode in (0, 1), (label, r.returncode, r.stderr)
        return r

    def assemble(label, text, profile='public', fmt='bin', explain=False, red=False):
        source, target = out / (label + '.basm'), out / (label + '.' + fmt)
        source.write_text('bits 64\nsection .text\n' + text + '\n')
        target.write_bytes(b'preserved output')
        opts = ['--target-profile', profile] if profile else []
        if explain:
            opts += ['--explain']
        r = run(label, [basm, *opts, '-f', fmt, '-o', target, source])
        if red:
            assert r.returncode == 1 and b'error:' in r.stderr, (label, r.stderr)
            assert target.read_bytes() == b'preserved output', label
            assert not list(out.glob(target.name + '.tmp.*')), label
            report['refusals'] += 1
        else:
            assert r.returncode == 0, (label, r.stderr)
        return source, target, r

    if args.red:
        for name, (text, *_) in FORMS.items():
            for fmt in ('bin', 'elf64'):
                assemble(name + '-' + fmt, text, fmt=fmt, red=True)
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print('RED confirmed: all four unavailable forms refuse, 8 outputs preserved')
        return

    # Every architectural register pair, including self-pairs and both REX bits.
    texts = [f'adc {a},{b}' for width in (32, 64) for a, b in itertools.product(REGS[width], repeat=2)]
    texts += [f'ror {r},1' for r in REGS[64]] + [f'rol {r},8' for r in REGS[32]]
    for profile in ('', 'public', 'beyond'):
        source, target, _ = assemble('matrix-' + (profile or 'default'), '\n'.join(texts), profile)
        oracle = out / (target.stem + '.nasm.bin')
        assert run(oracle.stem, ['nasm', '-f', 'bin', '-o', oracle, source]).returncode == 0
        assert target.read_bytes() == oracle.read_bytes()
        report['byte_cases'] += len(texts)

    bad = ['adc', 'adc rax', 'adc rax,ebx', 'adc eax,rbx', 'adc ax,bx', 'adc al,cl',
           'adc ah,bh', 'adc r8w,r15w', 'adc spl,r8b', 'adc xmm0,xmm1', 'adc cr0,cr1',
           'adc rax,1', 'adc rax,[rbx]', 'adc [rax],rbx', 'adc qword [rax],rbx',
           'adc rax,rbx,rcx', 'adc rax,rbx,', 'adc rax,,rbx', 'adc rax rbx',
           'adc,rax rbx', 'adc rax rbx,', 'adc eax,ecx junk',
           'ror', 'ror rax', 'rol', 'rol eax']
    for op, reg, count in (('ror', 'rax', 1), ('rol', 'eax', 8)):
        bad += [f'{op} {reg},{c}' for c in (-1, 0, 2, 7, 9, 31, 32, 63, 64, 65, 255, 256, 257)
                if c != count]
        bad += [f'{op} {reg},{c}' for c in ('cl', 'rcx', '[rcx]', 'missing', f'{count}junk',
                                          f'{count}+0', f'({count})', f'byte {count}')]
        bad += [f'{op} {r},{count}' for r in ('al', 'ah', 'ax', 'r8w', 'xmm0', '[rax]', 'qword [rax]')]
        bad += [f'{op} {reg},{count},', f'{op} {reg},,{count}', f'{op} {reg},{count},1',
                f'{op} {reg} {count}', f'{op},{reg} {count}', f'{op} {reg} {count},']
    bad += ['ror eax,1', 'rol rax,8', 'ror rax,8', 'rol eax,1']
    bad += [f'bits {bits}\n{text}' for bits in (16, 32) for text, *_ in FORMS.values()]
    bad += [f'{prefix} {text}' for prefix in ('lock', 'rep', 'o64') for text, *_ in FORMS.values()]
    for i, text in enumerate(bad):
        for profile in ('', 'public', 'beyond'):
            for fmt in ('bin', 'elf64'):
                assemble(f'bad-{i}-{profile or "default"}-{fmt}', text, profile, fmt, red=True)

    for profile in ('public', 'beyond'):
        text = '\n'.join(v[0] for v in FORMS.values()) + '\nret'
        _, plain, _ = assemble('trace-' + profile, text, profile, 'elf64')
        plain_bytes = plain.read_bytes()
        _, target, r = assemble('trace-' + profile, text, profile, 'elf64', explain=True)
        assert target.read_bytes() == plain_bytes
        trace = json.loads(r.stdout)
        assert trace['semantic_verification'] == 'unimplemented'
        assert trace['coverage']['schema_forms'] == 95 and trace['coverage']['unmodeled'] == 0
        for record, (name, (_, reads, writes, flags)) in zip(trace['records'], FORMS.items()):
            assert record['form'] == name and record['control'] == 'next'
            assert {key: record['effects'][key] for key in ('reads', 'writes', 'flags')} == {
                'reads': reads, 'writes': writes, 'flags': flags}
        assert not trace['cfg']['complete'] and trace['cfg']['status'] == 'partial'
        assert [(e['from'], e['to'], e['kind']) for e in trace['cfg']['edges']] == [
            (i, i+1, 'fallthrough') for i in range(1, 5)]

    # Reviewed safe SysV leaf probes ONLY: register moves, CLC/STC, arithmetic,
    # PUSHFQ/POP RDX, two writes into caller-owned 16 bytes, RET. No privileged
    # fixtures, syscalls, arbitrary input bytes, stack-register operands or jumps.
    # NASM parity of the complete wrapper is mandatory before making it executable.
    rng = random.Random(730)
    for name, (instruction, *_) in FORMS.items():
        width = 64 if name in ('adc_rr64', 'ror_r64_1') else 32
        mask, sign = (1 << width) - 1, 1 << (width - 1)
        values = [0, 1, 15, 16, 63, sign-1, sign, mask-1, mask, 0x123456789abcdef0 & mask]
        pairs = list(itertools.product(values, repeat=2)) + [(rng.getrandbits(width), rng.getrandbits(width)) for _ in range(100)]
        for carry in (0, 1):
            # CMP seeds PF/ZF/AF/SF/OF; rotate must preserve PF/ZF/AF/SF.
            text = ('mov r8,rdx\nmov rax,rdi\nmov rcx,rsi\ncmp ecx,0\n'
                    + ('stc' if carry else 'clc') + '\npushfq\npop r9\n' + instruction
                    + '\npushfq\npop rdx\nmov [r8],rdx\nmov [r8+8],r9\nret')
            source, target, _ = assemble(f'probe-{name}-{carry}', text)
            oracle = out / (target.stem + '.nasm.bin')
            assert run(oracle.stem, ['nasm', '-f', 'bin', '-o', oracle, source]).returncode == 0
            code = target.read_bytes()
            assert code == oracle.read_bytes()
            with mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE) as mem:
                mem.write(code)
                address = ctypes.addressof(ctypes.c_char.from_buffer(mem))
                libc = ctypes.CDLL(None, use_errno=True)
                libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                assert libc.mprotect(address, len(code), mmap.PROT_READ | mmap.PROT_EXEC) == 0
                probe = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,
                                         ctypes.POINTER(ctypes.c_uint64))(address)
                for a, b in pairs:
                    flags = (ctypes.c_uint64 * 2)()
                    # High bits intentionally set: r32 writes must zero-extend.
                    actual = probe(a | (0xa5a5a5a500000000 if width == 32 else 0), b, flags)
                    if name.startswith('adc'):
                        total = a + b + carry
                        expected = total & mask
                        expected_flags = (int(total > mask) | (int((expected & 255).bit_count() % 2 == 0) << 2)
                                          | (((a ^ b ^ expected) & 16)) | (int(expected == 0) << 6)
                                          | (int(bool(expected & sign)) << 7)
                                          | (int(bool((~(a ^ b) & (a ^ expected)) & sign)) << 11))
                        checked = 0x8d5
                    else:
                        expected = ((a >> 1) | ((a & 1) << 63)) if width == 64 else ((a << 8) | (a >> 24)) & mask
                        expected_flags = flags[1] & 0xd4
                        expected_flags |= (a & 1) if width == 64 else (expected & 1)
                        checked = 0xd5  # OF is undefined for ROL by 8, never asserted.
                        if width == 64:
                            expected_flags |= (((expected >> 63) ^ (expected >> 62)) & 1) << 11
                            checked |= 0x800
                    assert actual == expected and flags[0] & checked == expected_flags, (name, carry, a, b, actual, expected, list(flags), expected_flags)
                    report['semantic_cases'] += 1
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS csum copy ISA:', json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
