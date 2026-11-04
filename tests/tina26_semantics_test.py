#!/usr/bin/env python3
"""INV-740: reviewed host-safe SSE leaves, NOT the independent Tina algorithms."""
import argparse
import ctypes
import hashlib
import itertools
import json
import mmap
from pathlib import Path
import random
import struct
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--basm', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    out = a.out.resolve()
    out.mkdir(parents=True)
    report = dict(sha256=hashlib.sha256(a.basm.read_bytes()).hexdigest(), cases=0)
    rng = random.Random(740)
    vectors = [struct.pack('<4I', *v) for v in itertools.product((0, 1, 0x7fffffff, 0x80000000, 0xffffffff), repeat=4)]
    vectors += [rng.getrandbits(128).to_bytes(16, 'little') for _ in range(100)]
    instructions = [(m, None) for m in ('movaps', 'movups', 'movdqa', 'movdqu', 'paddd', 'paddq', 'pxor', 'por', 'pmuludq', 'punpcklqdq', 'punpckhqdq')]
    instructions += [(m, i) for m in ('pslld', 'psrld', 'pshufd') for i in (0, 1, 7, 8, 12, 16, 20, 24, 25, 31, 32, 50, 57, 78, 147, 255)]
    instructions += [('movq-load', None), ('movq-xg', None), ('movq-gx', None), ('movq-store', None)]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    for serial, (m, imm) in enumerate(instructions):
        if m == 'movq-load':
            instruction = 'movq xmm15,[rdx]'
        elif m == 'movq-xg':
            instruction = 'mov rax,[rdx]\nmovq xmm15,rax'
        elif m == 'movq-gx':
            instruction = 'movq rax,xmm8\nmovq xmm15,rax'
        elif m == 'movq-store':
            instruction = 'movq [rdi+32],xmm8\nmovq xmm15,[rdi+32]'
        elif m == 'pshufd':
            instruction = f'pshufd xmm15,xmm8,{imm}'
        else:
            instruction = f'{m} xmm15,' + (str(imm) if imm is not None else 'xmm8')
        # Reviewed finite SysV leaf ONLY: two valid 16-byte reads, optional
        # 8-byte read/write in caller-owned space, caller-saved GPR/XMM arithmetic,
        # compare/flags snapshot, a 16-byte result write and RET. No CR/LGDT,
        # branches, syscall, kernel entry, or arbitrary source bytes executed.
        text = ('bits 64\nsection .text\nmovdqu xmm15,[rsi]\nmovdqu xmm8,[rdx]\n'
                'cmp rsi,rdx\npushfq\npop rcx\n' + instruction +
                '\npushfq\npop rax\nmov [rdi+16],rax\nmov [rdi+24],rcx\nmovdqu [rdi],xmm15\nret\n')
        src, dst, oracle = (out / f'{serial}.{ext}' for ext in ('basm', 'bin', 'nasm.bin'))
        src.write_text(text)
        for name, command in (('basm', [a.basm, '--target-profile', 'public', '-f', 'bin', '-o', dst, src]),
                              ('nasm', ['nasm', '-f', 'bin', '-o', oracle, src])):
            r = subprocess.run(list(map(str, command)), capture_output=True, timeout=30)
            (out / f'{serial}-{name}.log').write_bytes(r.stdout + r.stderr)
            assert r.returncode == 0, r.stderr
        code = dst.read_bytes()
        assert code == oracle.read_bytes(), (m, imm)
        with mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE) as mem:
            mem.write(code)
            address = ctypes.addressof(ctypes.c_char.from_buffer(mem))
            assert libc.mprotect(address, len(code), mmap.PROT_READ | mmap.PROT_EXEC) == 0
            probe = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(address)
            for n, av in enumerate(vectors):
                bv = vectors[(n * 37 + 11) % len(vectors)]
                va, vb, result = ctypes.create_string_buffer(av), ctypes.create_string_buffer(bv), ctypes.create_string_buffer(48)
                probe(result, va, vb)
                ad, bd = struct.unpack('<4I', av), struct.unpack('<4I', bv)
                aq, bq = struct.unpack('<2Q', av), struct.unpack('<2Q', bv)
                if m.startswith('movq'):
                    expected = bv[:8] + bytes(8)
                elif m.startswith('mov'):
                    expected = bv
                elif m == 'paddd':
                    expected = struct.pack('<4I', *((x+y) & 0xffffffff for x, y in zip(ad, bd)))
                elif m == 'paddq':
                    expected = struct.pack('<2Q', *((x+y) & 0xffffffffffffffff for x, y in zip(aq, bq)))
                elif m in ('pxor', 'por'):
                    expected = bytes((x ^ y) if m == 'pxor' else (x | y) for x, y in zip(av, bv))
                elif m == 'pmuludq':
                    expected = struct.pack('<2Q', ad[0]*bd[0], ad[2]*bd[2])
                elif m.startswith('punpck'):
                    lane = 0 if m == 'punpcklqdq' else 1
                    expected = struct.pack('<2Q', aq[lane], bq[lane])
                elif m == 'pshufd':
                    expected = struct.pack('<4I', *(bd[(imm >> (2*i)) & 3] for i in range(4)))
                else:
                    expected = struct.pack('<4I', *((0 if imm >= 32 else ((x << imm) & 0xffffffff if m == 'pslld' else x >> imm)) for x in ad))
                assert result.raw[:16] == expected, (m, imm, av.hex(), bv.hex(), result.raw.hex(), expected.hex())
                after, before = struct.unpack_from('<QQ', result.raw, 16)
                assert after & 0x8d5 == before & 0x8d5, (m, 'RFLAGS clobber')
                report['cases'] += 1
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS reviewed host-safe SSE instruction semantics:', json.dumps(report))


if __name__ == '__main__':
    main()
