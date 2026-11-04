#!/usr/bin/env python3
"""INV-740/741: bounded SSE2 and ELF metadata; privileged fixtures never run."""
import argparse
import hashlib
import itertools
import json
import re
from pathlib import Path
import struct
import subprocess

MOVES = ('movaps', 'movups', 'movdqa', 'movdqu')
ARITH = ('paddd', 'paddq', 'pxor', 'por', 'pmuludq', 'punpcklqdq', 'punpckhqdq')
REGS = 'rax rcx rdx rbx rsp rbp rsi rdi'.split() + [f'r{i}' for i in range(8, 16)]


def elf(path):
    b = path.read_bytes()
    assert b[:6] == b'\x7fELF\x02\x01'
    off = struct.unpack_from('<Q', b, 40)[0]
    width, count, ni = struct.unpack_from('<HHH', b, 58)
    assert width == 64
    rows = [struct.unpack_from('<IIQQQQIIQQ', b, off + width*i) for i in range(count)]
    names = b[rows[ni][4]:rows[ni][4]+rows[ni][5]]
    sections = {names[r[0]:names.index(b'\0', r[0])].decode():
                (r, b[r[4]:r[4]+r[5]] if r[1] != 8 else b'') for r in rows}
    symbols = {}
    if '.symtab' in sections:
        tab, data = sections['.symtab']
        st = rows[tab[6]]
        strings = b[st[4]:st[4]+st[5]]
        assert tab[9] == 24
        for offset in range(0, len(data), 24):
            n, info, other, sec, value, size = struct.unpack_from('<IBBHQQ', data, offset)
            symbols[strings[n:strings.index(b'\0', n)].decode()] = (info, other, sec, value, size)
    return sections, symbols


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--basm', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--red', action='store_true')
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True)
    basm = args.basm.resolve()
    report = dict(basm=str(basm), sha256=hashlib.sha256(basm.read_bytes()).hexdigest(),
                  red=args.red, byte_cases=0, gas_cases=0, refusals=0, metadata_cases=0)

    def run(label, argv):
        r = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (out / (label + '.log')).write_bytes(r.stdout + r.stderr)
        return r

    def assemble(label, text, fmt='bin', bad=False, profile='public', explain=False):
        src, dst = out / (label + '.basm'), out / (label + '.' + fmt)
        src.write_text('bits 64\n' + text + '\n')
        dst.write_bytes(b'preserved output')
        opts = ['--target-profile', profile] if profile else []
        r = run(label, [basm, *opts, *(['--explain'] if explain else []), '-f', fmt, '-o', dst, src])
        if bad:
            assert r.returncode == 1 and b'error:' in r.stderr, (label, r.returncode, r.stderr)
            assert dst.read_bytes() == b'preserved output'
            assert not list(out.glob(dst.name + '.tmp.*'))
            report['refusals'] += 1
        else:
            assert r.returncode == 0, (label, r.returncode, r.stderr)
        return src, dst, r

    def parity(label, texts, profile='public', gas=True):
        src, dst, _ = assemble(label, 'section .text\n' + '\n'.join(texts), profile=profile)
        oracle = out / (label + '.nasm.bin')
        r = run(label + '-nasm', ['nasm', '-f', 'bin', '-o', oracle, src])
        assert r.returncode == 0, r.stderr
        assert dst.read_bytes() == oracle.read_bytes(), label
        count = sum(1 for text in texts for line in text.splitlines() if not line.startswith('target:'))
        report['byte_cases'] += count
        if profile == 'public' and gas:
            gas, obj = out / (label + '.S'), out / (label + '.gas.o')
            text = src.read_text().replace('bits 64', '.intel_syntax noprefix\n.code64').replace('section .text', '.text')
            text = text.replace('[rel ', '[rip+')
            text = re.sub(r'\[(es|cs|ss|ds|fs|gs):', r'\1:[', text)
            text = re.sub(r'times (\d+) db 0', r'.zero \1', text)
            gas.write_text(text)
            r = run(label + '-gas', ['as', '--64', '-o', obj, gas])
            assert r.returncode == 0, r.stderr
            assert elf(obj)[0]['.text'][1] == dst.read_bytes(), label + '-gas'
            report['gas_cases'] += count

    required = [f'{m} xmm15,xmm8' for m in (*MOVES, *ARITH)]
    required += ['movq xmm9,rax', 'movq r15,xmm10', 'movq xmm8,[rdx]', 'movq [rdx],xmm8',
                 'pslld xmm15,16', 'psrld xmm8,25', 'pshufd xmm15,xmm8,0x32']
    if args.red:
        for i, text in enumerate(required):
            assemble(f'red-simd-{i}', text, bad=True)
        for i, text in enumerate(('global foo:data 4096\nsection .rodata\nfoo: times 4096 db 0',
                                  'global kernel_info:hidden\nsection .rodata\nkernel_info: dd 1')):
            assemble(f'red-symbol-{i}', text, 'elf64', bad=True)
        _, target, _ = assemble('red-note', 'section .note.Linux alloc noexec nowrite note align=4\ndd 1', 'elf64')
        assert elf(target)[0]['.note.Linux'][0][1] != 7, 'baseline already emits SHT_NOTE'
        report['metadata_cases'] += 1
    else:
        texts = [f'{m} xmm{a},xmm{b}' for m in (*MOVES, *ARITH) for a, b in itertools.product(range(16), repeat=2)]
        texts += [f'movq xmm{x},{r}\nmovq {r},xmm{x}' for x in range(16) for r in REGS]
        texts += [f'{m} xmm{x},{i}' for m in ('pslld', 'psrld') for x in range(16) for i in (0, 1, 7, 8, 12, 16, 20, 24, 25, 31, 32, 255)]
        texts += [f'pshufd xmm{a},xmm{b},{i}' for a, b in itertools.product(range(16), repeat=2) for i in (0, 0x10, 0x32, 0x39, 0x4e, 0x93, 255)]
        addresses = [f'[{r}{d:+}]' for r in REGS for d in (-2147483648, -129, -128, -1, 0, 1, 127, 128, 2147483647)]
        addresses += [f'[{b}+{i}*{s}+128]' for b in REGS for i in REGS if i != 'rsp' for s in (1, 2, 4, 8)]
        for m in (*MOVES, 'movq'):
            for x in range(16):
                texts += [f'{m} xmm{x},{a}\n{m} {a},xmm{x}' for a in addresses]
        # Stay inside the assembler source/trace bounds by using bounded batches.
        for profile in ('', 'public', 'beyond'):
            for i in range(0, len(texts), 4000):
                parity(f'matrix-{profile or "default"}-{i}', texts[i:i+4000], profile)
        for m in (*MOVES, 'movq'):
            parity('rip-' + m, [f'{m} xmm{x},[rel target]\n{m} [rel target+16],xmm{x}' for x in range(16)] + ['target: times 32 db 0'])
            for segments in (('fs', 'gs'), ('es', 'cs', 'ss', 'ds')):
                # GAS elides default legacy segments; NASM is the exact-byte
                # oracle for those ignored long-mode prefixes, not normalized GAS.
                parity('address-prefix-' + m + segments[0], [f'{m} xmm{x},[{seg}:{addr}]\n{m} [{seg}:{addr}],xmm{x}'
                       for x in range(16) for seg in segments
                       for addr in ('eax+ecx*4-128', 'r12+r9*8+128', '4096')], gas=segments[0] == 'fs')
        # PC32 fields against a declared extern, with signed boundary addends.
        reloc_text = 'extern ext\nsection .text\n' + '\n'.join(
            f'{m} xmm{x},[rel ext{d:+}]\n{m} [rel ext{d:+}],xmm{x}'
            for m in (*MOVES, 'movq') for x in range(16) for d in (-2147483648, -128, 0, 127, 2147483647))
        src, target, _ = assemble('relocations', reloc_text, 'elf64')
        oracle = out / 'relocations.nasm.o'
        assert run('relocations-nasm', ['nasm', '-f', 'elf64', '-o', oracle, src]).returncode == 0
        bs, _ = elf(target)
        ns, _ = elf(oracle)
        assert bs['.text'][1] == ns['.text'][1]
        def relas(sections):
            data = sections['.rela.text'][1]
            rows = [struct.unpack_from('<QQq', data, i) for i in range(0, len(data), 24)]
            assert all(info & 0xffffffff == 2 for _, info, _ in rows)
            return [(off, info & 0xffffffff, addend) for off, info, addend in rows]
        assert relas(bs) == relas(ns) and len(relas(bs)) == 800
        report['metadata_cases'] += 800
        for i, text in enumerate(required):
            _, target, r = assemble(f'trace-{i}', text, 'elf64', explain=True)
            trace = json.loads(r.stdout)
            assert trace['semantic_verification'] == 'unimplemented'
            assert trace['records'][0]['form'] is not None
            report['metadata_cases'] += 1
        traces = {}
        for m in MOVES:
            traces[m + '_rr'] = (f'{m} xmm15,xmm8', 'src', 'dst')
            traces[m + '_rm'] = (f'{m} xmm15,[r13+128]', 'memory,src.address', 'dst')
            traces[m + '_mr'] = (f'{m} [r13+128],xmm15', 'dst.address,src', 'memory')
        traces.update({m + '_rr': (f'{m} xmm15,xmm8', 'dst,src', 'dst') for m in ARITH})
        traces.update(movq_rm=('movq xmm15,[r13]', 'memory,src.address', 'dst'),
                      movq_mr=('movq [r13],xmm15', 'dst.address,src', 'memory'),
                      movq_xg=('movq xmm15,r8', 'src', 'dst'), movq_gx=('movq r15,xmm8', 'src', 'dst'),
                      pslld_shift=('pslld xmm15,16', 'dst', 'dst'), psrld_shift=('psrld xmm15,16', 'dst', 'dst'),
                      pshufd_shuf=('pshufd xmm15,xmm8,50', 'src', 'dst'))
        trace_text = '\n'.join(t[0] for t in traces.values()) + '\nlea rax,[rax]\nret'
        for profile in ('public', 'beyond'):
            label = 'trace-contract-' + profile
            _, target, _ = assemble(label, trace_text, 'elf64', profile=profile)
            plain = target.read_bytes()
            _, target, r = assemble(label, trace_text, 'elf64', profile=profile, explain=True)
            assert target.read_bytes() == plain
            trace = json.loads(r.stdout)
            assert trace['semantic_verification'] == 'unimplemented'
            assert trace['coverage']['schema_forms'] == 95 and trace['coverage']['unmodeled'] == 1
            assert not trace['cfg']['complete']
            for record, (name, (_, reads, writes)) in zip(trace['records'], traces.items()):
                assert record['form'] == name and record['control'] == 'next'
                assert {k: record['effects'][k] for k in ('reads', 'writes', 'flags')} == dict(reads=reads, writes=writes, flags='none')
                report['metadata_cases'] += 1
            assert trace['records'][-2]['form'] is None
        note = 'section .note.Linux alloc noexec nowrite note align=4\ndd 6,4,0\ndb "Linux",0\nalignb 4\ndd 0x12345678\nsection .note.Linux\ndd 0'
        _, target, _ = assemble('note', note, 'elf64')
        sections, _ = elf(target)
        sh, data = sections['.note.Linux']
        assert (sh[1], sh[2], sh[8]) == (7, 2, 4)
        assert data == struct.pack('<III', 6, 4, 0) + b'Linux\0\0\0' + struct.pack('<II', 0x12345678, 0)
        symbol_text = 'section .rodata\nglobal page:data 4096\npage: times 4096 db 0\nglobal kernel_info:hidden\nkernel_info: dd 1\nstatic extent:notype 4\nextent: dd 2\nstatic gdt:data 4\ngdt: dd 3\nsection .text\nglobal entry:notype 1\nentry: ret'
        src, target, _ = assemble('symbols', symbol_text, 'elf64')
        sections, syms = elf(target)
        assert syms['page'][0:2] == (0x11, 0) and syms['page'][3:] == (0, 4096)
        assert syms['kernel_info'][0:2] == (0x10, 2) and syms['kernel_info'][3:] == (4096, 0)
        assert syms['extent'][0:2] == (0, 0) and syms['extent'][3:] == (4100, 4)
        assert syms['gdt'][0:2] == (1, 0) and syms['gdt'][3:] == (4104, 4)
        assert syms['entry'][0:2] == (0x10, 0) and syms['entry'][3:] == (0, 1)
        oracle = out / 'symbols.nasm.o'
        assert run('symbols-nasm', ['nasm', '-f', 'elf64', '-o', oracle, src]).returncode == 0
        gas, gas_obj = out / 'symbols.S', out / 'symbols.gas.o'
        gas.write_text('.section .rodata,"a",@progbits\n.globl page\n.type page,@object\n.size page,4096\npage: .zero 4096\n.globl kernel_info\n.hidden kernel_info\nkernel_info: .long 1\n.size extent,4\nextent: .long 2\n.type gdt,@object\n.size gdt,4\ngdt: .long 3\n.text\n.globl entry\n.type entry,@notype\n.size entry,1\nentry: ret\n')
        assert run('symbols-gas', ['as', '--64', '-o', gas_obj, gas]).returncode == 0
        for other in (oracle, gas_obj):
            os, symbols = elf(other)
            for name in ('page', 'kernel_info', 'extent', 'gdt', 'entry'):
                expected, actual = syms[name], symbols[name]
                assert actual[:2] == expected[:2] and actual[3:] == expected[3:]
                assert list(os)[actual[2]] == list(sections)[expected[2]]
        gas, gas_obj = out / 'note.S', out / 'note.gas.o'
        gas.write_text('.section .note.Linux,"a",@note\n.balign 4\n.long 6,4,0\n.asciz "Linux"\n.balign 4\n.long 0x12345678,0\n')
        assert run('note-gas', ['as', '--64', '-o', gas_obj, gas]).returncode == 0
        gs, _ = elf(gas_obj)
        assert gs['.note.Linux'][1] == data
        assert tuple(gs['.note.Linux'][0][i] for i in (1, 2, 8)) == (7, 2, 4)
        report['metadata_cases'] += 12
        bad = [f'{m} {ops}' for m in (*MOVES, *ARITH, 'movq', 'pslld', 'psrld', 'pshufd')
               for ops in ('', 'xmm0', 'ymm0,ymm1', 'xmm16,xmm0', 'xmm0,xmm9999999999999999999', 'xmm0,,xmm1', 'xmm0 xmm1', ',xmm0 xmm1', 'xmm0,xmm1,', 'xmm0,xmm1,junk')]
        bad += [f'{m} xmm0,{v}' for m in ('pslld', 'psrld') for v in ('-1', '256', '4294967296', '1junk', 'missing', '1+0', 'cl', 'xmm1')]
        bad += [f'pshufd xmm0,xmm1,{v}' for v in ('-1', '256', '1junk', 'missing', 'cl')]
        bad += [f'{m} xmm0,[rax]' for m in ARITH]
        bad += [f'{m} xmm0,{a}' for m in MOVES for a in ('[rax+2147483648]', '[rax-2147483649]', '[rax+rsp*2]', '[rax+rcx*3]', '[rax+rcx+rdx]', '[rax-rcx]', '[rax]junk', '[rax+]', '[rax++1]', '[rax+-1]', '[rax+rcx*0]', '[rax+1*4]')]
        bad += [f'{prefix} {text}' for prefix in ('lock', 'rep', 'o64', 'bits 32\n', 'bits 16\n') for text in required]
        attrs = 'alloc noexec nowrite note align=4'
        bad += [f'section .note.Linux {attrs} {a}\ndd 1' for a in ('unknown', 'group=foo', 'GROUP', 'write', 'exec', 'progbits', 'nobits', 'note', 'alloc', 'align=4', 'noalloc', 'align=0', 'align=3', 'align=4294967296', ',')]
        bad += [f'section .note.Linux {attrs}\nsection .note.Linux {a}\ndd 1' for a in ('progbits', 'write', 'exec', 'unknown', 'alloc note align=8')]
        bad += [f'global foo:{a}\nsection .rodata\nfoo: dd 0' for a in ('data -1', 'data 5', 'data 4294967296', 'data 18446744073709551615', 'hidden 4', 'hidden:hidden', 'hiddenjunk', 'data:hidden 4', 'function hidden 4')]
        bad += ['global foo:hidden\nglobal foo\nfoo: dd 0', 'global foo:data 4\nglobal foo:function 4\nfoo: dd 0', 'global foo:hidden\nweak foo\nfoo: dd 0']
        bad += [f'{binding} foo:{typ} {v}\nsection .rodata\nfoo: dd 0' for binding in ('global', 'static') for typ in ('data', 'notype')
                for v in ('', '-1', '5', '4294967296', '9223372036854775807+1', '18446744073709551617-18446744073709551616', 'missing-foo', 'foo', '4,4')]
        bad += ['global foo:hidden\nextern foo', 'static foo:hidden\nfoo: dd 0',
                'movaps xmm0,[rel target-2147483648]\ntarget: db 0\nmovaps xmm0,[rel target-2147483648]']
        for i, text in enumerate(bad):
            for profile in ('', 'public', 'beyond'):
                assemble(f'bad-{i}-{profile or "default"}', text, 'elf64', bad=True, profile=profile)
        # Encoding-only: never execute these ring-0 / transfer fixtures.
        parity('purgatory', ['lgdt [rel target]', 'mov ds,eax', 'mov es,eax', 'mov ss,eax', 'mov fs,eax', 'mov gs,eax', 'retfq', 'jmp [r8+16]', 'jmp [rel target]', 'mov rax,cr0', 'mov cr0,rax', 'mov r8,cr3', 'mov cr3,r8', 'target: times 16 db 0'])
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
