#!/usr/bin/env python3
"""INV-740: exact baseline bytes/diagnostics for code-size sharing. Never execute."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--basm', type=Path, required=True)
    p.add_argument('--before', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True)
    cases = []
    for op in ('vaddps', 'vmulps', 'vxorps', 'vpor', 'vpxor', 'vpcmpeqd'):
        for kind in ('xmm', 'ymm'):
            cases.append('\n'.join(f'{op} {kind}{d},{kind}{s},{kind}{t}' for d, s, t in itertools.product(range(16), repeat=3)))
            cases.append('\n'.join(f'{op} {kind}{d},{kind}{s},[{addr}]' for d, s in itertools.product(range(16), repeat=2)
                                   for addr in ('rax', 'r12+r9*4+128', 'eax+ecx*2', 'fs:rax')))
        cases += [f'{op} {ops}' for ops in ('rax,ymm0,ymm1', 'ymm0,rax,ymm1', 'xmm0,ymm0,ymm1', 'ymm0,xmm0,ymm1', 'ymm0,ymm0,xmm1', 'ymm0,ymm0,1', 'ymm16,ymm0,ymm0', 'ymm0,ymm0,[rax+rcx*3]')]
    byte_regs = 'al cl dl bl ah ch dh bh spl bpl sil dil'.split() + [f'r{i}b' for i in range(8, 16)]
    cases.append('\n'.join(f'set{cc} {r}' for cc in ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g') for r in byte_regs))
    cases += [f'sete {r}' for r in ('ax', 'eax', 'rax', '[rax]', 'xmm0', 'missing')]
    cases += [f'{op} {r}' for op in ('push', 'pop') for r in ('rax', 'r15', 'eax', 'r15d', 'ax', 'al', 'xmm0', 'missing')]
    cases.append('\n'.join(f'mov {seg},{r}\nmov {r},{seg}\nmov rax,[{seg}:{addr}]' for seg in ('es', 'cs', 'ss', 'ds', 'fs', 'gs')
                           for r in ('eax', 'rax', 'r15d', 'r15') for addr in ('rax', 'r12+r9*8-128', 'eax+ecx*2')))
    cases += [f'mov {seg},eax' for seg in ('s', 'as', 'ES', 'ess', 'xs', 'sse', 'g', 'gsx')]
    report = dict(basm=str(a.basm), before=str(a.before), sha256=hashlib.sha256(a.basm.read_bytes()).hexdigest(), cases=0)
    for profile, bits in (('', 64), ('public', 64), ('beyond', 64), ('', 16), ('', 32)):
        for case in cases:
            i = report['cases']
            src, dst = a.out / f'{i}.basm', a.out / f'{i}.out'
            src.write_text(f'bits {bits}\nsection .text\n' + case + '\n')
            results = []
            for arm, tool in (('before', a.before), ('after', a.basm)):
                dst.write_bytes(b'preserved')
                r = subprocess.run([str(tool), *(['--target-profile', profile] if profile else []), '-f', 'elf64', '-o', str(dst), str(src)], capture_output=True, timeout=30)
                (a.out / f'{i}-{arm}.log').write_bytes(r.stdout + r.stderr)
                assert r.returncode in (0, 1)
                results.append((r.returncode, r.stdout, r.stderr, dst.read_bytes()))
            assert results[0] == results[1], (i, profile, bits, case[:200])
            report['cases'] += 1
    (a.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS exact retained VEX/SETcc/stack/segment sharing:', json.dumps(report))


if __name__ == '__main__':
    main()
