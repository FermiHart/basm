#!/usr/bin/env python3
"""Bounded NASM comparisons with replayable failures and no crash-as-reject."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--basm', required=True, type=Path)
    parser.add_argument('--elftool', required=True, type=Path)
    parser.add_argument('--nasm', default='nasm')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--count', type=int, default=250)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    if not 1 <= args.count <= 10000 or not 0 <= args.seed <= 0x7fffffff:
        parser.error('count must be 1..10000 and seed 0..2147483647')
    basm, elftool = args.basm.resolve(), args.elftool.resolve()
    nasm = shutil.which(args.nasm)
    if not nasm:
        parser.error('NASM is required for this differential check')
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    generated = subprocess.run(['perl', str(ROOT / 'tests/fuzz/generate.pl'),
                                str(args.seed), str(args.count)],
                               check=True, capture_output=True, timeout=20).stdout
    corpus = [chunk for chunk in generated.split(b'%%CASE%%\n') if chunk.strip()]
    if len(corpus) != args.count:
        raise AssertionError(f'generator returned {len(corpus)} cases, expected {args.count}')
    report = {'schema': 'basm-standalone-differential-v1', 'seed': args.seed,
              'expected_cases': args.count, 'accepted_equal': 0, 'controlled_rejections': 0,
              'failed': 0, 'cases': [], 'basm_sha256': hashlib.sha256(basm.read_bytes()).hexdigest(),
              'nasm_version': subprocess.check_output([nasm, '-v'], text=True).strip(),
              'corpus_sha256': hashlib.sha256(generated).hexdigest()}
    env = dict(os.environ, LC_ALL='C', SOURCE_DATE_EPOCH='0')
    with tempfile.TemporaryDirectory(prefix='basm-differential-') as temp:
        work = Path(temp)
        for index, source in enumerate(corpus):
            src, bobj, nobj = work / 'input.basm', work / 'basm.o', work / 'nasm.o'
            src.write_bytes(source)
            bobj.unlink(missing_ok=True)
            nobj.unlink(missing_ok=True)
            record = {'case': index, 'source_sha256': hashlib.sha256(source).hexdigest()}
            br = nr = None
            try:
                br = subprocess.run([str(basm), '-f', 'elf64', '-o', str(bobj), str(src)],
                                    capture_output=True, env=env, timeout=10)
                nr = subprocess.run([nasm, '-f', 'elf64', '-o', str(nobj), str(src)],
                                    capture_output=True, env=env, timeout=10)
                record.update(basm_rc=br.returncode, nasm_rc=nr.returncode)
                for label, result in [('basm', br), ('nasm', nr)]:
                    if result.returncode not in (0, 1):
                        raise AssertionError(f'{label} crashed or returned unexpected status {result.returncode}')
                    if any(marker in result.stderr for marker in
                           (b'AddressSanitizer', b'UndefinedBehaviorSanitizer', b'runtime error:')):
                        raise AssertionError(f'{label} emitted sanitizer diagnostic')
                if br.returncode == nr.returncode == 1:
                    if bobj.exists():
                        raise AssertionError('rejected source published an object')
                    report['controlled_rejections'] += 1
                    record['result'] = 'controlled-rejection'
                elif br.returncode == nr.returncode == 0:
                    comparison = subprocess.run([str(elftool), 'diff', str(bobj), str(nobj)],
                                                capture_output=True, timeout=10)
                    if any(marker in comparison.stderr for marker in
                           (b'AddressSanitizer', b'UndefinedBehaviorSanitizer', b'runtime error:')):
                        record['comparison_stderr'] = comparison.stderr.decode(errors='replace')
                        raise AssertionError('ELF comparator emitted a sanitizer diagnostic')
                    if comparison.returncode:
                        record['comparison'] = comparison.stdout.decode(errors='replace')
                        raise AssertionError('ELF semantic comparison diverged')
                    report['accepted_equal'] += 1
                    record['result'] = 'equal'
                else:
                    raise AssertionError('acceptance differs within the generated common subset')
            except (AssertionError, subprocess.TimeoutExpired) as exc:
                report['failed'] += 1
                record['result'], record['error'] = 'FAIL', str(exc)
                failure = output / f'case-{index:04d}'
                failure.mkdir()
                for item in work.iterdir():
                    if item.is_file():
                        shutil.copy2(item, failure / item.name)
                for label in ('br', 'nr'):
                    result = locals().get(label)
                    if result is not None:
                        (failure / (label + '.stderr')).write_bytes(result.stderr)
                (failure / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
            report['cases'].append(record)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in
                      ('seed', 'expected_cases', 'accepted_equal', 'controlled_rejections', 'failed')}))
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
