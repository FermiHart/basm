#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Run scoped, reproducible local qualification; preserve failures and logs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--basm', required=True, type=Path)
    parser.add_argument('--compat', required=True, type=Path)
    parser.add_argument('--elftool', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    originals = [p.resolve() for p in (args.basm, args.compat, args.elftool)]
    for program in originals:
        if not program.is_file() or not os.access(program, os.X_OK):
            parser.error(f'missing executable: {program}')
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Each invocation owns a fresh directory; previous receipts remain intact.
    evidence = Path(tempfile.mkdtemp(prefix='checks-', dir=output.parent))
    snapshot_dir = evidence / 'bin'
    snapshot_dir.mkdir()
    snapshots, identities = [], {}
    for original, name in zip(originals, ('basm', 'basm-compat', 'elftool')):
        data = original.read_bytes()
        snapshot = snapshot_dir / name
        snapshot.write_bytes(data)
        snapshot.chmod(0o555)
        snapshots.append(snapshot)
        identities[str(original)] = hashlib.sha256(data).hexdigest()
    basm, compat, elftool = snapshots
    report = {'schema': 'basm-standalone-checks-v1', 'platform': platform.platform(),
              'version': (ROOT / 'VERSION').read_text().strip(),
              'scope': 'local standalone host qualification; no Beyond guest claim',
              'binaries': identities,
              'tested_snapshots': {str(p): digest(p) for p in snapshots},
              'evidence': str(evidence), 'suites': []}
    env = dict(os.environ, BASM=str(compat), PUBLIC=str(basm), ELFTOOL=str(elftool),
               LC_ALL='C', SOURCE_DATE_EPOCH='0')
    env.pop('BASM_DDC_COMPILER_HASH', None)
    env.pop('BASM_DDC_COMPILER_PATH', None)

    def record(label, command, timeout=180, public=False):
        child_env = dict(env)
        if public:
            child_env['BASM'] = str(basm)
        before = time.monotonic()
        try:
            result = subprocess.run([str(x) for x in command], cwd=ROOT,
                                    env=child_env, capture_output=True, timeout=timeout)
            rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            rc, stdout, stderr = 124, exc.stdout or b'', exc.stderr or b''
            stderr += b'\nqualification timeout; suite did not pass\n'
        except OSError as exc:
            rc, stdout, stderr = 127, b'', str(exc).encode()
        (evidence / (label + '.stdout')).write_bytes(stdout)
        (evidence / (label + '.stderr')).write_bytes(stderr)
        item = {'name': label, 'command': [str(x) for x in command], 'returncode': rc,
                'seconds': round(time.monotonic() - before, 3), 'status': 'PASS' if rc == 0 else 'FAIL'}
        report['suites'].append(item)
        report['passed'] = sum(r['status'] == 'PASS' for r in report['suites'])
        report['failed'] = sum(r['status'] == 'FAIL' for r in report['suites'])
        (evidence / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        output.write_text(json.dumps(report, indent=2) + '\n')
        print(f"{item['status']} {label} ({item['seconds']}s)", flush=True)
        return rc

    py = sys.executable
    record('isa-generated', ['perl', 'isa/generate.pl', '--check'])
    record('subset-contract', ['sh', 'tests/subset_spec_test.sh'])
    record('cli', [py, 'tests/standalone/test_cli.py', '--basm', basm, '--compat', compat])
    record('data-sections', [py, 'tests/standalone/test_data_sections.py', '--basm', basm,
                            '--nasm', shutil.which('nasm') or 'nasm',
                            '--output-dir', evidence / 'data-sections'])
    record('name-boundaries', [py, 'tests/standalone/test_names.py', '--basm', basm,
                              '--nasm', shutil.which('nasm') or 'nasm',
                              '--output-dir', evidence / 'name-boundaries'])
    record('input-admission', [py, 'tests/campaign/test_inputs.py', '--basm', basm,
                              '--json-out', evidence / 'inputs.json'])
    # This inherited suite explicitly selects public for most cases and also
    # tests the compatibility parser's diagnostic in selector-free cases.
    record('preprocessor', [py, 'tests/campaign/test_preprocessor.py', '--basm', compat,
                           '--output-dir', evidence / 'preprocessor'])
    record('elf-writer', [py, 'tests/campaign/test_writer.py', '--basm', basm])
    record('publication', [py, 'tests/campaign/test_main.py', '--basm', basm])
    record('atomic-publication', [py, 'tests/atomic_publish_test.py', basm])
    # Historical v2 and explicit public/v4 proofs need the compatibility build.
    record('attestation-trust', [py, 'tests/campaign/test_trust.py', '--basm', compat,
                                '--elftool', elftool, '--json', evidence / 'trust.json',
                                '--work-dir', evidence / 'trust-cases'])
    record('layout-stability', ['sh', 'tests/layout_stability_test.sh'])
    record('intent-encoding', ['sh', 'tests/intent_encoding_test.sh'])
    record('intent-trace', ['sh', 'tests/intent_trace_test.sh'], public=True)
    record('intent-cfg', ['sh', 'tests/intent_cfg_test.sh'], public=True)
    for seed in (1, 11):
        record(f'differential-{seed}', [py, 'tests/standalone/test_differential.py',
                                       '--basm', basm, '--elftool', elftool,
                                       '--seed', seed, '--count', '250',
                                       '--output-dir', evidence / f'fuzz-{seed}'])
    record('flat-example', [basm, '-f', 'bin', '-o', evidence / 'bytes.bin', 'examples/bytes.basm'])
    if not (evidence / 'bytes.bin').is_file() or (evidence / 'bytes.bin').read_bytes() != b'BASM\x01\0\0\0':
        record('flat-example-bytes', [py, '-c', 'raise SystemExit("wrong flat bytes")'])
    if platform.system() == 'Linux' and platform.machine() == 'x86_64':
        obj, exe = evidence / 'hello.o', evidence / 'hello'
        if record('hello-assemble', [basm, '-f', 'elf64', '-o', obj, 'examples/hello_linux_x86_64.basm']) == 0:
            if record('hello-link', ['ld', '-o', exe, obj]) == 0:
                record('hello-run', [py, '-c',
                       'import subprocess,sys; r=subprocess.run([sys.argv[1]],capture_output=True,timeout=5); '
                       'assert r.returncode==0 and r.stdout==b"Hello from BearBasm!\\n", (r.returncode,r.stdout,r.stderr)', exe])
    else:
        report['unrun_platform_checks'] = ['hello-link', 'hello-run']
    # Packaging has its own filesystem failure cases and cannot be replaced by assembly tests.
    record('packaging', [py, 'tests/standalone/test_packaging.py'])
    for snapshot in snapshots:
        if digest(snapshot) != report['tested_snapshots'][str(snapshot)]:
            record('artifact-drift-' + snapshot.name,
                   [py, '-c', 'raise SystemExit("tested artifact changed during qualification")'])
    report['status'] = 'PASS' if report['failed'] == 0 else 'FAIL'
    output.write_text(json.dumps(report, indent=2) + '\n')
    (evidence / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'passed': report['passed'],
                      'failed': report['failed'], 'report': str(output)}))
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
