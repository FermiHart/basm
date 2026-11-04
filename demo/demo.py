#!/usr/bin/env python3
# Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Reproduce the real Hello + OBJECT-evidence demo and retain every command.

Requires Linux x86-64, Python 3, Basm, elftool and GNU ld. Set BASM and ELFTOOL
to explicit executables when they are not on PATH. The destination must be new.
The signing seed is a PUBLIC test-vector fixture, never a release signing key.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

# Public Ed25519 test-vector seed. It contains no production secret.
# demo.pub is provided independently; it is never copied from a proof.
PUBLIC_DEMO_SEED = bytes.fromhex(
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')


def identity(path):
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def executable(value):
    found = shutil.which(value)
    if not found:
        raise SystemExit('required executable is unavailable: ' + value)
    return Path(found).resolve()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path,
                        help='fresh directory for runnable artifacts and events.json')
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    work = args.output_dir.resolve()
    binaries = {'basm': executable(os.environ.get('BASM', 'basm')),
                'elftool': executable(os.environ.get('ELFTOOL', 'elftool')),
                'ld': executable(os.environ.get('DEMO_LINKER', 'ld')),
                'python3': Path(sys.executable).resolve()}
    work.mkdir(parents=True, exist_ok=False)
    (work / 'bin').mkdir()
    (work / 'raw').mkdir()
    for name, binary in binaries.items():
        (work / 'bin' / name).symlink_to(binary)
    for name in ('hello.basm', 'demo.pub', 'other-demo.pub', 'object_edit.py', 'explain_summary.py'):
        shutil.copyfile(source / name, work / name)
    seed = work / 'demo.seed'
    seed.write_bytes(PUBLIC_DEMO_SEED)
    seed.chmod(0o600)
    env = dict(os.environ, PATH=str(work / 'bin') + os.pathsep + os.environ.get('PATH', ''),
               LC_ALL='C', SOURCE_DATE_EPOCH='0')
    record = {
        'schema': 'basm-presentation-capture-v1', 'status': 'RUNNING',
        'started_at': datetime.now(timezone.utc).isoformat(), 'cwd': str(work),
        'platform': 'Linux x86-64 / ELF64',
        'scope': 'The signed v4 proof targets hello.o, an ELF object. The linked hello executable is not attested by this proof.',
        'key_scope': 'Public synthetic demo fixture; never a release signing key. The external public key is provided before signing, not extracted from the proof.',
        'binaries': {name: identity(path) for name, path in binaries.items()},
        'source_files': {name: identity(source / name) for name in
                         ('hello.basm', 'demo.pub', 'other-demo.pub', 'object_edit.py', 'explain_summary.py', 'demo.py')},
        'scenes': [
            {'id': 'hello', 'title': 'A few lines. A real ELF. A real voice.',
             'scope': 'Assemble, audit, link with GNU ld, execute Hello.'},
            {'id': 'evidence', 'title': 'Trust the object. Notice one changed byte.',
             'scope': 'Signed v4 OBJECT evidence, external demo key, tamper, reject, restore, verify.'},
            {'id': 'wrong-key', 'title': 'A signature is not permission.',
             'scope': 'Optional: a different external public key is rejected.'},
            {'id': 'explain', 'title': 'See what was assembled.',
             'scope': 'Selected fields from actual --explain; semantic verification is unimplemented.'}],
        'events': [], 'checks': {},
    }
    receipt = work / 'events.json'

    def checkpoint():
        receipt.write_text(json.dumps(record, indent=2) + '\n')

    def run(scene, label, argv, expected=0, display=None, stdout_file=None):
        event = {'id': label, 'scene': scene, 'argv': argv, 'cwd': str(work),
                 'display_command': display or shlex.join(argv),
                 'expected_returncode': expected}
        print('$ ' + event['display_command'], flush=True)
        start = time.monotonic()
        result = subprocess.run(argv, cwd=work, env=env, capture_output=True, timeout=30)
        event.update(returncode=result.returncode, seconds=round(time.monotonic() - start, 6),
                     stdout=result.stdout.decode('utf-8'), stderr=result.stderr.decode('utf-8'),
                     stdout_base64=base64.b64encode(result.stdout).decode(),
                     stderr_base64=base64.b64encode(result.stderr).decode())
        out, err = work / 'raw' / (label + '.stdout'), work / 'raw' / (label + '.stderr')
        out.write_bytes(result.stdout)
        err.write_bytes(result.stderr)
        event['stdout_file'], event['stderr_file'] = str(out.relative_to(work)), str(err.relative_to(work))
        if stdout_file:
            (work / stdout_file).write_bytes(result.stdout)
            event['stdout_redirected_to'] = stdout_file
        else:
            sys.stdout.write(event['stdout'])
        sys.stderr.write(event['stderr'])
        record['events'].append(event)
        checkpoint()
        if result.returncode != expected:
            raise RuntimeError(label + ': unexpected exit status ' + str(result.returncode))
        return result

    try:
        checkpoint()
        run('hello', 'version', ['basm', '--version'])
        run('hello', 'assemble', ['basm', '-f', 'elf64', '-o', 'hello.o', 'hello.basm'])
        run('hello', 'audit-object', ['elftool', 'audit', 'hello.o'])
        run('hello', 'link', ['ld', '-o', 'hello', 'hello.o'])
        hello = run('hello', 'run-hello', ['./hello'])
        assert hello.stdout == b'Hello from BearBasm!\n'
        record['checks']['hello_stdout_exact'] = True
        run('evidence', 'sign-object',
            ['basm', '--target-profile', 'public', '-f', 'elf64', '-o', 'hello.o',
             '--emit-attestation-v4', 'hello.basmproof', '--sign', 'demo.seed', 'hello.basm'],
            display='basm --target-profile public -f elf64 -o hello.o \\\n  --emit-attestation-v4 hello.basmproof \\\n  --sign demo.seed hello.basm')
        verify = ['elftool', 'attest', '--trusted-key', 'demo.pub', '--tool', 'bin/basm', 'hello.basmproof']
        verify_display = 'elftool attest --trusted-key demo.pub \\\n  --tool bin/basm hello.basmproof'
        run('evidence', 'verify-original', verify, display=verify_display)
        original = (work / 'hello.o').read_bytes()
        inode = (work / 'hello.o').stat().st_ino
        run('evidence', 'flip-one-byte', ['python3', 'object_edit.py', 'flip', 'hello.o'])
        changed = (work / 'hello.o').read_bytes()
        assert len(changed) == len(original) and sum(a != b for a, b in zip(original, changed)) == 1
        assert (work / 'hello.o').stat().st_ino == inode
        record['checks']['tampering'] = {'same_path': 'hello.o', 'same_inode': True,
                                        'changed_bytes': 1, 'bytes': len(original),
                                        'original_sha256': hashlib.sha256(original).hexdigest(),
                                        'modified_sha256': hashlib.sha256(changed).hexdigest()}
        rejected = run('evidence', 'verify-modified', verify, expected=1, display=verify_display)
        assert b'output hash mismatch' in rejected.stdout
        run('evidence', 'restore-original', ['python3', 'object_edit.py', 'restore', 'hello.o'])
        assert (work / 'hello.o').read_bytes() == original
        assert (work / 'hello.o').stat().st_ino == inode
        record['checks']['restored_exact_bytes_same_inode'] = True
        run('evidence', 'verify-restored', verify, display=verify_display)
        wrong = run('wrong-key', 'verify-wrong-key',
                    ['elftool', 'attest', '--trusted-key', 'other-demo.pub', 'hello.basmproof'], expected=1)
        assert b'signature invalid or signer untrusted' in wrong.stdout
        run('explain', 'explain-json',
            ['basm', '--target-profile', 'public', '--explain', '-f', 'elf64', '-o', 'explained.o', 'hello.basm'],
            display='basm --target-profile public --explain \\\n  -f elf64 -o explained.o hello.basm > explained.json', stdout_file='explained.json')
        run('explain', 'explain-summary', ['python3', 'explain_summary.py', 'explained.json'])
        record['artifacts'] = {name: identity(work / name) for name in
                               ('hello.basm', 'hello.o', 'hello.o.original', 'hello', 'hello.basmproof',
                                'demo.pub', 'other-demo.pub', 'explained.o', 'explained.json')}
        record['checks']['proof_output_path_is_object'] = 'output_path: hello.o\n' in (work / 'hello.basmproof').read_text()
        assert record['checks']['proof_output_path_is_object']
        record['status'] = 'COMPLETE'
        return 0
    except Exception as error:
        record['status'] = 'FAILED'
        record['error'] = str(error)
        raise
    finally:
        seed.unlink(missing_ok=True)
        record['synthetic_seed_removed'] = not seed.exists()
        record['completed_at'] = datetime.now(timezone.utc).isoformat()
        checkpoint()


if __name__ == '__main__':
    raise SystemExit(main())
