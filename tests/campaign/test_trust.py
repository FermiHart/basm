#!/usr/bin/env python3
"""W08-W11/W19-W20 integration regressions; never execute generated objects.
Supply an explicitly built product or diagnostic binary; optional elftool must
implement the same evidence formats. All keys are public synthetic test material.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def elf_sections(path):
    data = path.read_bytes()
    shoff = struct.unpack_from('<Q', data, 40)[0]
    stride, count, strings_index = struct.unpack_from('<HHH', data, 58)
    strings, size = struct.unpack_from('<QQ', data, shoff + strings_index * stride + 24)
    names = []
    for i in range(count):
        idx = struct.unpack_from('<I', data, shoff + i * stride)[0]
        names.append(data[strings + idx:data.index(0, strings + idx, strings + size)].decode())
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--basm', required=True, type=Path)
    parser.add_argument('--elftool', type=Path)
    parser.add_argument('--json', type=Path)
    parser.add_argument('--work-dir', type=Path, help='new directory retaining fixtures and failure state')
    args = parser.parse_args()
    basm = args.basm.resolve()
    elftool = args.elftool.resolve() if args.elftool else None
    results = []
    env = dict(os.environ, SOURCE_DATE_EPOCH='0')
    env.pop('BASM_DDC_COMPILER_HASH', None)
    env.pop('BASM_DDC_COMPILER_PATH', None)

    if args.work_dir:
        retained = args.work_dir.resolve()
        retained.mkdir(parents=True, exist_ok=False)
        workspace = contextlib.nullcontext(str(retained))
    else:
        workspace = tempfile.TemporaryDirectory(prefix='basm-campaign-trust-')
    with workspace as name:
        work = Path(name)
        src = work / 'input.basm'
        src.write_text('bits 64\nsection .text\nmov rax,rbx\nret\n')
        seed_a, seed_b = work / 'a.seed', work / 'b.seed'
        seed_a.write_bytes(bytes(range(32)))
        seed_b.write_bytes(bytes(range(32, 64)))
        for key in (seed_a, seed_b):
            key.chmod(0o600)

        def source_state():
            """Observe type/identity without reading devices, FIFOs or huge inputs."""
            try:
                st = src.lstat()
            except FileNotFoundError:
                return {'path': str(src), 'exists': False}
            state = {'path': str(src), 'mode': st.st_mode, 'device': st.st_dev,
                     'inode': st.st_ino, 'bytes': st.st_size, 'mtime_ns': st.st_mtime_ns}
            if src.is_symlink():
                state['symlink_target'] = os.readlink(src)
                try:
                    target = src.stat()
                    state['referent_mode'] = target.st_mode
                    state['referent_device'] = target.st_dev
                    state['referent_inode'] = target.st_ino
                except FileNotFoundError:
                    state['referent_missing'] = True
            elif src.is_file() and st.st_size <= 16 * 1024 * 1024:
                state['sha256'] = hashlib.sha256(src.read_bytes()).hexdigest()
            return state

        def checkpoint():
            if args.json:
                args.json.parent.mkdir(parents=True, exist_ok=True)
                args.json.write_text(json.dumps(results, indent=2) + '\n')

        def command(label, argv, expected=0):
            before = source_state()
            run = subprocess.run([str(x) for x in argv], cwd=work, env=env,
                                 capture_output=True, text=True, timeout=30)
            record = {'name': label, 'returncode': run.returncode, 'expected': expected,
                      'argv': [str(x) for x in argv],
                      'source_before': before, 'source_after': source_state(),
                      'stdout': run.stdout[-2000:], 'stderr': run.stderr[-2000:]}
            results.append(record)
            checkpoint()
            if run.returncode != expected:
                raise AssertionError(json.dumps(record, indent=2))
            return run

        def check(label, condition):
            results.append({'name': label, 'passed': bool(condition)})
            checkpoint()
            if not condition:
                raise AssertionError(label)

        def assemble(label, output, extra=(), source=src):
            return command(label, [basm, '-f', 'elf64', '-o', output, *extra, source])

        def verify(label, proof, expected=0, trusted=None, strict=True):
            extra = ['--trusted-key', trusted] if trusted else []
            mode = '--verify-attestation-strict' if strict else '--verify-attestation'
            command(label, [basm, mode, proof, *extra], expected)
            if elftool:
                strict_flags = ['--strict'] if strict else []
                command(label + '-elftool', [elftool, 'attest', *strict_flags, '--tool', basm,
                                             *extra, proof], expected)

        def unsigned(wire):
            return wire.split('\nsignature_alg: ', 1)[0] + '\nsignature: unsigned\n'

        obj, proof = work / 'legacy.o', work / 'legacy.proof'
        assemble('signed-v2', obj, ['--emit-attestation', proof, '--sign', seed_a])
        verify('v2-valid', proof)
        original = proof.read_text()
        pub_hex = next(line.split(': ', 1)[1] for line in original.splitlines()
                       if line.startswith('signature_pub: '))
        trusted, wrong = work / 'trusted.pub', work / 'wrong.pub'
        trusted.write_text(pub_hex + '\n')
        wrong.write_bytes(bytes(32))
        verify('trusted-correct-key', proof, trusted=trusted)
        verify('trusted-wrong-key', proof, 1, wrong)
        signature_line = next(line for line in original.splitlines(True)
                              if line.startswith('signature: '))
        pub_line = next(line for line in original.splitlines(True)
                        if line.startswith('signature_pub: '))
        alg_line = 'signature_alg: ed25519-over-sha256\n'
        mutations = {
            'duplicate-signature': original + signature_line,
            'duplicate-pub': original + pub_line,
            'duplicate-algorithm': original + alg_line,
            'missing-algorithm': original.replace(alg_line, ''),
            'missing-public-key': original.replace(pub_line, ''),
            'unknown-algorithm': original.replace('ed25519-over-sha256', 'unknown-algorithm'),
            'metadata-after-signature': original + 'build_epoch: 123\n',
            'signature-extra-hex': original.replace(signature_line, signature_line[:-1] + '00\n'),
            'unknown-trailer': original + 'signature_unknown: x\n',
            'embedded-nul': original + '\0hidden\n',
            'unterminated-trailer': original[:-1],
        }
        for label, data in mutations.items():
            malformed = work / (label + '.proof')
            malformed.write_text(data)
            verify(label, malformed, 1)

        unsigned_proof = work / 'unsigned.proof'
        unsigned_proof.write_text(unsigned(original))
        verify('v2-explicit-unsigned', unsigned_proof, strict=False)
        verify('trusted-key-implies-signature', unsigned_proof, 1, trusted, strict=False)
        for label, suffix in {'unsigned-metadata-after-trailer': 'build_epoch: 123\n',
                              'unsigned-duplicate-trailer': 'signature: unsigned\n'}.items():
            malformed = work / (label + '.proof')
            malformed.write_text(unsigned(original) + suffix)
            verify(label, malformed, 1, strict=False)

        fifo = work / 'proof.fifo'
        os.mkfifo(fifo)
        verify('proof-fifo-rejected', fifo, 1)
        verify('trusted-key-fifo-rejected', proof, 1, fifo)
        verify('trusted-key-device-rejected', proof, 1, Path('/dev/zero'))

        source_bytes = src.read_bytes()
        src.unlink()
        os.mkfifo(src)
        verify('source-fifo-rejected', proof, 1, trusted)
        src.unlink()
        src.symlink_to('/dev/zero')
        verify('source-device-rejected', proof, 1, trusted)
        src.unlink()
        with src.open('wb') as f:
            f.truncate(16 * 1024 * 1024 + 1)
        verify('source-over-budget-rejected', proof, 1, trusted)
        src.write_bytes(source_bytes)
        object_bytes = obj.read_bytes()
        with obj.open('wb') as f:
            f.truncate(1024 * 1024 * 1024 + 1)
        verify('output-over-budget-rejected', proof, 1, trusted)
        obj.write_bytes(object_bytes)
        if elftool:
            command('elftool-tool-anchor-device-rejected', [elftool, 'attest', '--tool',
                    '/dev/zero', proof], 1)
            command('elftool-tool-anchor-mismatch', [elftool, 'attest', '--tool',
                    src, proof], 1)

        oversized = work / 'oversized.proof'
        with oversized.open('wb') as f:
            f.truncate(16 * 1024 * 1024 + 1)
        verify('oversized-proof-refused', oversized, 1)

        bad_seed = work / 'trailing-data.seed'
        bad_seed.write_bytes(b'00' * 32 + b' ' * 64 + b'junk')
        old_obj, old_proof = work / 'preserved.o', work / 'preserved.proof'
        old_obj.write_bytes(b'OLD OBJECT')
        old_proof.write_bytes(b'OLD PROOF')
        command('bad-seed-before-publication', [basm, '-f', 'elf64', '-o', old_obj,
                '--emit-attestation', old_proof, '--sign', bad_seed, src], 1)
        check('old-object-preserved', old_obj.read_bytes() == b'OLD OBJECT')
        check('old-proof-preserved', old_proof.read_bytes() == b'OLD PROOF')

        victim, symlink_proof = work / 'unrelated.txt', work / 'symlink.proof'
        victim.write_bytes(b'PRESERVE UNRELATED FILE')
        symlink_proof.symlink_to(victim)
        assemble('proof-symlink-replaced-atomically', work / 'symlink.o',
                 ['--emit-attestation', symlink_proof, '--sign', seed_a])
        check('symlink-victim-not-truncated', victim.read_bytes() == b'PRESERVE UNRELATED FILE')
        check('proof-is-regular-new-generation', not symlink_proof.is_symlink())
        verify('published-symlink-replacement-valid', symlink_proof)

        def cached(label, cache, extra, source=src):
            output = work / (label + '.o')
            run = assemble(label, output, ['--target-profile', 'public', '--rel8-escrow',
                           work / cache, '--rel8-key', seed_a, *extra], source=source)
            return output, 'rel8 escrow hit' in run.stderr

        plain, _ = cached('plain-cold', 'cache-a', [])
        signed, hit = cached('request-proof-after-plain', 'cache-a',
                             ['--emit-exec-proof', '--sign-exec-proof', seed_a])
        check('proof-mode-separates-cache-key', not hit)
        check('requested-proof-present', '.note.TinaProof' in elf_sections(signed))
        check('plain-has-no-proof', '.note.TinaProof' not in elf_sections(plain))
        signed_a, _ = cached('signer-a-cold', 'cache-b', ['--emit-exec-proof', '--sign-exec-proof', seed_a])
        signed_b, hit = cached('signer-b-after-a', 'cache-b', ['--emit-exec-proof', '--sign-exec-proof', seed_b])
        check('signer-separates-cache-key', not hit)
        fresh_b, _ = cached('signer-b-cold', 'cache-c', ['--emit-exec-proof', '--sign-exec-proof', seed_b])
        warm_b, hit = cached('signer-b-warm', 'cache-b', ['--emit-exec-proof', '--sign-exec-proof', seed_b])
        check('same-contract-is-cache-hit', hit)
        check('signer-a-differs', signed_a.read_bytes() != signed_b.read_bytes())
        check('signer-b-cold-warm-identical', signed_b.read_bytes() == fresh_b.read_bytes() == warm_b.read_bytes())
        check('no-persistent-tool-metadata-memo', not list((work / 'cache-b').glob('.tool-*.sha256')))

        receipt = next(path for path in (work / 'cache-b').glob('*.receipt')
                       if ('output_sha256: ' + hashlib.sha256(signed_b.read_bytes()).hexdigest()) in path.read_text())
        receipt.write_text(receipt.read_text().replace('auth_alg: hmac-sha256', 'auth_alg: ignored-algorithm'))
        command('cache-unknown-algorithm-rejected', [basm, '--target-profile', 'public',
                '--rel8-escrow', work / 'cache-b', '--rel8-key', seed_a,
                '--emit-exec-proof', '--sign-exec-proof', seed_b,
                '-f', 'elf64', '-o', work / 'bad-receipt.o', src], 1)
        check('bad-cache-receipt-does-not-publish', not (work / 'bad-receipt.o').exists())

        inc, payload = work / 'dependency.inc', work / 'payload with space.bin'
        inc.write_text('%define VALUE 7\n')
        payload.write_bytes(b'SNAPSHOT PAYLOAD')
        src.write_text('bits 64\n%include "' + str(inc) + '"\nsection .text\nmov eax, VALUE\nret\n'
                       'section .rodata\nincbin "' + str(payload) + '"\n')
        v4 = work / 'closure.proof'
        assemble('signed-v4', work / 'closure.o', ['--target-profile', 'public',
                 '--emit-attestation-v4', v4, '--sign', seed_a])
        verify('v4-valid', v4, trusted=trusted)
        wire = v4.read_text()
        check('v4-header', wire.startswith('basm attestation v4\n'))
        check('v4-three-inputs', 'dependency_count: 3\n' in wire)
        check('v4-no-mock-pqc', 'signature_pqc' not in wire)
        unsigned_v4 = work / 'unsigned-v4.proof'
        unsigned_v4.write_text(unsigned(wire))
        verify('v4-explicit-unsigned', unsigned_v4, strict=False)
        inc.write_text('%define VALUE 9\n')
        verify('v4-detects-include-change', v4, 1, trusted)
        inc.write_text('%define VALUE 7\n')
        payload.write_bytes(b'CHANGED PAYLOAD!')
        verify('v4-detects-incbin-change', v4, 1, trusted)
        payload.write_bytes(b'SNAPSHOT PAYLOAD')
        verify('v4-restored-inputs-valid', v4, trusted=trusted)
        dependency_line = next(line for line in wire.splitlines(True) if line.startswith('dependency: '))
        parser_wire = unsigned(wire)
        for label, data in {
            'v4-duplicate-record': parser_wire.replace(dependency_line, dependency_line * 2, 1),
            'v4-wrong-count': parser_wire.replace('dependency_count: 3', 'dependency_count: 4'),
            'v4-noncanonical-count': parser_wire.replace('dependency_count: 3', 'dependency_count: 03'),
            'v4-missing-config': '\n'.join(line for line in parser_wire.split('\n') if not line.startswith('configuration_sha256: ')),
            'v4-unknown-field': parser_wire.replace('dependency_count: ', 'unknown_dependency_count: '),
            'v4-unknown-kind': parser_wire.replace('dependency: 1 ', 'dependency: 0 ', 1),
            'v4-source-path-mismatch': parser_wire.replace(str(src).encode().hex(), b'/different/input'.hex(), 1),
            'v4-nul-dependency-path': parser_wire.replace(str(src).encode().hex(), '00', 1),
            'v4-placeholder-pqc-rejected': parser_wire.replace('signature: unsigned\n',
                                                             'signature_pqc_alg: dilithium3-placeholder\nsignature: unsigned\n'),
        }.items():
            path = work / (label + '.proof')
            path.write_text(data)
            verify(label, path, 1, strict=False)

        # W20: parser-deferred directives must not disappear behind cache hits.
        # The uncached assembler retains its existing support for these inputs.
        late_src, late_inc = work / 'late.basm', work / 'late.inc'
        late_inc.write_text('mov eax, 1\n')
        late_src.write_text('%macro LOAD 0\n%include "' + str(late_inc) + '"\n%endmacro\n'
                            'section .text\nLOAD\nret\n')
        late_proof = work / 'late.proof'
        assemble('deferred-include-uncached', work / 'late.o', ['--target-profile', 'public',
                 '--emit-attestation-v4', late_proof, '--sign', seed_a], source=late_src)
        verify('deferred-include-v4-valid', late_proof, trusted=trusted)
        for label, cache in (('cold', 'deferred-cold'), ('existing-directory', 'cache-a')):
            output = work / ('deferred-' + label + '.o')
            run = command('deferred-include-cache-refused-' + label, [basm, '--target-profile', 'public',
                          '--rel8-escrow', work / cache, '--rel8-key', seed_a,
                          '-f', 'elf64', '-o', output, late_src], 1)
            check('deferred-include-diagnostic-' + label, 'deferred preprocessor directive' in run.stderr)
            check('deferred-include-no-publication-' + label, not output.exists())
        late_inc.write_text('mov eax, 9\n')
        verify('deferred-include-v4-detects-change', late_proof, 1, trusted)

        late_payload = work / 'late-payload.bin'
        late_payload.write_bytes(b'1234')
        late_src.write_text('%macro SETUP 0\n%define EMBED incbin\n%endmacro\n'
                            'section .rodata\nSETUP\nEMBED "' + str(late_payload) + '"\n')
        assemble('deferred-define-uncached', work / 'late-define.o', source=late_src)
        run = command('deferred-define-cache-refused', [basm, '--rel8-escrow', work / 'cache-a',
                      '--rel8-key', seed_a, '-f', 'elf64', '-o', work / 'late-define-cache.o', late_src], 1)
        check('deferred-define-diagnostic', 'deferred preprocessor directive' in run.stderr)
        late_src.write_text('%macro PICK 0\n%if 1\nincbin "' + str(late_payload) + '"\n'
                            '%else\nincbin "does-not-exist"\n%endif\n%endmacro\nsection .rodata\nPICK\n')
        assemble('deferred-conditional-uncached', work / 'late-conditional.o', source=late_src)
        run = command('deferred-conditional-cache-refused', [basm, '--rel8-escrow', work / 'cache-a',
                      '--rel8-key', seed_a, '-f', 'elf64', '-o', work / 'late-conditional-cache.o', late_src], 1)
        check('deferred-conditional-diagnostic', 'deferred preprocessor directive' in run.stderr)

        # Filename framing is shared with incbin_arguments/filename_token. A
        # decoy prefix makes an independently truncated scanner observable.
        lexical_cases = [
            ('space', work / 'lex payload.bin', work / 'lex', '', ''),
            ('backtick', work / 'lex-backtick\\`tail.bin', work / 'lex-backtick\\', '`', ''),
            ('comment', work / 'lex-comment.bin', work / 'lex-comment.bin;ignored', '', ';ignored'),
        ]
        for label, target, decoy, quote, suffix in lexical_cases:
            target.write_bytes(b'AAAA')
            decoy.write_bytes(b'DECOY')
            lexical_src = work / ('lex-' + label + '.basm')
            lexical_src.write_text('section .rodata\nincbin ' + quote + str(target) + quote + suffix + '\n')
            first, hit = cached('lex-' + label + '-first', 'lex-' + label + '-cache', [], lexical_src)
            check('lex-' + label + '-cold-miss', not hit)
            target.write_bytes(b'BBBB')
            changed, hit = cached('lex-' + label + '-changed', 'lex-' + label + '-cache', [], lexical_src)
            fresh, _ = cached('lex-' + label + '-fresh', 'lex-' + label + '-fresh-cache', [], lexical_src)
            check('lex-' + label + '-actual-input-invalidates', not hit and first.read_bytes() != changed.read_bytes())
            check('lex-' + label + '-cold-warm-parity', changed.read_bytes() == fresh.read_bytes())

        literals_src = work / 'literal-directives.basm'
        literals_src.write_text('section .rodata\n'
                                'db "%include missing", "%define X incbin", "%if 0"\n'
                                '; %include "does-not-exist"\n')
        cached('literal-directives', 'literal-cache', [], literals_src)

        # Combined modes consume one real executable hash, and one digest per
        # immutable dependency, even when the same incbin appears twice.
        combo_src = work / 'combined.basm'
        combo_src.write_text('bits 64\n%include "' + str(inc) + '"\nsection .text\nmov eax, VALUE\nret\n'
                             'section .rodata\nincbin "' + str(payload) + '"\nincbin "' + str(payload) + '"\n')
        combo_obj, combo_proof = work / 'combined.o', work / 'combined.proof'
        for label, expected_hit, expected_tool_reuses in (('cold', 0, 2), ('warm', 1, 1)):
            run = assemble('combined-' + label, combo_obj, ['--target-profile', 'public', '--profile',
                           '--rel8-escrow', work / 'combined-cache', '--rel8-key', seed_a,
                           '--emit-exec-proof', '--sign-exec-proof', seed_a,
                           '--emit-attestation-v4', combo_proof, '--sign', seed_a], source=combo_src)
            verify('combined-' + label + '-valid', combo_proof, trusted=trusted)
            profile = next(line for line in run.stderr.splitlines() if line.startswith('BASM_PROFILE '))
            metrics = dict(token.split('=', 1) for token in profile.split()[1:])
            check('combined-' + label + '-cache-state', int(metrics['cache_hit']) == expected_hit)
            check('combined-' + label + '-tool-hashed-once', int(metrics['hash_tool_calls']) == 1)
            check('combined-' + label + '-tool-reused', int(metrics['hash_tool_reuses']) == expected_tool_reuses)
            check('combined-' + label + '-dependencies-hashed-once', int(metrics['hash_dependency_calls']) == 3)
            check('combined-' + label + '-dependency-reuse', int(metrics['hash_dependency_reuses']) >= 3)

    report = {'schema': 'BASM-CAMPAIGN-TRUST-v1',
              'basm_sha256': hashlib.sha256(basm.read_bytes()).hexdigest(),
              'elftool_sha256': hashlib.sha256(elftool.read_bytes()).hexdigest() if elftool else None,
              'sanitizer_environment': {key: os.environ.get(key) for key in
                                        ('ASAN_OPTIONS', 'UBSAN_OPTIONS', 'LSAN_OPTIONS')},
              'checks': results, 'status': 'PASS', 'object_execution': False}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS trust/cache/evidence:', len(results), 'checks')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
