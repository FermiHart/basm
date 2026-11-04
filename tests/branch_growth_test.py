#!/usr/bin/env python3
"""INV-BASM-BRANCH-GROWTH-001: every large jmp/jcc displacement and cap refusal."""
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='basm-branches-') as directory:
        out = Path(directory)
        for instruction, opcode in (('jmp', b'\xe9'), ('jz', b'\x0f\x84')):
            size = len(opcode)+4
            for count in (8192, 8193, 65536, 65537):
                source = out/'input.basm'
                source.write_text('bits 64\n'+f'{instruction} near target\n'*count+'target: ret\n')
                target = out/'output.bin'; target.write_bytes(b'previous')
                result = subprocess.run([str(ROOT/'basm'), '-f', 'bin', str(source),
                                         '-o', str(target)], capture_output=True, timeout=60)
                if count > 65536:
                    assert result.returncode == 1 and b'too many branches' in result.stderr
                    assert target.read_bytes() == b'previous'
                    continue
                assert result.returncode == 0, result.stderr
                data = target.read_bytes()
                assert len(data) == count*size+1 and data[-1:] == b'\xc3'
                for i in range(count):
                    offset = i*size
                    assert data[offset:offset+len(opcode)] == opcode
                    displacement = struct.unpack_from('<i', data, offset+len(opcode))[0]
                    assert offset+size+displacement == count*size
    print('Basm branches: all jmp/jcc targets at8192/8193/65536 correct;65537 refusal preserves output PASS')


if __name__ == '__main__':
    main()
