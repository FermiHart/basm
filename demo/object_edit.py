#!/usr/bin/env python3
# Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Demonstrate one-byte tampering, then restore the same object in place."""
from pathlib import Path
import struct
import sys


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('flip', 'restore'):
        raise SystemExit('usage: object_edit.py flip|restore hello.o')
    action, path = sys.argv[1], Path(sys.argv[2])
    backup = path.with_name(path.name + '.original')
    before_inode = (path.stat().st_dev, path.stat().st_ino)
    if action == 'flip':
        original = path.read_bytes()
        assert original[:7] == b'\x7fELF\x02\x01\x01'
        table = struct.unpack_from('<Q', original, 40)[0]
        stride, count, names_index = struct.unpack_from('<HHH', original, 58)
        assert stride == 64 and table + count * stride <= len(original)
        sections = [struct.unpack_from('<IIQQQQIIQQ', original, table + i * stride)
                    for i in range(count)]
        names_row = sections[names_index]
        names = original[names_row[4]:names_row[4] + names_row[5]]
        matches = [row for row in sections if names[row[0]:].split(b'\0', 1)[0] == b'.rodata']
        assert len(matches) == 1 and matches[0][5] > 0
        offset = matches[0][4]
        assert offset < len(original)
        with backup.open('xb') as handle:
            handle.write(original)
        old, new = original[offset], original[offset] ^ 1
        with path.open('r+b') as handle:
            handle.seek(offset)
            handle.write(bytes([new]))
        changed = path.read_bytes()
        assert len(changed) == len(original)
        assert sum(a != b for a, b in zip(original, changed)) == 1
        print(f'{path.name}: byte {offset} changed 0x{old:02x} -> 0x{new:02x}')
    else:
        original = backup.read_bytes()
        with path.open('r+b') as handle:
            handle.write(original)
            handle.truncate()
        assert path.read_bytes() == original
        print(f'{path.name}: original bytes restored')
    assert (path.stat().st_dev, path.stat().st_ino) == before_inode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
