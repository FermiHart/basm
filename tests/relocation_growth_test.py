#!/usr/bin/env python3
"""INV-BASM-RELOC-GROWTH-001: exact relocation records and atomic cap refusal."""
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='basm-relocations-') as directory:
        out = Path(directory)
        for count in (4096, 4097, 65536, 65537):
            source = out/'input.basm'
            source.write_text('bits 64\nextern external\nsection .data\n'
                              f'times {count} dq external\n')
            obj = out/'output.o'; obj.write_bytes(b'previous output')
            result = subprocess.run([str(ROOT/'basm'), '-f', 'elf64', str(source),
                                     '-o', str(obj)], capture_output=True, timeout=60)
            if count > 65536:
                assert result.returncode == 1 and b'too many relocations' in result.stderr
                assert obj.read_bytes() == b'previous output'
                continue
            assert result.returncode == 0, result.stderr
            data = obj.read_bytes(); start = struct.unpack_from('<Q', data, 40)[0]
            _, n, names = struct.unpack_from('<HHH', data, 58)
            sections = [struct.unpack_from('<IIQQQQIIQQ', data, start+i*64) for i in range(n)]
            strings = data[sections[names][4]:sections[names][4]+sections[names][5]]
            rela = next(row for row in sections if strings[row[0]:].split(b'\0',1)[0] == b'.rela.data')
            assert rela[5] == count*24
            symtab = sections[rela[6]]
            names = sections[symtab[6]]
            stringtab = data[names[4]:names[4]+names[5]]
            external = next(i for i in range(symtab[5]//24)
                            if stringtab[struct.unpack_from('<I',data,symtab[4]+i*24)[0]:].split(b'\0',1)[0] == b'external')
            for i in range(count):
                offset, info, addend = struct.unpack_from('<QQq', data, rela[4]+i*24)
                assert offset == i*8 and info == (external<<32)|1 and addend == 0
    print('Basm relocations: 4096/4097/65536 exact records, 65537 refusal preserves prior output PASS')


if __name__ == '__main__':
    main()
