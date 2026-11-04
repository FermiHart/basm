#!/usr/bin/env python3
"""Writer regressions: empty tables, deterministic bytes, long symbol tables.

This is an independent ELF reader for the assertions below; it does not call
the writer's own decoder and is not a substitute for the NASM parity gate.
"""
import argparse
import json
import pathlib
import struct
import subprocess
import tempfile


def sections(data):
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    off = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings = struct.unpack_from("<HHH", data, 58)
    assert size == 64 and off + size * count <= len(data)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, off + i * size) for i in range(count)]
    names = data[rows[strings][4]:rows[strings][4] + rows[strings][5]]
    return {names[r[0]:].split(b"\0", 1)[0].decode(): r for r in rows}


def run(basm, directory, name, source):
    path = directory / (name + ".basm")
    out = directory / (name + ".o")
    path.write_text(source)
    command = [basm, "-f", "elf64", "-o", str(out), str(path)]
    subprocess.run(command, check=True, capture_output=True, timeout=30)
    first = out.read_bytes()
    subprocess.run(command, check=True, capture_output=True, timeout=30)
    assert out.read_bytes() == first, "same input changed ELF bytes"
    return first


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--basm", required=True)
    ap.add_argument("--baseline", help="Optional frozen W12 lane for exact-byte comparison")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="basm-writer-") as temporary:
        root = pathlib.Path(temporary)
        empty = run(args.basm, root, "empty", "bits 64\nsection .text\nnop\n")
        sec = sections(empty)
        sym = sec[".symtab"]
        assert empty[sym[4]:sym[4] + 24] == bytes(24), "null symbol leaked state"
        strings = sec[".strtab"]
        assert empty[strings[4]] == 0, "string table lacks the null entry"
        names = ["local_symbol_with_long_name_%06d" % i for i in range(5999, -1, -1)]
        large = run(args.basm, root, "large", "bits 64\nsection .text\n" +
                    "".join(name + ": nop\n" for name in names))
        sec = sections(large)
        string_row, symbol_row = sec[".strtab"], sec[".symtab"]
        strings = large[string_row[4]:string_row[4] + string_row[5]]
        assert len(strings) > 65536
        symbols = []
        for at in range(symbol_row[4], symbol_row[4] + symbol_row[5], 24):
            name, info, other, index, value, extent = struct.unpack_from("<IBBHQQ", large, at)
            assert other == 0
            spelling = strings[name:].split(b"\0", 1)[0].decode()
            if spelling.startswith("local_symbol_"):
                symbols.append((spelling, value))
        assert symbols == list(zip(names, range(len(names)))), "local definition order changed"
        large_string_bytes = len(strings)
        ordered_cases = 0
        comparisons = 0
        # First-intern and definition order differ. Exercise both sides of the
        # tiny-table boundary and multiple merge widths, including a large ELF.
        # These assertions use the independent ELF reader, not symmap_sort.
        for count in (2, 32, 33, 257, 4096):
            source = "bits 64\n" + "".join("static L%d:notype 1\n" % i
                      for i in range(count - 1, -1, -1))
            source += "section .text\n" + "".join("L%d: nop\n" % i
                       for i in range(count)) + "ret\n"
            data = run(args.basm, root, "reverse-%d" % count, source)
            rows = sections(data)
            sr, nr = rows[".symtab"], rows[".strtab"]
            table = data[nr[4]:nr[4] + nr[5]]
            actual = []
            for at in range(sr[4], sr[4] + sr[5], 24):
                name, info, other, index, value, extent = struct.unpack_from("<IBBHQQ", data, at)
                spelling = table[name:].split(b"\0", 1)[0].decode()
                if spelling.startswith("L"):
                    actual.append((spelling, value, info >> 4, extent))
            assert actual == [("L%d" % i, i, 0, 1) for i in range(count)]
            ordered_cases += 1
            if args.baseline:
                before = run(args.baseline, root, "reverse-%d" % count, source)
                assert before == data, "sorting changed W12 ELF bytes"
                comparisons += 1
        print(json.dumps({"suite": "writer", "passed": 4 + ordered_cases,
                          "large_string_table_bytes": large_string_bytes,
                          "reversed_intern_cases": ordered_cases,
                          "w12_exact_byte_comparisons": comparisons}))


if __name__ == "__main__":
    main()
