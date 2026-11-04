#!/usr/bin/env python3
"""Data bytes, fixed-section declarations and long relocation-name regressions.

No assembled machine code is executed. Expected bytes and an independent ELF
reader qualify the assertions; --nasm optionally checks the common dialect too.
Failure inputs, diagnostics and prior-output checks remain in the reported path.
"""
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


def elf_sections(data):
    assert data[:7] == b"\x7fELF\x02\x01\x01", "not little-endian ELF64"
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, names_index = struct.unpack_from("<HHH", data, 58)
    assert size == 64 and offset + count * size <= len(data)
    assert names_index < count
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size)
               for i in range(count)]
    names_header = headers[names_index]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    result = []
    for index, row in enumerate(headers):
        assert row[0] < len(names)
        end = names.find(b"\0", row[0])
        assert end >= 0
        result.append({"index": index, "name": names[row[0]:end].decode(),
                       "type": row[1], "flags": row[2], "offset": row[4],
                       "size": row[5], "link": row[6], "info": row[7],
                       "align": row[8], "entsize": row[9]})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--nasm", type=Path, help="optional NASM parity oracle")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    basm = args.basm.resolve()
    nasm = args.nasm.resolve() if args.nasm else None
    output = args.output_dir.resolve() if args.output_dir else Path(
        tempfile.mkdtemp(prefix="basm-data-sections-"))
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    oracle_cases = 0
    sentinel = b"previous object must survive refusal\n"

    def assemble(name, source, expected=None, diagnostic=None, inspect=None):
        nonlocal oracle_cases
        folder = output / name
        folder.mkdir(exist_ok=True)
        (folder / "input.basm").write_text("bits 64\n" + source + "\n")
        fmt = "elf64" if inspect else "bin"
        destination = folder / "output"
        destination.write_bytes(sentinel)
        argv = [str(basm), "--target-profile", "public", "-f", fmt,
                "-o", str(destination), "input.basm"]
        record = {"name": name, "argv": argv, "passed": False}
        cases.append(record)
        try:
            result = subprocess.run(argv, cwd=folder, capture_output=True,
                                    text=True, timeout=20)
            record.update(returncode=result.returncode, stderr=result.stderr)
            (folder / "stderr.txt").write_text(result.stderr)
            actual = destination.read_bytes()
            assert result.returncode >= 0, "terminated by signal"
            assert not any(marker in result.stderr for marker in
                           ("AddressSanitizer", "LeakSanitizer", "runtime error:")), result.stderr
            if diagnostic:
                assert result.returncode != 0, "invalid source was accepted"
                assert diagnostic in result.stderr, "wrong diagnostic: " + result.stderr
                assert actual == sentinel, "refusal replaced the prior output"
                assert not list(folder.glob("output.tmp.*")), "refusal left an owned temporary"
            else:
                assert result.returncode == 0, result.stderr
                if inspect:
                    inspect(actual)
                else:
                    assert actual == expected, ("bytes differ", actual.hex(), expected.hex())
                    if nasm:
                        oracle = subprocess.run([str(nasm), "-f", "bin", "-o", "oracle", "input.basm"],
                                                cwd=folder, capture_output=True, text=True, timeout=20)
                        assert oracle.returncode == 0, oracle.stderr
                        assert (folder / "oracle").read_bytes() == expected, "NASM byte mismatch"
                        oracle_cases += 1
            record["passed"] = True
        except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
            record["error"] = str(error)

    vectors = [
        ("empty", "''", b""),
        ("two", "'ab'", b"ab"),
        ("three", '"abc"', b"abc"),
        ("nine", "'abcdefghi'", b"abcdefghi"),
        ("utf8", "'á∞'", "á∞".encode()),
        ("escaped", r"`A\n\0Z`", b"A\n\0Z"),
        ("hex", r"`\x4\x41\xff`", b"\x04A\xff"),
        ("octal", r"`\0\101\377`", b"\0A\xff"),
    ]
    for directive, width in (("db", 1), ("dw", 2), ("dd", 4), ("dq", 8)):
        for name, spelling, value in vectors:
            expected = value + bytes((-len(value)) % width)
            assemble(directive + "_" + name, directive + " " + spelling, expected)
        # Each string operand pads independently; following scalars preserve
        # their own width and delimiters rather than merging into the string.
        first, second = b"a", b"bc"
        expected = (first + bytes((-len(first)) % width) +
                    second + bytes((-len(second)) % width) + (7).to_bytes(width, "little"))
        assemble(directive + "_list", directive + " 'a','bc',7", expected)

    named = [r"\a", r"\b", r"\e", r"\f", r"\n", r"\r", r"\t", r"\v",
             "\\\\", "\\'", '\\"', "\\`", r"\?"]
    assemble("named_escapes", "db `" + "".join(named) + "`",
             bytes((7, 8, 27, 12, 10, 13, 9, 11, 92, 39, 34, 96, 63)))
    assemble("bounded_escape_digits", r"db `\x4142\1011\08`", b"A42A1\0" + b"8")
    assemble("character_expressions", r"dq `\x41`+1, `\101`+2, `\n`+3",
             struct.pack("<QQQ", 66, 67, 13))
    assemble("string_layout", "section .data\nstart: dw 'abc'\nend: dq end-start", b"abc\0" + struct.pack("<Q", 4))

    for name, escape, diagnostic in (
            ("unicode_short", r"\u0041", "unsupported backtick escape"),
            ("unicode_long", r"\U00000041", "unsupported backtick escape"),
            ("unknown", r"\q", "unsupported backtick escape"),
            ("hex_empty", r"\x", "hexadecimal escape requires"),
            ("hex_invalid", r"\xG", "hexadecimal escape requires"),
            ("octal_overflow", r"\400", "octal escape exceeds")):
        assemble("reject_string_" + name, "dq `" + escape + "`", diagnostic=diagnostic)
        assemble("reject_expression_" + name, "dq `" + escape + "`+1", diagnostic=diagnostic)

    def fixed_metadata(data):
        rows = {row["name"]: row for row in elf_sections(data)}
        for name, kind, flags in ((".text", 1, 6), (".data", 1, 3), (".rodata", 1, 2),
                                  (".bss", 8, 3), (".note.GNU-stack", 1, 0)):
            assert rows[name]["type"] == kind, (name, rows[name])
            assert rows[name]["flags"] == flags, (name, rows[name])
        assert rows[".text"]["align"] == 4

    assemble("canonical_attributes", "\n".join((
        "section .text alloc exec nowrite progbits align=4", "ret",
        "section .text exec", "section .data alloc noexec write progbits", "db 1",
        "section .rodata alloc noexec nowrite progbits", "db 2",
        "section .bss alloc noexec write nobits", "resb 3",
        "section .note.GNU-stack noalloc noexec nowrite progbits")), inspect=fixed_metadata)
    for index, declaration in enumerate((".text noexec", ".text noalloc", ".text write", ".text nobits",
                                          ".data nowrite", ".data exec", ".data nobits", ".bss progbits",
                                          ".rodata write", ".rodata exec", ".note.GNU-stack alloc",
                                          ".note.GNU-stack exec")):
        assemble("reject_canonical_" + str(index), "section " + declaration,
                 diagnostic="canonical section attributes conflict")

    names = ["." + "a" * 253 + suffix for suffix in ("x", "y")]

    def long_relocations(data):
        rows = elf_sections(data)
        by_name = {row["name"]: row for row in rows}
        assert len(by_name) == len(rows), "colliding section names"
        for name in names:
            section, relocation = by_name[name], by_name[".rela" + name]
            assert len(relocation["name"]) == 260
            assert relocation["type"] == 4 and relocation["size"] == 24
            assert relocation["info"] == section["index"], "wrong relocation target section"
            assert relocation["link"] == by_name[".symtab"]["index"]

    assemble("long_relocation_names", "extern other\n" + "\n".join(
        "section " + name + "\ndq other" for name in names), inspect=long_relocations)
    passed = sum(case["passed"] for case in cases)
    report = {"suite": "standalone-data-sections", "passed": passed, "total": len(cases),
              "failed": len(cases) - passed, "nasm_parity_cases": oracle_cases, "cases": cases}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    summary = {key: value for key, value in report.items() if key != "cases"}
    if passed != len(cases) or args.output_dir:
        summary["evidence"] = str(output)
    print(json.dumps(summary))
    if passed != len(cases):
        for case in cases:
            if not case["passed"]:
                print("FAIL " + case["name"] + ": " + case.get("error", "unknown"))
        return 1
    if not args.output_dir:
        shutil.rmtree(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
