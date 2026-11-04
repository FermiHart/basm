#!/usr/bin/env python3
"""Exact assembler names at the 255-byte boundary, including ELF references.

Checks inspect object bytes; they do not execute assembled machine code. Two
names that differ only in byte 255 must remain distinct through declarations,
preprocessing, expression capture and ELF relocation targets. Overlong names
must fail without replacing an existing output. NASM is an optional oracle for
the common positive syntax; it does not define Basm's rejection limits.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from test_data_sections import elf_sections


def elf_object(data):
    sections = elf_sections(data)
    by_name = {row["name"]: row for row in sections}
    assert len(by_name) == len(sections), "colliding section names"

    def contents(row):
        start, size = row["offset"], row["size"]
        assert start + size <= len(data), "section outside object"
        return data[start:start + size]

    table = by_name[".symtab"]
    assert table["entsize"] == 24 and table["size"] % 24 == 0
    strings = contents(sections[table["link"]])
    symbols = []
    for offset in range(0, table["size"], 24):
        name, info, other, section, value, size = struct.unpack_from(
            "<IBBHQQ", data, table["offset"] + offset)
        assert name < len(strings), "invalid symbol string offset"
        end = strings.find(b"\0", name)
        assert end >= 0, "unterminated symbol name"
        symbols.append({"name": strings[name:end].decode(), "binding": info >> 4,
                        "type": info & 15, "section": section, "value": value,
                        "size": size, "other": other})
    relocations = {}
    for row in sections:
        if row["type"] != 4:
            continue
        assert row["link"] == table["index"]
        assert row["entsize"] == 24 and row["size"] % 24 == 0
        entries = []
        for offset in range(0, row["size"], 24):
            position, info, addend = struct.unpack_from("<QQq", data, row["offset"] + offset)
            symbol = symbols[info >> 32]
            entries.append((position, info & 0xffffffff, symbol["name"], addend))
        relocations[sections[row["info"]]["name"]] = entries
    return by_name, symbols, relocations, contents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--nasm", type=Path, help="optional NASM common-syntax oracle")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    basm = args.basm.resolve()
    nasm = args.nasm.resolve() if args.nasm else None
    output = args.output_dir.resolve() if args.output_dir else Path(
        tempfile.mkdtemp(prefix="basm-names-"))
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    oracle_cases = 0
    sentinel = b"previous object must survive refusal\n"

    def assemble(name, source, expected=None, inspect=None, reject=False,
                 options=(), oracle=True):
        nonlocal oracle_cases
        folder = output / name
        folder.mkdir(exist_ok=True)
        source = "bits 64\n" + source + "\n"
        (folder / "input.basm").write_text(source)
        fmt = "elf64" if inspect else "bin"
        destination = folder / "output"
        destination.write_bytes(sentinel)
        argv = [str(basm), "--target-profile", "public", "-f", fmt,
                *options, "-o", str(destination), "input.basm"]
        record = {"name": name, "argv": argv, "passed": False,
                  "input_sha256": hashlib.sha256(source.encode()).hexdigest()}
        cases.append(record)
        try:
            result = subprocess.run(argv, cwd=folder, capture_output=True,
                                    text=True, timeout=20)
            record.update(returncode=result.returncode, stderr=result.stderr)
            (folder / "stdout.txt").write_text(result.stdout)
            (folder / "stderr.txt").write_text(result.stderr)
            actual = destination.read_bytes()
            record["output_sha256"] = hashlib.sha256(actual).hexdigest()
            assert result.returncode >= 0, "terminated by signal"
            assert not any(marker in result.stderr for marker in
                           ("AddressSanitizer", "LeakSanitizer", "runtime error:")), result.stderr
            if reject:
                assert result.returncode != 0, "overlong name was accepted"
                assert result.stderr.strip(), "refusal lacked a diagnostic"
                assert actual == sentinel, "refusal replaced the prior output"
                assert not list(folder.glob("output.tmp.*")), "refusal left an owned temporary"
            else:
                assert result.returncode == 0, result.stderr
                if inspect:
                    inspect(actual)
                else:
                    assert actual == expected, ("bytes differ", actual.hex(), expected.hex())
                if nasm and oracle:
                    oracle_argv = [str(nasm), "-f", fmt, *options,
                                   "-o", "oracle", "input.basm"]
                    reference = subprocess.run(oracle_argv, cwd=folder, capture_output=True,
                                               text=True, timeout=20)
                    (folder / "oracle-stderr.txt").write_text(reference.stderr)
                    record["oracle_argv"] = oracle_argv
                    assert reference.returncode == 0, reference.stderr
                    reference_bytes = (folder / "oracle").read_bytes()
                    if inspect:
                        inspect(reference_bytes)
                    else:
                        assert reference_bytes == expected, "NASM byte mismatch"
                    oracle_cases += 1
            record["passed"] = True
        except (AssertionError, OSError, KeyError, IndexError, ValueError,
                struct.error, subprocess.TimeoutExpired) as error:
            record["error"] = str(error)

    prefix = "n" + "a" * 253
    first, second = prefix + "x", prefix + "y"
    assert len(first) == len(second) == 255
    labels = "section .text\n" + first + ": nop\n" + second + ": ret"

    def verify_named(data, binding=0, defined=True, references=False):
        sections, symbols, relocations, contents = elf_object(data)
        selected = [row for row in symbols if row["name"].startswith(prefix)]
        assert len(selected) == 2, "missing, aliased or duplicate boundary symbols"
        by_name = {row["name"]: row for row in selected}
        assert set(by_name) == {first, second}, "symbol spelling changed"
        for name, value in ((first, 0), (second, 1)):
            row = by_name[name]
            assert row["binding"] == binding, "symbol binding changed"
            assert row["section"] == (sections[".text"]["index"] if defined else 0)
            assert row["value"] == (value if defined else 0)
        if defined:
            assert contents(sections[".text"]) == b"\x90\xc3"
        if references:
            assert contents(sections[".data"]) == bytes(16)
            assert relocations[".data"] == [(0, 1, first, 0), (8, 1, second, 0)], \
                "relocations no longer reference the two complete names"

    assemble("local_labels_255", labels, inspect=verify_named)

    def verify_implicit(data):
        sections, symbols, _, contents = elf_object(data)
        by_name = {row["name"]: row for row in symbols if row["name"].startswith(prefix)}
        assert set(by_name) == {first, second}
        assert [by_name[name]["value"] for name in (first, second)] == [0, 1]
        assert all(row["section"] == sections[".data"]["index"] for row in by_name.values())
        assert contents(sections[".data"]) == b"\x07\x08"

    assemble("implicit_labels_255", "section .data\n" + first + " db 7\n" + second + " db 8",
             inspect=verify_implicit)
    named_references = "\nsection .data\ndq " + first + " wrt ..sym\ndq " + second + " wrt ..sym"
    assemble("global_names_255_references", "global " + first + "\nglobal " + second + "\n" +
             labels + named_references,
             inspect=lambda data: verify_named(data, binding=1, references=True))
    assemble("weak_names_255_references", "weak " + first + "\nweak " + second + "\n" +
             labels + named_references,
             inspect=lambda data: verify_named(data, binding=2, references=True), oracle=False)

    def verify_extern(data):
        verify_named(data, binding=1, defined=False)
        sections, _, relocations, contents = elf_object(data)
        assert contents(sections[".text"]) == b"\x48\xb8" + bytes(8) + b"\x48\xb9" + bytes(8)
        assert relocations[".text"] == [(2, 1, first, 0), (12, 1, second, 0)]

    assemble("extern_names_255_references", "extern " + first + "\nextern " + second +
             "\nsection .text\nmov rax, " + first + "\nmov rcx, " + second, inspect=verify_extern)
    assemble("equ_names_255", first + " equ 7\n" + second + " equ 8\nmov eax, " + first +
             "\nmov ecx, " + second, b"\xb8\x07\0\0\0\xb9\x08\0\0\0")
    emit_pair = "db " + first + ", " + second
    assemble("define_names_255", "%define " + first + " 7\n%define " + second + " 8\n" +
             emit_pair, b"\x07\x08")
    assigns = "%assign " + first + " 7\n%assign " + second + " 8\n"
    assemble("assign_names_255", assigns + emit_pair, b"\x07\x08")
    assemble("assign_update_255", assigns + "%assign " + first + " " + first + "+2\n" +
             emit_pair, b"\x09\x08")
    assemble("assign_in_macro_255", "%macro emit_values 0\n" + assigns + emit_pair +
             "\n%endmacro\nemit_values", b"\x07\x08")
    assemble("cli_definitions_255", emit_pair, b"\x07\x08",
             options=("-D" + first + "=7", "-D", second + "=8"))
    assemble("macro_names_255", "%macro " + first + " 0\ndb 7\n%endmacro\n%macro " +
             second + " 0\ndb 8\n%endmacro\n" + first + "\n" + second, b"\x07\x08")

    scopes = ["g" + "a" * 251 + suffix for suffix in ("x", "y")]

    def verify_qualified(data):
        sections, symbols, _, contents = elf_object(data)
        assert contents(sections[".text"]) == b"\xeb\0\x90\xeb\0\x90"
        by_name = {row["name"]: row for row in symbols}
        for scope, position in zip(scopes, (2, 5)):
            assert len(scope + ".x") == 255
            assert by_name[scope + ".x"]["value"] == position
            assert by_name[scope + ".x"]["section"] == sections[".text"]["index"]

    assemble("qualified_local_255", "section .text\n" + "\n".join(
        scope + ":\njmp .x\n.x: nop" for scope in scopes), inspect=verify_qualified)
    structure = "s" + "a" * 249
    assemble("structure_name_250", "struc " + structure + "\n.x resb 7\nendstruc\nmov eax, " +
             structure + "_size", b"\xb8\x07\0\0\0")
    fields = ["f" + "a" * 251 + suffix for suffix in ("x", "y")]
    assemble("structure_fields_253", "struc S\n." + fields[0] + " resb 7\n." + fields[1] +
             " resb 8\nendstruc\nmov eax, S." + fields[0] + "\nmov ecx, S." + fields[1],
             b"\xb8\0\0\0\0\xb9\x07\0\0\0")

    too_long = first + "z"
    for name, source in (
            ("label", too_long + ": ret"),
            ("global", "global " + too_long + "\nret"),
            ("extern", "extern " + too_long + "\nret"),
            ("weak", "weak " + too_long + "\nret"),
            ("equ", too_long + " equ 7\nret"),
            ("define", "%define " + too_long + " 7\nret"),
            ("assign", "%assign " + too_long + " 7\nret"),
            ("macro", "%macro " + too_long + " 0\nret\n%endmacro\nret"),
            ("section", "section ." + "a" * 255 + "\ndb 1")):
        assemble("reject_" + name + "_256", source, reject=True)
    assemble("reject_cli_definition_256", "ret", reject=True,
             options=("-D", too_long + "=7"))
    assemble("reject_qualified_local_256", "g" + "a" * 253 + ":\n.x: ret", reject=True)
    assemble("reject_local_under_global_255", first + ":\n.local: ret", reject=True)
    assemble("reject_structure_size_name_256", "struc s" + "a" * 250 +
             "\n.x resb 1\nendstruc\nret", reject=True)

    passed = sum(case["passed"] for case in cases)
    report = {"suite": "standalone-names", "passed": passed, "total": len(cases),
              "failed": len(cases) - passed, "nasm_parity_cases": oracle_cases,
              "basm_sha256": hashlib.sha256(basm.read_bytes()).hexdigest(), "cases": cases}
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
