#!/usr/bin/env python3
"""W04/W05 admission and numeric regressions; never execute assembled code.

Accepts an explicitly selected assembler lane. Checks real ELF bytes with an
independent, bounded stdlib reader; rejection must preserve an existing output.
No NASM differential or sovereign provenance is inferred from this test.
"""
import argparse
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
MASK = (1 << 64) - 1
SENTINEL = b"campaign-existing-output-must-survive\n"


def elf_sections(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise AssertionError("assembler did not publish ELF64 little-endian")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    off, stride, count, names_index = header[6], header[11], header[12], header[13]
    if stride != 64 or count > 128 or names_index >= count or off + count * stride > len(data):
        raise AssertionError("invalid section-header bounds")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, off + i * stride) for i in range(count)]
    table = sections[names_index]
    names = data[table[4]:table[4] + table[5]]
    result = {}
    for sec in sections:
        end = names.find(b"\0", sec[0])
        if end < 0:
            raise AssertionError("invalid section name")
        name = names[sec[0]:end].decode("ascii", "strict")
        if sec[1] != 8 and sec[4] + sec[5] > len(data):
            raise AssertionError("section payload out of bounds")
        result[name] = {"size": sec[5], "bytes": b"" if sec[1] == 8 else data[sec[4]:sec[4] + sec[5]]}
    return result


def pack(*values):
    return b"".join(struct.pack("<Q", value & MASK) for value in values)


def cases():
    tests = []
    def ok(name, source, expected, section=".data"):
        tests.append({"name": name, "source": source, "expected": expected, "section": section})
    def bad(name, source, diagnostic=None):
        tests.append({"name": name, "source": source, "diagnostic": diagnostic})

    ok("u64_decimal_hex", "section .data\ndq 18446744073709551615,0xffffffffffffffff\n", pack(MASK, MASK))
    ok("u64_high_bit", "section .data\ndq 9223372036854775808,0x8000000000000000\n", pack(1 << 63, 1 << 63))
    ok("signed_min", "section .data\ndq -9223372036854775808,-0x8000000000000000\n", pack(1 << 63, 1 << 63))
    ok("modular_sum", "section .data\ndq 9223372036854775807+1,0xffffffffffffffff+2\n", pack(1 << 63, 1))
    ok("modular_product_negation", "section .data\ndq (0x8000000000000000*2)+3,-(0x8000000000000000)\n", pack(3, 1 << 63))
    ok("logical_right_shift", "section .data\ndq -1>>1,0x8000000000000000>>63\n", pack(MASK >> 1, 1))
    ok("shift_boundaries", "section .data\ndq -1<<1,1<<63,5<<0,9>>0\n", pack(MASK - 1, 1 << 63, 5, 9))
    ok("operator_precedence", "section .data\ndq ((3+4)*5)<<2,255&15^3|128\n", pack(140, 140))
    ok("unary_plus", "section .data\ndq +1,-(-1),+0x7fffffffffffffff\n", pack(1, 1, (1 << 63) - 1))
    ok("character_expression", "section .data\ndb 'a'+1,'b' + 1\n", b"bc")
    ok("comma_unary_values", "section .data\ndb 1, -2, +3, 'a', +1\n", bytes([1, 254, 3, 97, 1]))
    ok("quoted_data", "section .data\ndb \"a;b,c\",`a\\`b`,\"\",7\n", b"a;b,ca`b\x07")
    ok("parenthesis_valid", "section .data\ndq " + "(" * 100 + "1" + ")" * 100 + "\n", pack(1))
    ok("checked_count_small", "section .data\nresb -1 + 3\ntimes (2 + 1) db 7\n", b"\0\0\x07\x07\x07")
    ok("checked_align_valid", "section .data\ndb 7\nalign (1 << 4)\ndb 8\n", b"\x07" + b"\x90" * 15 + b"\x08")
    ok("checked_zero_reserve", "section .data\nresq 0\ndb 7\n", b"\x07")
    ok("incbin_snapshot_slice", 'section .data\nincbin "payload.bin", 1 + 1, (2 + 1)\n', bytes([2, 3, 4]))
    ok("incbin_quoted_comma", 'section .data\nincbin "payload,bytes.bin", 1, 2\n', bytes([1, 2]))
    ok("incbin_empty_past_end", 'section .data\nincbin "payload.bin", 999, 0\ndb 7\n', b"\x07")
    ok("deferred_include_nested", '%macro LOAD 0\n%include "level1.inc"\n%endmacro\nsection .data\nLOAD\n', bytes([11, 12]))
    ok("deferred_include_dead", '%macro LOAD 0\n%if 0\n%include "missing-file.inc"\n%endif\n%endmacro\nsection .data\nLOAD\ndb 7\n', b"\x07")
    ok("relative_field_cross_section", "section .text\nglobal target\ntarget:\nnop\nret\nsection .data\ndd target + 1 - $\n", b"\0" * 4)
    ok("relative_field_same_section", "section .data\nfirst: db 7\ndd first - $\n", b"\x07" + b"\xff" * 4)
    ok("expression_cache_capacity", "section .data\n" + "".join(f"dq ({i}*3+7)\n" for i in range(1200)), pack(*(i*3+7 for i in range(1200))))
    ok("data_and_size_cache_domains", "section .data\ndq 1+2\ntimes 1+2 db 7\n", pack(3) + b"\x07" * 3)

    for op in ("extern", "weak", "align", "alignb", "incbin", "default", "org", "db", "dw", "dd", "dq", "resb"):
        bad("arity_first_" + op, op + "\n")
        bad("arity_after_section_" + op, "section .text\n" + op + "\n")
    for op in ("extern", "weak", "default"):
        good_arg = "rel" if op == "default" else "foo"
        bad("arity_extra_" + op, "section .text\n" + op + " " + good_arg + " ignored\n")
    for value in ("18446744073709551616", "0x10000000000000000", "999999999999999999999999999999999", "0x"):
        bad("literal_reject_" + value, "section .data\ndq " + value + "\n")
    for value in ("1<<64", "1<<-1", "1>>64", "1>>-1"):
        bad("shift_reject_" + value.replace("<", "L").replace(">", "R"), "section .data\ndq " + value + "\n", "shift out of range")
    bad("checked_align_narrowing", "section .data\ndb 7\nalign 4294967297\ndb 8\n")
    bad("checked_reserve_wrapped_sum", "section .data\nresb 9223372036854775807+9223372036854775807+3\n")
    bad("checked_reserve_wrapped_product", "section .data\nresb 4611686018427387904*4\n")
    bad("checked_reserve_unsigned_literal", "section .data\nresb 0xffffffffffffffff+2\n")
    bad("checked_reserve_shift_overflow", "section .data\nresb 1<<63\n")
    bad("checked_negative_reserve", "section .data\nresb -1\n")
    bad("checked_times_product", "section .data\ntimes 4294967296 resq 4294967296\n")
    bad("size_cache_does_not_hide_wrap", "section .data\ndq 0xffffffffffffffff+2\ntimes 0xffffffffffffffff+2 db 7\n")
    bad("unmatched_paren", "section .data\ndb (1\n")
    bad("extra_paren", "section .data\ndb 1)\n")
    bad("unclosed_quote", 'section .data\ndb "unterminated\n')
    bad("unclosed_backtick_escape", "section .data\ndb `abc\\\n")
    bad("unclosed_memory", "section .text\nmov rax,[rbx\n")
    bad("extra_memory_close", "section .text\nmov rax,[rbx]]\n")
    bad("recursive_unary_budget", "section .data\ndq " + "-" * 140 + "1\n", "expression nesting too deep")
    bad("separate_numeric_terms", "section .data\nresb 1 2\n")
    bad("data_missing_comma", "section .data\ndb 1 2\n")
    bad("data_trailing_comma", "section .data\ndb 1,\n")
    bad("data_empty_item", "section .data\ndb 1,,2\n")
    bad("data_operator_before_comma", "section .data\ndb 1+,2\n")
    bad("incbin_missing_skip", 'section .data\nincbin "payload.bin",,1\n')
    bad("incbin_negative_count", 'section .data\nincbin "payload.bin",0,-1\n')
    bad("incbin_extra_argument", 'section .data\nincbin "payload.bin",0,1,2\n')
    bad("incbin_count_overflow", 'section .data\nincbin "payload.bin",0,0xffffffffffffffff+2\n')
    bad("bss_symbol_narrowing", "section .bss\nresb 4294967296\nlabel:\n")
    bad("section_name_truncation", "section ." + "x" * 255 + "\ndb 7\n")
    bad("source_nul", b"section .data\ndb 7\0\ndb 8\n")
    bad("include_nul", '%include "nul.inc"\n')

    rng = random.Random(4305)
    expressions = []
    expected = bytearray()
    for _ in range(48):
        a, b = rng.getrandbits(64), rng.getrandbits(64)
        shift = rng.randrange(64)
        for text, value in ((str(a), a), (hex(a), a), (f"({a}+{b})", a+b),
                            (f"({a}*{b})", a*b), (f"({a}>>{shift})", a>>shift)):
            expressions.append("dq " + text)
            expected.extend(pack(value))
    ok("deterministic_u64_properties", "section .data\n" + "\n".join(expressions) + "\n", bytes(expected))
    return tests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, default=Path(os.environ.get("BASM", ROOT / "basm")))
    parser.add_argument("--profiles", default="public", help="comma-separated public,beyond,compatibility")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--filter", default="")
    args = parser.parse_args()
    binary = args.basm.resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix="basm-inputs-w04-") as tmp:
        workspace = Path(tmp)
        (workspace / "payload.bin").write_bytes(bytes(range(16)))
        (workspace / "payload,bytes.bin").write_bytes(bytes(range(16)))
        (workspace / "level1.inc").write_text('db 11\n%include "level2.inc"\n')
        (workspace / "level2.inc").write_text("db 12\n")
        (workspace / "nul.inc").write_bytes(b"section .data\ndb 7\0\ndb 8\n")
        for profile in args.profiles.split(","):
            if profile not in ("public", "beyond", "compatibility"):
                parser.error("unknown profile")
            flags = [] if profile == "compatibility" else ["--target-profile", profile]
            for number, case in enumerate(cases()):
                if args.filter and args.filter not in case["name"]:
                    continue
                source = workspace / (f"case-{number}.basm")
                output = workspace / "case.o"
                text = case["source"]
                source.write_bytes(text if isinstance(text, bytes) else text.encode())
                output.write_bytes(SENTINEL)
                start = time.monotonic()
                item = {"name": case["name"], "profile": profile}
                try:
                    proc = subprocess.run([str(binary), *flags, "-f", "elf64", "-o", str(output), str(source)],
                                          cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                    diagnostic=proc.stderr.decode("utf-8", "replace")
                    item.update(rc=proc.returncode, stderr=diagnostic[:1500])
                    assert not any(marker in diagnostic for marker in ("AddressSanitizer", "LeakSanitizer", "runtime error:")), "sanitizer reported a memory/undefined-behavior error"
                    if "expected" in case:
                        assert proc.returncode == 0, "valid source refused"
                        sections = elf_sections(output)
                        actual = sections.get(case["section"], {"bytes": b""})["bytes"]
                        assert actual == case["expected"], f"wrong {case['section']} bytes: got {actual[:80].hex()} expected {case['expected'][:80].hex()}"
                    else:
                        assert proc.returncode == 1, "invalid input did not return a controlled error"
                        assert output.read_bytes() == SENTINEL, "rejection modified existing output"
                        assert proc.stderr, "rejection had no diagnostic"
                        if case.get("diagnostic"):
                            assert case["diagnostic"] in item["stderr"], "wrong diagnostic"
                    item["status"] = "PASS"
                except (AssertionError, OSError, subprocess.TimeoutExpired) as exc:
                    item.update(status="FAIL", reason=str(exc))
                item["seconds"] = round(time.monotonic() - start, 6)
                results.append(item)
                if item["status"] == "FAIL":
                    print(json.dumps(item), flush=True)
    failed = sum(item["status"] == "FAIL" for item in results)
    summary = {"schema": "BASM-W04-W05-INPUT-TEST-v1", "binary": str(binary),
               "executed_generated_code": False, "nasmdifferential": False,
               "cases": len(results), "passed": len(results) - failed, "failed": failed, "results": results}
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"{'FAIL' if failed else 'PASS'} W04/W05 inputs: {len(results)-failed}/{len(results)} cases, profiles={args.profiles}")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
