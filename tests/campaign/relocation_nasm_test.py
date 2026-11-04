#!/usr/bin/env python3
"""N01-N04 differential relocation regressions; generated ELF is never executed.

Compare complete ET_REL models with the independent benchmark parser, link at
nonzero fixed section addresses, and inspect selected fields against independent
expected addresses. Sources, argv, output streams, artifacts and hashes persist.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from nasm_elf import compare_elf

STACK = "section .note.GNU-stack noalloc noexec nowrite progbits align=1\n"
TEXT, DATA, EXTERNAL = 0x401000, 0x600000, 0x12345000


def identity(path):
    path = Path(path).resolve()
    body = path.read_bytes()
    return {"path": str(path), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def elf_view(path):
    """Read trusted assembler/linker outputs as data, without loading code."""
    raw = path.read_bytes()
    assert raw[:6] == b"\x7fELF\x02\x01"
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    stride, count, string_index = struct.unpack_from("<HHH", raw, 58)
    assert stride == 64 and shoff + count * stride <= len(raw)
    headers = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + i * stride) for i in range(count)]
    h = headers[string_index]
    strings = raw[h[4]:h[4] + h[5]]
    sections, symbols = {}, {}
    for h in headers:
        name = strings[h[0]:].split(b"\0", 1)[0].decode()
        sections[name] = {"address": h[3], "bytes": raw[h[4]:h[4] + h[5]]}
        if h[1] == 2:
            string_header = headers[h[6]]
            names = raw[string_header[4]:string_header[4] + string_header[5]]
            for at in range(h[4], h[4] + h[5], h[9]):
                name_offset, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", raw, at)
                name = names[name_offset:].split(b"\0", 1)[0].decode()
                if name:
                    symbols[name] = value
    return sections, symbols


def cases(wave):
    # section, label, byte offset from label, width, independent expected value
    yield {
        "name": "N01-mov-absolute",
        "source": """bits 64
extern external_target
global exported
section .text
imm64_positive: mov rax,external_target+17
imm64_negative: mov rdx,external_target-9
imm32_positive: mov eax,external_target+3
imm32_negative: mov r9d,external_target-7
imm64_local: mov rbx,local_data+5
imm64_global: mov r10,exported-4
ret
section .data
db 0
local_data: dd 0
exported: dd 0
""" + STACK,
        "fields": [
            (".text", "imm64_positive", 2, 8, EXTERNAL + 17),
            (".text", "imm64_negative", 2, 8, EXTERNAL - 9),
            (".text", "imm32_positive", 1, 4, EXTERNAL + 3),
            (".text", "imm32_negative", 2, 4, EXTERNAL - 7),
            (".text", "imm64_local", 2, 8, DATA + 1 + 5),
            (".text", "imm64_global", 2, 8, DATA + 5 - 4),
        ],
    }
    yield {
        "name": "N01-bin-org-mov", "format": "bin",
        "source": "bits 64\norg 0x7000\nmov rax,target\nmov eax,target+3\ntarget: db 1\n",
    }
    yield {
        "name": "N01-unsigned32-link-range", "link_failure": True,
        "external": 0x100000000,
        "source": "bits 64\nextern external_target\nsection .text\nmov eax,external_target\n" + STACK,
    }
    if wave < 2:
        return
    yield {
        "name": "N02-memory-bases",
        "source": """bits 64
extern external_target
section .text
mem32: mov ecx,[abs external_target+17]
mem64: mov rdx,[abs external_target-9]
base64: mov rax,[rbx+external_target+3]
base32: mov r9d,[eax+external_target-7]
relative: mov r10,[rel external_target+12]
relative_local: lea rax,[rel local_data+3]
absolute_local: mov rcx,[local_data-1]
ret
section .data
db 0
local_data: dd 0
""" + STACK,
        "fields": [
            (".text", "mem32", 3, 4, EXTERNAL + 17),
            (".text", "mem64", 4, 4, EXTERNAL - 9),
            (".text", "base64", 3, 4, EXTERNAL + 3),
            (".text", "base32", 4, 4, EXTERNAL - 7),
            (".text", "absolute_local", 4, 4, DATA),
        ],
    }
    yield {
        "name": "N02-signed32-link-range", "link_failure": True,
        "external": 0x80000000,
        "source": "bits 64\nextern external_target\nsection .text\nmov ecx,[abs external_target]\n" + STACK,
    }
    yield {
        "name": "N02-signed32-negative", "external": 0xffffffff80000000,
        "source": "bits 64\nextern external_target\nsection .text\nnegative: mov ecx,[abs external_target]\n" + STACK,
        "fields": [(".text", "negative", 3, 4, 0x80000000)],
    }
    yield {
        "name": "N02-addr32-unsigned", "external": 0x80000000,
        "source": "bits 64\nextern external_target\nsection .text\nunsigned: mov ecx,[eax+external_target]\n" + STACK,
        "fields": [(".text", "unsigned", 3, 4, 0x80000000)],
    }
    yield {
        "name": "N02-bin-org-memory", "format": "bin",
        "source": "bits 64\norg 0x7000\nmov ecx,[abs target]\nmov rdx,[abs target+1]\ntarget: db 1\n",
    }
    yield {
        "name": "N02-negative-memory-basis", "assembly_failure": True,
        "source": "bits 64\nextern external_target\nsection .text\nmov rax,[rbx-external_target]\n" + STACK,
    }
    if wave < 3:
        return
    yield {
        "name": "N03-data-named-addends",
        "source": """bits 64
extern external_target
section .data
positive32: dd external_target+17
negative32: dd external_target-9
positive64: dq external_target+33
negative64: dq external_target-21
forward32: dd forward+7
forward: db 0
""" + STACK,
        "fields": [
            (".data", "positive32", 0, 4, EXTERNAL + 17),
            (".data", "negative32", 0, 4, EXTERNAL - 9),
            (".data", "positive64", 0, 8, EXTERNAL + 33),
            (".data", "negative64", 0, 8, EXTERNAL - 21),
            (".data", "forward32", 0, 4, DATA + 28 + 7),
        ],
    }
    yield {
        "name": "N03-affine-cancellation",
        "source": """bits 64
section .data
anchor: db 0
other: db 0,0,0
delta equ other-anchor
difference: dd other-anchor
reverse: dd anchor-other
scaled_difference: dq (other-anchor)*7
coefficient_one: dd (2*other-anchor)
translated: dd other+(other-anchor)
zeroed: dd 0*other+19
constant: dd delta*7
""" + STACK,
        "fields": [
            (".data", "difference", 0, 4, 1),
            (".data", "reverse", 0, 4, 0xffffffff),
            (".data", "scaled_difference", 0, 8, 7),
            (".data", "coefficient_one", 0, 4, DATA + 2),
            (".data", "translated", 0, 4, DATA + 2),
            (".data", "zeroed", 0, 4, 19),
            (".data", "constant", 0, 4, 7),
        ],
    }
    yield {
        "name": "N03-memory-immediate-addends",
        "source": """bits 64
extern external_target
section .text
unsigned_field: mov dword [rax],external_target+4
signed_field: mov qword [rbx+8],external_target-9
""" + STACK,
        "fields": [
            (".text", "unsigned_field", 2, 4, EXTERNAL + 4),
            (".text", "signed_field", 4, 4, EXTERNAL - 9),
        ],
    }
    yield {
        "name": "N03-dword-link-range", "link_failure": True,
        "external": 0x100000000,
        "source": "bits 64\nextern external_target\nsection .data\ndd external_target\n" + STACK,
    }
    yield {
        "name": "N03-bin-data-org", "format": "bin",
        "source": "bits 64\norg 0x7000\ndd target+3\ndq target-1\ntarget: db 1\n",
    }
    for suffix, expression in (("negative", "-external_target"),
                               ("scaled", "external_target*2"),
                               ("mask", "external_target&65535"),
                               ("nonlinear", "external_target*external_target")):
        yield {
            "name": "N03-reject-" + suffix, "assembly_failure": True,
            "source": "bits 64\nextern external_target\nsection .data\ndd " + expression + "\n" + STACK,
        }
    yield {
        "name": "N03-global-is-not-extern", "assembly_failure": True,
        "source": "bits 64\nglobal missing\nsection .data\ndd missing\n" + STACK,
    }
    if wave < 4:
        return
    yield {
        "name": "N04-location-counters",
        "source": """bits 64
section .data
anchor: db 0,0,0,0
here: dd $
origin: dq $$
multi: dd $, $+4, $$+8
distance: dd $-$$
from_anchor: dd ($-anchor)
anchor_from_origin: dd anchor-$$
translated: dd $+(anchor-$$)
""" + STACK,
        "fields": [
            (".data", "here", 0, 4, DATA + 4),
            (".data", "origin", 0, 8, DATA),
            (".data", "multi", 0, 4, DATA + 16),
            (".data", "multi", 4, 4, DATA + 20),
            (".data", "multi", 8, 4, DATA + 8),
            (".data", "distance", 0, 4, 28),
            (".data", "from_anchor", 0, 4, 32),
            (".data", "anchor_from_origin", 0, 4, 0),
            (".data", "translated", 0, 4, DATA + 40),
        ],
    }
    yield {
        "name": "N04-location-mov",
        "source": "bits 64\nsection .text\nhere: mov rax,$\norigin: mov edx,$$\n" + STACK,
        "fields": [(".text", "here", 2, 8, TEXT), (".text", "origin", 1, 4, TEXT)],
    }
    yield {
        "name": "N04-bin-counter-org", "format": "bin",
        "source": "bits 64\norg 0x7000\ndb 0,0,0,0\ndd $,$$,$-$$\ndq $$+3\n",
    }
    yield {
        "name": "N04-relative-data-preserved",
        "source": """bits 64
extern external_target
section .text
local_target: ret
section .data
external_relative: dd external_target- $
section_relative: dd local_target+8- $
same_section: dd end- $
end: dd 0
""" + STACK,
        "fields": [
            (".data", "external_relative", 0, 4, EXTERNAL - DATA),
            (".data", "section_relative", 0, 4, (TEXT + 8 - (DATA + 4)) & 0xffffffff),
            (".data", "same_section", 0, 4, 4),
        ],
    }
    yield {
        "name": "N04-thousand-contextual",
        "source": "bits 64\nsection .data\n" + "dd $\n" * 1000 + STACK,
    }
    yield {
        "name": "N04-normalized-consumers",
        "source": """bits 64
extern external_target
section .text
with_delta: mov eax,[rel external_target+(end-start)]
push_external: push external_target+7
push_absolute: push end-start
push_local: push start+1
ret
section .data
start: db 0,0,0,0
end: db 0
""" + STACK,
        "fields": [
            (".text", "with_delta", 2, 4, EXTERNAL + 4 - TEXT - 6),
            (".text", "push_external", 1, 4, EXTERNAL + 7),
            (".text", "push_local", 1, 4, DATA + 1),
        ],
    }
    yield {
        "name": "N04-reject-relative-extra-basis", "assembly_failure": True,
        "source": "bits 64\nextern external_target\nextern other_target\nsection .text\nmov rax,[rel external_target+other_target]\n" + STACK,
    }
    yield {
        "name": "N04-symbol-growth-between-expressions",
        "source": "bits 64\nextern external_target\nsection .data\n" +
                  "".join("L%d: dq external_target+%d\n" % (i, i) for i in range(256)) + STACK,
    }
    yield {
        "name": "N04-times-statement-anchor",
        "source": """bits 64
extern external_target
section .data
db 0,0,0,0
times_here: times 3 dd $
external_fields: times 3 dd external_target- $
""" + STACK,
        "fields": [(".data", "times_here", i * 4, 4, DATA + 4) for i in range(3)] +
                  [(".data", "external_fields", i * 4, 4, EXTERNAL - DATA - 16) for i in range(3)],
    }
    yield {
        "name": "N04-bin-times-counter", "format": "bin",
        "source": "bits 64\norg 0x7000\ntimes 3 dd $\n",
    }
    for suffix, expression, rejected in (
        ("scaled", "external_target*2", True),
        ("negative", "-external_target", True),
        ("sum", "external_target+other", True),
        ("cancel", "external_target-external_target", False),
        ("zero", "0*external_target", False),
        ("balanced", "external_target+other-other-external_target", False),
    ):
        yield {
            "name": "N04-bin-external-" + suffix, "format": "bin",
            "assembly_failure": rejected,
            "source": "bits 64\nextern external_target\nextern other\ndq " + expression + "\n",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", required=True, type=Path)
    parser.add_argument("--nasm", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--wave", type=int, choices=range(1, 5), default=4)
    parser.add_argument("--asan-no-leaks", action="store_true",
                        help="explicit ASan/UBSan run with unavailable LeakSanitizer disabled")
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tool_paths = {"basm": args.basm.resolve(), "nasm": args.nasm.resolve()}
    tool_paths.update({name: Path(shutil.which(name)).resolve() for name in ("ld", "readelf", "objdump")})
    tools_before = {name: identity(path) for name, path in tool_paths.items()}
    result = {"schema": "BASM-NASM-RELOCATIONS-N01-N04-v1", "status": "RUNNING",
              "wave": args.wave, "tools": tools_before, "runner": identity(__file__),
              "entrypoint": identity(Path(sys.argv[0])),
              "parity_checker": identity(Path(__file__).with_name("nasm_elf.py")),
              "generated_code_executed": False, "commands": [], "cases": []}
    for key in ("runner", "parity_checker", "entrypoint"):
        snapshot = out / Path(result[key]["path"]).name
        shutil.copyfile(result[key]["path"], snapshot)
        result[key + "_snapshot"] = identity(snapshot)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"}
    if args.asan_no_leaks:
        env["ASAN_OPTIONS"]="detect_leaks=0:halt_on_error=1"
        env["UBSAN_OPTIONS"]="halt_on_error=1:print_stacktrace=1"
    result["environment"]=env
    result["asan_no_leaks"]=args.asan_no_leaks

    def save():
        (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    def run(name, argv, expect_failure=False):
        argv = [str(x) for x in argv]
        completed = subprocess.run(argv, cwd=out, env=env, capture_output=True, timeout=15)
        stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
        stdout.write_bytes(completed.stdout)
        stderr.write_bytes(completed.stderr)
        combined=completed.stdout+completed.stderr
        markers=[marker for marker in (b"AddressSanitizer",b"UndefinedBehaviorSanitizer",
                 b"LeakSanitizer",b"runtime error:",b"Sanitizer CHECK failed") if marker in combined]
        result["commands"].append({"name": name, "argv": argv, "returncode": completed.returncode,
                                   "expected_failure": expect_failure,
                                   "sanitizer_markers": [marker.decode() for marker in markers],
                                   "stdout": identity(stdout), "stderr": identity(stderr)})
        save()
        assert not markers, (name,"sanitizer diagnostic",markers)
        assert (completed.returncode != 0) if expect_failure else (completed.returncode == 0), name

    try:
        for case in cases(args.wave):
            name, fmt = case["name"], case.get("format", "elf64")
            source = out / (name + ".asm")
            source.write_text(case["source"])
            item = {"name": name, "source": identity(source), "outputs": {}}
            result["cases"].append(item)
            objects = {}
            for assembler in ("basm", "nasm"):
                key = name + "-" + assembler
                obj = out / (key + (".bin" if fmt == "bin" else ".o"))
                objects[assembler] = obj
                assembly_failure=(case.get("assembly_failure",False) or
                    (case.get("basm_only_rejection",False) and assembler=="basm") or
                    (case.get("nasm_only_rejection",False) and assembler=="nasm"))
                preserve_existing=(assembly_failure and assembler=="basm" and
                                   case.get("preserve_existing_basm",False))
                if preserve_existing:
                    prior_output=b"BASM prior published output: must survive rejected input.\n"
                    obj.write_bytes(prior_output)
                    prior_identity=identity(obj)
                run(key + "-assemble", [tool_paths[assembler], "-f", fmt, "-o", obj, source], assembly_failure)
                if assembly_failure:
                    if preserve_existing:
                        assert obj.read_bytes()==prior_output, key + " altered prior output on rejection"
                        item["outputs"][assembler]={"rejected":True,
                            "prior_output":prior_identity,"preserved_existing_output":identity(obj)}
                    else:
                        assert not obj.exists(), key + " published a failed assembly"
                    continue
                item["outputs"][assembler] = {"object": identity(obj)}
                if fmt == "bin":
                    continue
                for utility, flags in (("readelf", ["-hSWsr"]), ("objdump", ["-drw", "-Mintel"])):
                    run(key + "-object-" + utility, [tool_paths[utility], *flags, obj])
                linked = out / (key + ".elf")
                run(key + "-link", [tool_paths["ld"], "-m", "elf_x86_64", "--defsym",
                    "external_target=" + hex(case.get("external", EXTERNAL)),
                    "--section-start=.text=" + hex(TEXT), "--section-start=.data=" + hex(DATA),
                    "-e", "0", "-o", linked, obj], case.get("link_failure", False))
                if case.get("link_failure"):
                    continue
                linked.chmod(0o400)
                run(key + "-linked-readelf", [tool_paths["readelf"], "-hSWsr", linked])
                run(key + "-linked-objdump", [tool_paths["objdump"], "-drw", "-Mintel", linked])
                sections, symbols = elf_view(linked)
                for section_name, expected_hex in case.get("expected_section_hex",{}).items():
                    assert sections[section_name]["bytes"].hex()==expected_hex, (name,assembler,section_name)
                fields = []
                for section_name, label, delta, width, expected in case.get("fields", []):
                    section = sections[section_name]
                    at = symbols[label] - section["address"] + delta
                    assert 0 <= at <= len(section["bytes"]) - width
                    raw = section["bytes"][at:at + width]
                    actual = int.from_bytes(raw, "little")
                    fields.append({"label": label, "width": width, "actual": actual,
                                   "expected": expected, "raw_hex": raw.hex()})
                    assert actual == expected, (name, assembler, label, actual, expected)
                item["outputs"][assembler].update({"linked_image": identity(linked), "fields": fields,
                    "checked_section_bytes":case.get("expected_section_hex",{})})
            if case.get("basm_only_rejection"):
                item["status"] = case.get("rejection_status","EXPECTED_UNSUPPORTED_EQU_FORM")
            elif case.get("nasm_only_rejection"):
                item["status"] = "VALIDATED_BASM_EXTENSION_REFUSED_BY_NASM"
            elif case.get("assembly_failure"):
                item["status"] = "BOTH_REJECTED"
            elif fmt == "bin":
                assert objects["basm"].read_bytes() == objects["nasm"].read_bytes(), name + " binary parity"
                item["status"] = "PASS"
            else:
                parity = compare_elf(objects["basm"], objects["nasm"])
                parity_path = out / (name + "-parity.json")
                parity_path.write_text(json.dumps(parity, indent=2, sort_keys=True) + "\n")
                item["parity"] = identity(parity_path)
                assert parity["equal"], (name, parity["differences"])
                item["status"] = "PASS"
            save()
        result["tools_unchanged"] = all(identity(path) == tools_before[name] for name, path in tool_paths.items())
        assert result["tools_unchanged"]
        assert identity(__file__) == result["runner"]
        assert identity(Path(sys.argv[0])) == result["entrypoint"]
        assert identity(Path(__file__).with_name("nasm_elf.py")) == result["parity_checker"]
        result["status"] = "PASS"
    except Exception as exc:
        result["status"] = "FAIL"
        result["error"] = repr(exc)
        raise
    finally:
        save()
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "result": str(out / "result.json")}))


if __name__ == "__main__":
    main()
