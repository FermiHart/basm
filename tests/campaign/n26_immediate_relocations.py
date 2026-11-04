#!/usr/bin/env python3
"""N26 immediate fields: independent ELF parity, link values and rejection.

NASM is an explicit immutable input. GNU ld links at nonzero addresses; linked
images are read as bytes and never executed. Narrow overflows must fail in both
linkers' inputs. Unsupported product forms are reported separately from parity.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from nasm_elf import compare_elf
from relocation_nasm_test import elf_view, identity

STACK = "section .note.GNU-stack noalloc noexec nowrite progbits align=1\n"
TEXT, DATA, EXTERNAL = 0x401000, 0x600000, 0x12345000


def program(name, rows, bits=64, external=EXTERNAL, text_address=TEXT, prelude="", suffix=""):
    """Rows provide instruction, field width and independently expected value.

    These immediate fields terminate their instruction. End labels locate them
    without deriving an expected opcode length from the implementation.
    """
    source = f"bits {bits}\n" + prelude + "section .text\ndb 0x90,0x90,0x90\n"
    fields = []
    for i, (instruction, width, value) in enumerate(rows):
        label = f"field_{i}"
        source += f"{label}: {instruction}\n{label}_end:\n"
        fields.append({"label": label + "_end", "delta": -width, "width": width,
                       "expected": {"symbol": label} if value == "$" else value})
    return {"name": name, "bits": bits, "source": source + suffix + STACK,
            "external": external, "text_address": text_address, "fields": fields}


def cases():
    rows = []
    for op in ("add", "or", "and", "sub", "xor", "cmp"):
        for reg in ("rax", "rcx", "r8", "r15", "eax", "ecx", "r8d", "r15d"):
            rows.append((f"{op} {reg},external_target+1", 4, EXTERNAL + 1))
    rows += [("test eax,external_target+7", 4, EXTERNAL + 7),
             ("test r9,external_target-3", 4, EXTERNAL - 3),
             ("imul eax,external_target+1", 4, EXTERNAL + 1),
             ("imul r10,external_target-7", 4, EXTERNAL - 7)]
    yield program("wide-register-fields", rows, prelude="extern external_target\n")

    rows = [(f"{op} {reg},external_target-3", width, 0x40 - 3)
            for op in ("mov", "add", "or", "and", "sub", "xor", "cmp", "test")
            for reg, width in (("al", 1), ("ah", 1), ("spl", 1), ("r9b", 1),
                               ("ax", 2), ("cx", 2), ("r9w", 2))]
    rows += [("imul ax,external_target+1", 2, 0x41),
             ("imul r9w,external_target-3", 2, 0x3d),
             ("shl al,external_target+1", 1, 0x41),
             ("shr ax,external_target-3", 1, 0x3d),
             ("sar r9,external_target+1", 1, 0x41),
             ("btr eax,external_target+1", 1, 0x41),
             ("btr r9,external_target+1", 1, 0x41),
             ("int external_target+3", 1, 0x43),
             ("out external_target+1,al", 1, 0x41),
             ("out external_target+1,ax", 1, 0x41),
             ("out external_target+1,eax", 1, 0x41)]
    yield program("narrow-register-fields", rows, external=0x40, prelude="extern external_target\n")

    rows = [(f"{op} {size} [{base}],external_target+1", width, 0x41)
            for op in ("add", "or", "and", "sub", "xor", "cmp")
            for size, base, width in (("byte", "rax", 1), ("word", "r9", 2),
                                      ("dword", "r8+r9*4+16", 4), ("qword", "rbx+8", 4))]
    yield program("memory-immediate-fields", rows, external=0x40, prelude="extern external_target\n")
    yield program("local-section-immediates", [
        ("add rax,local_data+1", 4, DATA + 4),
        ("test r9d,local_data-3", 4, DATA),
        ("imul r10,local_data+7", 4, DATA + 10),
        ("cmp qword [rbx],local_data+1", 4, DATA + 4)],
        suffix="section .data\ndb 1,2,3\nlocal_data: dd 0\n")
    yield program("wide-instruction-anchor", [
        ("add rax,$", 4, "$"), ("test r9,$", 4, "$"), ("imul rax,$", 4, "$"),
        ("add qword [rax],$", 4, "$"), ("lock add qword [rax],$", 4, "$"),
        ("mov qword [fs:eax],$", 4, "$"), ("cmp dword [r8+r9*4+8],$", 4, "$"),
        ("mov qword [rel local_data],$", 4, "$"), ("o64 add rax,$", 4, "$"),
        ("sub rax,$", 4, "$"), ("test rax,$", 4, "$"), ("imul r9,$", 4, "$"),
        ("cmp qword [rel local_data],$", 4, "$"), ("add qword [eax],$", 4, "$"),
        ("mov rax,$", 8, "$"), ("mov eax,$", 4, "$"), ("push $", 4, "$"),
    ], suffix="section .data\nlocal_data: dq 0\n")
    yield program("narrow-instruction-anchor", [
        ("mov al,$", 1, "$"), ("mov ax,$", 2, "$"), ("add al,$", 1, "$"),
        ("test ax,$", 2, "$"), ("imul ax,$", 2, "$"), ("shl al,$", 1, "$"),
        ("btr rax,$", 1, "$"), ("int $", 1, "$"), ("out $,al", 1, "$"),
    ], text_address=0x40)

    for bits in (16, 32, 64):
        yield program(f"word-numeric-mode-{bits}", [
            ("mov ax,0x1234", 2, 0x1234), ("add ax,0x2345", 2, 0x2345),
            ("test ax,0x3456", 2, 0x3456), ("test cx,0x4567", 2, 0x4567),
            ("imul ax,0x5678", 2, 0x5678), ("imul cx,7", 1, 7),
            ("shr ax,2", 1, 2), ("shl eax,3", 1, 3),
        ], bits=bits)
        yield program(f"word-relocations-mode-{bits}", [
            ("mov ax,external_target+3", 2, 0x4003), ("add ax,external_target+1", 2, 0x4001),
            ("test cx,external_target-3", 2, 0x3ffd), ("imul ax,external_target+7", 2, 0x4007),
        ], bits=bits, external=0x4000, prelude="extern external_target\n")

    for bits in (16, 32):
        case = program(f"far-fields-mode-{bits}", [
            ("jmp external_target:7", 2, 0x40),
            ("jmp dword external_target:external_target+3", 2, 0x40),
            ("jmp word external_target:external_target-3", 2, 0x40),
        ], bits=bits, external=0x40, prelude="extern external_target\n")
        case["fields"] += [{"label": "field_1_end", "delta": -6, "width": 4, "expected": 0x43},
                           {"label": "field_2_end", "delta": -4, "width": 2, "expected": 0x3d}]
        yield case

    yield program("dual-memory-and-immediate-bases", [
        ("add qword [abs memory_target+16],external_target-3", 4, EXTERNAL - 3),
        ("cmp qword [rel memory_target],external_target+1", 4, EXTERNAL + 1),
        ("mov qword [rbx+memory_target+8],external_target+7", 4, EXTERNAL + 7),
    ], prelude="extern external_target\nextern memory_target\n")
    yield program("signed32-negative-link", [
        ("add rax,external_target", 4, 0x80000000),
        ("test r9,external_target", 4, 0x80000000),
        ("imul r10,external_target", 4, 0x80000000),
        ("cmp qword [rbx],external_target", 4, 0x80000000),
    ], external=0xffffffff80000000, prelude="extern external_target\n")

    for label, external, instructions, bits in (
        ("u8", 0x100, ("mov al,external_target", "add al,external_target", "test al,external_target",
                         "shl al,external_target", "btr rax,external_target", "int external_target",
                         "out external_target,al", "cmp byte [rax],external_target"), 64),
        ("u16", 0x10000, ("mov ax,external_target", "add ax,external_target", "test ax,external_target",
                           "imul ax,external_target", "cmp word [rax],external_target"), 64),
        ("s32", 0x80000000, ("add rax,external_target", "test r9,external_target", "imul r10,external_target",
                              "cmp qword [rbx],external_target"), 64),
        ("u32", 0x100000000, ("add eax,external_target", "test ecx,external_target", "imul edx,external_target",
                               "cmp dword [rbx],external_target"), 64),
        ("far16", 0x10000, ("jmp external_target:7", "jmp word 8:external_target"), 32),
    ):
        for i, instruction in enumerate(instructions):
            yield {"name": f"link-overflow-{label}-{i}", "bits": bits, "external": external,
                   "link_failure": True, "source": f"bits {bits}\nextern external_target\nsection .text\n{instruction}\n" + STACK}

    core = ("mov al,{e}", "mov ax,{e}", "add rax,{e}", "cmp qword [rbx],{e}", "test r9,{e}",
            "imul r10,{e}", "shl al,{e}", "btr rax,{e}", "int {e}", "out {e},al")
    for i, form in enumerate(core):
        for category, expression, fmt in (("flat-external", "external_target+1", "bin"),
                                           ("scaled-basis", "external_target*2", "elf64")):
            yield {"name": f"reject-{category}-{i}", "bits": 64, "format": fmt, "assembly_failure": True,
                   "source": "bits 64\nextern external_target\nsection .text\n" + form.format(e=expression) + "\n"}

    yield {"name": "flat-symbolic-widths", "bits": 64, "format": "bin", "source": """bits 64
org 0x20
mov al,target
mov ax,target
add rax,target
test ax,target
imul rax,target
shl al,target
btr rax,target
int target
out target,al
cmp qword [rbx],target
target: db 1
"""}
    yield {"name": "flat-cancelled-basis", "bits": 64, "format": "bin", "source": """bits 64
extern external_target
add rax,external_target-external_target+1
imul rax,external_target-external_target+1
shl al,external_target-external_target+1
mov al,external_target-external_target+7
out external_target-external_target+3,al
"""}
    yield {"name": "flat-literal-commas", "bits": 64, "format": "bin", "source": """bits 64
add al,','
test ax,','
imul ax,','
shl al,','
out ',',al
"""}
    for i, instruction in enumerate(("test qword [rax],$", "imul rax,rbx,7", "imul rax,rbx,rcx")):
        yield {"name": f"unsupported-form-{i}", "bits": 64, "product_failure": True,
               "source": "bits 64\nsection .text\n" + instruction + "\n" + STACK}
    for bits in (16, 32):
        for i, instruction in enumerate(("movsx rax,eax", "movsx r8d,ax", "movzx eax,r9b")):
            yield {"name": f"reject-movx-mode-{bits}-{i}", "bits": bits, "assembly_failure": True,
                   "source": f"bits {bits}\nsection .text\n{instruction}\n" + STACK}
    for i, instruction in enumerate(("imul al,7", "test rax,ecx", "test ah,r8b",
        "out rdx,al", "out dx,bl", "out 7,rax", "shl rax,bl", "add rax,7,1", "add qword [rax],7,1",
        "test rax,7,1", "shl rax,7,1", "btr rax,7,1", "int 7,1", "out 7,al,1", "jmp 8:7")):
        yield {"name": f"reject-operands-{i}", "bits": 64, "assembly_failure": True,
               "source": "bits 64\nsection .text\n" + instruction + "\n" + STACK}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--nasm", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--asan-no-leaks", action="store_true")
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    paths = {key: getattr(args, key).resolve() for key in ("basm", "public", "nasm")}
    paths["ld"] = Path(shutil.which("ld")).resolve()
    paths["readelf"] = Path(shutil.which("readelf")).resolve()
    tools_before = {name: identity(path) for name, path in paths.items()}
    dependencies = [Path(__file__), Path(__file__).with_name("nasm_elf.py"),
                    Path(__file__).with_name("relocation_nasm_test.py")]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"}
    if args.asan_no_leaks:
        env.update(ASAN_OPTIONS="detect_leaks=0:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    result = {"schema": "BASM-N26-IMMEDIATE-RELOCATIONS-v1", "status": "RUNNING", "tools": tools_before,
              "generated_code_executed": False, "environment": env, "commands": [], "cases": [],
              "dependencies": [identity(path) for path in dependencies]}
    for path in dependencies:
        shutil.copyfile(path, out / path.name)

    def save():
        (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    def run(name, argv, expected_failure=False):
        argv = [str(x) for x in argv]
        proc = subprocess.run(argv, env=env, cwd=out, capture_output=True, timeout=20)
        stdout, stderr = out / (name + ".stdout"), out / (name + ".stderr")
        stdout.write_bytes(proc.stdout)
        stderr.write_bytes(proc.stderr)
        result["commands"].append({"name": name, "argv": argv, "returncode": proc.returncode,
                                   "expected_failure": expected_failure,
                                   "stdout": identity(stdout), "stderr": identity(stderr)})
        save()
        assert not any(x in proc.stderr for x in (b"AddressSanitizer", b"LeakSanitizer", b"runtime error:")), name + " sanitizer"
        assert (proc.returncode != 0) if expected_failure else (proc.returncode == 0), (name, proc.stderr.decode(errors="replace"))

    try:
        for case in cases():
            name, fmt = case["name"], case.get("format", "elf64")
            src = out / (name + ".asm")
            src.write_text(case["source"])
            item = {"name": name, "source": identity(src), "outputs": {}, "status": "RUNNING"}
            result["cases"].append(item)
            objects = {}
            variants = [("nasm", "nasm", ()) , ("basm", "basm", ())]
            if case["bits"] == 64:
                variants += [("beyond", "basm", ("--target-profile", "beyond")), ("public", "public", ())]
            for variant, assembler, flags in variants:
                key = name + "-" + variant
                obj = out / (key + (".bin" if fmt == "bin" else ".o"))
                objects[variant] = obj
                rejected = case.get("assembly_failure", False) or (assembler != "nasm" and case.get("product_failure", False))
                run(key + "-assemble", [paths[assembler], *flags, "-f", fmt, "-o", obj, src], rejected)
                if rejected:
                    assert not obj.exists(), key + " published output after failed assembly"
                    continue
                item["outputs"][variant] = {"object": identity(obj)}
                if fmt == "bin" or case.get("product_failure"):
                    continue
                run(key + "-readelf", [paths["readelf"], "-hSWsr", obj])
                linked = out / (key + ".elf")
                run(key + "-link", [paths["ld"], "-m", "elf_x86_64", "--defsym",
                    "external_target=" + hex(case.get("external", EXTERNAL)), "--defsym", "memory_target=0x402000",
                    "--section-start=.text=" + hex(case.get("text_address", TEXT)),
                    "--section-start=.data=" + hex(DATA), "-e", "0", "-o", linked, obj], case.get("link_failure", False))
                if case.get("link_failure"):
                    continue
                linked.chmod(0o400)
                sections, symbols = elf_view(linked)
                fields = []
                for field in case.get("fields", []):
                    section = sections[".text"]
                    at = symbols[field["label"]] - section["address"] + field["delta"]
                    width = field["width"]
                    assert 0 <= at <= len(section["bytes"]) - width
                    actual = int.from_bytes(section["bytes"][at:at + width], "little")
                    expected = field["expected"]
                    if isinstance(expected, dict):
                        expected = symbols[expected["symbol"]]
                    fields.append({"label": field["label"], "width": width, "actual": actual, "expected": expected})
                    assert actual == expected, (key, field, actual)
                item["outputs"][variant].update({"linked_image": identity(linked), "fields": fields})
            if case.get("product_failure"):
                item["status"] = "PRODUCT_UNSUPPORTED_NASM_ACCEPTS"
            elif case.get("assembly_failure"):
                item["status"] = "BOTH_REJECTED"
            else:
                for variant in objects.keys() - {"nasm"}:
                    if fmt == "bin":
                        assert objects[variant].read_bytes() == objects["nasm"].read_bytes(), (name, variant, "binary parity")
                    else:
                        parity = compare_elf(objects[variant], objects["nasm"])
                        artifact = out / (name + "-" + variant + "-parity.json")
                        artifact.write_text(json.dumps(parity, indent=2, sort_keys=True) + "\n")
                        item["outputs"][variant]["parity"] = identity(artifact)
                        assert parity["equal"], (name, variant, parity["differences"])
                item["status"] = "LINK_OVERFLOW_REJECTED" if case.get("link_failure") else "PASS"
            save()
        result["tools_unchanged"] = all(identity(path) == tools_before[name] for name, path in paths.items())
        assert result["tools_unchanged"]
        assert [identity(path) for path in dependencies] == result["dependencies"]
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
