#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Independent, bounded ELF64 / SysV leaf ABI checker.

The interpreter proves only the obligations of the closed model below, under
its explicit entry/environment assumptions. It is not a general x86 decoder,
functional-equivalence prover, signature verifier, linker, or execution sandbox.
It reads object bytes directly. Assembler traces and source maps are not proof.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
import struct
import sys


RESULT_SCHEMA = "bearbasm-contract-result-v1"
MODEL = "x86-64-sysv-leaf-v1"
LIMITS = {
    "object_bytes": 4 * 1024 * 1024,
    "contract_bytes": 65536,
    "target_bytes": 16384,
    "source_bytes": 1024 * 1024,
    "receipt_bytes": 1024 * 1024,
    "sections": 128,
    "symbols": 16384,
    "relocations": 16384,
    "function_bytes": 4096,
    "instructions": 512,
    "states": 512,
    "steps": 2048,
    "stack_bytes": 512,
}
REGS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
REGS32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
          "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d")
CALLEE = (3, 5, 12, 13, 14, 15)
CALLER = (0, 1, 2, 6, 7, 8, 9, 10, 11)
DEFAULT_TARGET = {
    "schema": "bearbasm-contract-target-v1", "domain": "hosted-user",
    "features": ["base"], "os_state": {},
}

# This closed descriptor table is the independent checker's sole instruction
# inventory. --describe exports it. Its semantics are implemented below, not
# imported from the assembler's ISA table or its trace verdict.
FORMS = (
    {"id": "mov_rr", "opcodes": ["89", "8b"], "shape": "rr", "operation": "mov", "widths": [32, 64]},
    {"id": "add_rr", "opcodes": ["01", "03"], "shape": "rr", "operation": "add", "widths": [32, 64]},
    {"id": "sub_rr", "opcodes": ["29", "2b"], "shape": "rr", "operation": "sub", "widths": [32, 64]},
    {"id": "xor_rr", "opcodes": ["31", "33"], "shape": "rr", "operation": "xor", "widths": [32, 64]},
    {"id": "cmp_rr", "opcodes": ["39", "3b"], "shape": "rr", "operation": "cmp", "widths": [32, 64]},
    {"id": "test_rr", "opcodes": ["85"], "shape": "rr", "operation": "test", "widths": [32, 64]},
    {"id": "push_r64", "opcodes": [f"{n:02x}" for n in range(0x50, 0x58)], "shape": "register", "operation": "push", "widths": [64]},
    {"id": "pop_r64", "opcodes": [f"{n:02x}" for n in range(0x58, 0x60)], "shape": "register", "operation": "pop", "widths": [64]},
    {"id": "stack_adjust", "opcodes": ["81", "83"], "shape": "rsp_immediate", "operation": "stack", "widths": [64]},
    {"id": "jmp_rel8", "opcodes": ["eb"], "shape": "relative8", "operation": "jump", "widths": []},
    {"id": "jmp_rel32", "opcodes": ["e9"], "shape": "relative32", "operation": "jump", "widths": []},
    {"id": "jcc_rel8", "opcodes": [f"{n:02x}" for n in range(0x70, 0x80)], "shape": "relative8", "operation": "branch", "widths": []},
    {"id": "jcc_rel32", "opcodes": [f"0f{n:02x}" for n in range(0x80, 0x90)], "shape": "relative32", "operation": "branch", "widths": []},
    {"id": "nop", "opcodes": ["90"], "shape": "fixed", "operation": "nop", "widths": []},
    {"id": "ret", "opcodes": ["c3"], "shape": "fixed", "operation": "ret", "widths": []},
    {"id": "cld", "opcodes": ["fc"], "shape": "fixed", "operation": "cld", "widths": []},
    {"id": "std", "opcodes": ["fd"], "shape": "fixed", "operation": "std", "widths": []},
    {"id": "cpuid", "opcodes": ["0fa2"], "shape": "fixed", "operation": "cpuid", "widths": [],
     "feature": "cpuid", "os_requirement": "cpuid_user_enabled"},
)
OPCODES = {op: form for form in FORMS for op in form["opcodes"]}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Refusal(Exception):
    def __init__(self, code, message, *, status="REJECTED", offset=None, path=None, details=None):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status
        self.offset, self.path, self.details = offset, path, details


def refuse(code, message, **kwargs):
    raise Refusal(code, message, **kwargs)


def read_bounded(path, limit):
    """Read one regular-file descriptor; never follow paths from metadata."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                refuse("INPUT_NOT_REGULAR", "Input must be a regular file")
            if before.st_size > limit:
                refuse("INPUT_LIMIT", "Input exceeds the fixed byte limit", details={"limit": limit})
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(data) > limit or len(data) != before.st_size or identity(before) != identity(after):
            refuse("INPUT_CHANGED", "Input changed during its bounded read")
        return data
    except OSError:
        refuse("INPUT_IO", "Cannot read a requested input")


def load_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                refuse("JSON_DUPLICATE", "Duplicate JSON member")
            result[key] = value
        return result
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=lambda _: refuse("JSON_NUMBER", "Non-finite JSON number"))
    except (UnicodeError, ValueError, RecursionError):
        refuse("JSON_INVALID", "Invalid or excessively nested JSON input")
    # Limit nesting independently of the Python decoder's own recursion ceiling.
    pending = [(result, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 12:
            refuse("JSON_DEPTH", "JSON nesting exceeds the fixed limit")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return result


def exact_keys(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        refuse("SCHEMA_MEMBERS", "Missing or unknown schema member")


def strings(value, allowed):
    if not isinstance(value, list) or len(value) > len(allowed) or any(type(x) is not str or x not in allowed for x in value):
        refuse("SCHEMA_VALUE", "Unsupported list value")
    if len(set(value)) != len(value):
        refuse("SCHEMA_VALUE", "Duplicate list value")
    return value


def environment(value):
    exact_keys(value, ("features", "os_state"))
    strings(value["features"], ("base", "cpuid"))
    if "base" not in value["features"]:
        refuse("ENVIRONMENT_BASE", "The x86-64 base requirement is mandatory")
    exact_keys(value["os_state"], (), ("cpuid_user_enabled",))
    if any(type(x) is not bool for x in value["os_state"].values()):
        refuse("ENVIRONMENT_STATE", "OS state declarations must be booleans")


def parse_contract(data):
    value = load_json(data)
    exact_keys(value, ("schema", "function", "abi", "domain", "requires", "clobbers", "max_stack_bytes"), ("source",))
    if value["schema"] != "bearbasm-contract-v1" or value["abi"] != "sysv-amd64" or value["domain"] != "hosted-user":
        refuse("CONTRACT_MODEL", "Only the hosted-user SysV AMD64 leaf contract is supported", status="UNPROVEN")
    if type(value["function"]) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}", value["function"]):
        refuse("CONTRACT_SYMBOL", "Invalid bounded function name")
    strings(value["clobbers"], tuple(REGS[i] for i in CALLER) + ("rflags",))
    maximum = value["max_stack_bytes"]
    if type(maximum) is not int or maximum < 0 or maximum > LIMITS["stack_bytes"] or maximum % 8:
        refuse("CONTRACT_STACK", "Stack budget must be a multiple of eight within the checker limit")
    environment(value["requires"])
    if "source" in value:
        source = value["source"]
        exact_keys(source, ("label", "sha256", "locations"))
        if type(source["label"]) is not str or len(source["label"]) > 256:
            refuse("SOURCE_LABEL", "Invalid source label")
        if type(source["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]):
            refuse("SOURCE_HASH", "Invalid source hash")
        if not isinstance(source["locations"], list) or len(source["locations"]) > LIMITS["instructions"]:
            refuse("SOURCE_MAP_LIMIT", "Source map exceeds its fixed limit")
        seen = set()
        for location in source["locations"]:
            exact_keys(location, ("offset", "line"))
            offset, line = location["offset"], location["line"]
            if type(offset) is not int or not 0 <= offset < LIMITS["function_bytes"] or offset in seen:
                refuse("SOURCE_MAP_OFFSET", "Invalid or duplicate source-map offset")
            if type(line) is not int or not 1 <= line <= LIMITS["source_bytes"]:
                refuse("SOURCE_MAP_LINE", "Invalid source-map line")
            seen.add(offset)
    return value


def parse_target(data):
    value = load_json(data)
    exact_keys(value, ("schema", "domain", "features", "os_state"))
    if value["schema"] != "bearbasm-contract-target-v1" or value["domain"] != "hosted-user":
        refuse("TARGET_DOMAIN", "Unsupported target domain", status="UNPROVEN")
    environment({"features": value["features"], "os_state": value["os_state"]})
    return value


def compare_contracts(before_path, after_path):
    before_bytes = read_bounded(before_path, LIMITS["contract_bytes"])
    after_bytes = read_bounded(after_path, LIMITS["contract_bytes"])
    before, after = parse_contract(before_bytes), parse_contract(after_bytes)
    changes = []
    for field in ("function", "clobbers", "max_stack_bytes", "requires", "source"):
        if before.get(field) != after.get(field):
            changes.append({"field": field, "before": before.get(field), "after": after.get(field)})
    return {"schema": "bearbasm-contract-diff-v1", "model": MODEL, "status": "DIFF_ONLY",
            "before_sha256": sha(before_bytes), "after_sha256": sha(after_bytes),
            "changes": changes, "requires_reverification": before_bytes != after_bytes,
            "authorizes_publication": False,
            "mandatory_callee_saved": [REGS[i] for i in CALLEE],
            "limits": "Compares declarations only; it does not establish ABI or functional equivalence"}


def in_range(offset, size, total):
    # Python integers do not wrap; retain subtraction form for auditability.
    return 0 <= offset <= total and 0 <= size <= total - offset


def overlaps(a, size_a, b, size_b):
    return size_a > 0 and size_b > 0 and a < b + size_b and b < a + size_a


class ELF:
    """Strict ET_REL reader; no C pointer casts or assembler-supplied verdicts."""
    def __init__(self, data, function):
        self.data = data
        if len(data) < 64:
            refuse("ELF_HEADER", "Truncated ELF header")
        fields = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        ident, etype, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstr = fields
        if ident[:7] != b"\x7fELF\x02\x01\x01" or ident[7] not in (0, 3) or any(ident[8:]):
            refuse("ELF_IDENT", "Only ELF64 little-endian System V/Linux identification is supported")
        if (etype, machine, version, entry, phoff, flags, ehsize, phentsize, phnum, shentsize) != (1, 62, 1, 0, 0, 0, 64, 0, 0, 64):
            refuse("ELF_FORMAT", "Only plain x86-64 ET_REL objects are supported", status="UNPROVEN")
        if not 1 < shnum <= LIMITS["sections"] or not 0 < shstr < shnum:
            refuse("ELF_SECTION_COUNT", "Invalid or unsupported section count/index")
        if shoff < 64 or not in_range(shoff, shnum * 64, len(data)):
            refuse("ELF_SECTION_RANGE", "Section table is outside the file")
        self.sections = []
        spans = []
        for index in range(shnum):
            raw = struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * 64)
            name, stype, sflags, addr, offset, size, link, info, align, entsize = raw
            section = dict(index=index, name_index=name, type=stype, flags=sflags, addr=addr,
                           offset=offset, size=size, link=link, info=info, align=align, entsize=entsize)
            if index == 0:
                if any(raw):
                    refuse("ELF_NULL_SECTION", "Nonzero null section header is unsupported")
            else:
                if stype not in (1, 2, 3, 4, 7, 8):
                    refuse("ELF_SECTION_TYPE", "Unsupported section type", status="UNPROVEN")
                if addr or (align and (align & (align - 1) or align > 1 << 30)):
                    refuse("ELF_SECTION_ATTRIBUTES", "Invalid section address/alignment")
                if sflags & ~0x37:
                    refuse("ELF_SECTION_FLAGS", "Unsupported section flags", status="UNPROVEN")
                if stype != 8:
                    if not in_range(offset, size, len(data)):
                        refuse("ELF_CONTENT_RANGE", "Section content is outside the file")
                    if size and (offset < 64 or overlaps(offset, size, shoff, shnum * 64)):
                        refuse("ELF_CONTENT_OVERLAP", "Section content overlaps ELF headers")
                    if size:
                        spans.append((offset, size))
            self.sections.append(section)
        spans.sort()
        for left, right in zip(spans, spans[1:]):
            if overlaps(*left, *right):
                refuse("ELF_CONTENT_OVERLAP", "Overlapping section contents are unsupported")
        names = self.sections[shstr]
        if names["type"] != 3:
            refuse("ELF_NAMES", "Section names must use a string table")
        for section in self.sections:
            section["name"] = self.string(names, section["name_index"])
        symtabs = [s for s in self.sections if s["type"] == 2]
        if len(symtabs) != 1:
            refuse("ELF_SYMTAB", "Exactly one symbol table is required")
        table = symtabs[0]
        if table["entsize"] != 24 or table["size"] % 24 or table["size"] // 24 > LIMITS["symbols"]:
            refuse("ELF_SYMBOL_SIZE", "Invalid or excessive symbol table")
        if not 0 < table["link"] < shnum or self.sections[table["link"]]["type"] != 3:
            refuse("ELF_SYMBOL_NAMES", "Invalid symbol string-table link")
        count = table["size"] // 24
        if not count or not 1 <= table["info"] <= count:
            refuse("ELF_SYMBOL_BOUNDARY", "Invalid local/global symbol boundary")
        strings_section = self.sections[table["link"]]
        self.symbols = []
        matches = []
        for index in range(count):
            raw = struct.unpack_from("<IBBHQQ", data, table["offset"] + index * 24)
            name_i, info, other, sec, value, size = raw
            name = self.string(strings_section, name_i)
            if index == 0 and any(raw):
                refuse("ELF_NULL_SYMBOL", "Invalid null symbol")
            binding, kind = info >> 4, info & 15
            if binding not in (0, 1, 2) or kind not in (0, 1, 2, 3, 4) or other & ~3:
                refuse("ELF_SYMBOL_KIND", "Unsupported symbol kind or visibility", status="UNPROVEN")
            if (index < table["info"]) != (binding == 0):
                refuse("ELF_SYMBOL_BOUNDARY", "Symbol binding contradicts local/global boundary")
            if sec not in (0, 0xfff1):
                if sec >= shnum or not in_range(value, size, self.sections[sec]["size"]):
                    refuse("ELF_SYMBOL_RANGE", "Symbol is outside its section")
            symbol = dict(name=name, binding=binding, kind=kind, section=sec, value=value, size=size)
            self.symbols.append(symbol)
            if name == function:
                matches.append(symbol)
        if len(matches) != 1:
            refuse("FUNCTION_IDENTITY", "Function must have exactly one symbol identity")
        selected = matches[0]
        if selected["binding"] != 1 or selected["kind"] != 2 or not 0 < selected["section"] < shnum:
            refuse("FUNCTION_KIND", "A defined global STT_FUNC is required")
        section = self.sections[selected["section"]]
        if section["type"] != 1 or section["flags"] & 7 != 6:
            refuse("FUNCTION_SECTION", "Function must be in allocated, executable, non-writable PROGBITS")
        if not 1 <= selected["size"] <= LIMITS["function_bytes"]:
            refuse("FUNCTION_SIZE", "Function extent is empty or exceeds the fixed limit")
        relocations = 0
        widths = {1: 8, 2: 4, 10: 4, 11: 4}
        for reloc in (s for s in self.sections if s["type"] == 4):
            if reloc["entsize"] != 24 or reloc["size"] % 24 or reloc["link"] != table["index"] or not 0 < reloc["info"] < shnum:
                refuse("ELF_RELOCATION_TABLE", "Invalid RELA table attributes")
            relocations += reloc["size"] // 24
            if relocations > LIMITS["relocations"]:
                refuse("ELF_RELOCATION_LIMIT", "Too many relocations")
            target = self.sections[reloc["info"]]
            for at in range(reloc["offset"], reloc["offset"] + reloc["size"], 24):
                offset, info, _addend = struct.unpack_from("<QQq", data, at)
                kind, symbol = info & 0xffffffff, info >> 32
                if kind not in widths:
                    refuse("ELF_RELOCATION_KIND", "Unsupported relocation kind", status="UNPROVEN")
                if symbol >= count or not in_range(offset, widths[kind], target["size"]):
                    refuse("ELF_RELOCATION_RANGE", "Invalid relocation symbol or target range")
                if target["index"] == selected["section"] and overlaps(offset, widths[kind], selected["value"], selected["size"]):
                    refuse("FUNCTION_RELOCATION", "Relocation overlaps the checked function; final bytes are unknown", status="UNPROVEN")
        self.selected, self.section = selected, section
        self.start = section["offset"] + selected["value"]
        self.code = data[self.start:self.start + selected["size"]]

    def string(self, section, offset):
        if offset >= section["size"]:
            refuse("ELF_STRING_RANGE", "String index is outside its table")
        start = section["offset"] + offset
        stop = min(section["offset"] + section["size"], start + 4097)
        end = self.data.find(b"\0", start, stop)
        if end < 0:
            refuse("ELF_STRING_TERMINATOR", "Unterminated or excessive ELF string")
        try:
            return self.data[start:end].decode("utf-8")
        except UnicodeError:
            refuse("ELF_STRING_ENCODING", "ELF names must be valid UTF-8 in this model")


@dataclass(frozen=True)
class Instruction:
    offset: int
    size: int
    form: str
    operation: str
    width: int = 0
    dst: int = -1
    src: int = -1
    immediate: int = 0
    target: int = -1
    condition: int = -1


def decode(code):
    instructions = {}
    pos = 0
    while pos < len(code):
        if len(instructions) >= LIMITS["instructions"]:
            refuse("INSTRUCTION_LIMIT", "Instruction budget exhausted", status="UNPROVEN", offset=pos)
        start = pos
        rex = 0
        if 0x40 <= code[pos] <= 0x4f:
            rex = code[pos]
            pos += 1
        if pos == len(code):
            refuse("DECODE_TRUNCATED", "Truncated opcode", offset=start)
        first = code[pos]
        pos += 1
        opcode = f"{first:02x}"
        if first == 0x0f:
            if pos == len(code):
                refuse("DECODE_TRUNCATED", "Truncated two-byte opcode", offset=start)
            opcode += f"{code[pos]:02x}"
            pos += 1
        form = OPCODES.get(opcode)
        if form is None:
            refuse("INSTRUCTION_UNKNOWN", "Instruction is outside the closed model", status="UNPROVEN", offset=start)
        shape, operation = form["shape"], form["operation"]
        fields = {}
        if shape == "rr":
            if rex & 2:  # REX.X is redundant for mod=3; reject noncanonical use.
                refuse("PREFIX_UNKNOWN", "Unsupported REX prefix", status="UNPROVEN", offset=start)
            if pos == len(code):
                refuse("DECODE_TRUNCATED", "Missing ModRM byte", offset=start)
            modrm = code[pos]
            pos += 1
            if modrm >> 6 != 3:
                refuse("MEMORY_UNMODELED", "Explicit memory operands are outside the leaf model", status="UNPROVEN", offset=start)
            reg = ((modrm >> 3) & 7) + (8 if rex & 4 else 0)
            rm = (modrm & 7) + (8 if rex & 1 else 0)
            dst, src = (reg, rm) if first in (0x8b, 0x03, 0x2b, 0x33, 0x3b) else (rm, reg)
            if dst == 4 and operation not in ("cmp", "test"):
                refuse("STACK_WRITE_UNKNOWN", "General writes to RSP/ESP are not modeled", status="UNPROVEN", offset=start)
            fields = dict(width=64 if rex & 8 else 32, dst=dst, src=src)
        elif shape == "register":
            if rex not in (0, 0x41):
                refuse("PREFIX_UNKNOWN", "Only the required REX.B stack prefix is supported", status="UNPROVEN", offset=start)
            reg = (first & 7) + (8 if rex == 0x41 else 0)
            if operation == "pop" and reg == 4:
                refuse("STACK_WRITE_UNKNOWN", "POP RSP is not modeled", status="UNPROVEN", offset=start)
            fields = dict(width=64, dst=reg)
        elif shape == "rsp_immediate":
            amount_size = 1 if first == 0x83 else 4
            if rex != 0x48 or len(code) - pos < amount_size + 1:
                refuse("STACK_ADJUST_UNKNOWN", "Only complete ADD/SUB RSP immediate is modeled", status="UNPROVEN", offset=start)
            modrm = code[pos]
            pos += 1
            if modrm not in (0xc4, 0xec):
                refuse("IMMEDIATE_UNMODELED", "Only positive stack adjustments are modeled", status="UNPROVEN", offset=start)
            amount = int.from_bytes(code[pos:pos + amount_size], "little", signed=True)
            pos += amount_size
            if amount < 0 or amount % 8 or amount > LIMITS["stack_bytes"]:
                refuse("STACK_ADJUST_RANGE", "Stack adjustment is outside the bounded aligned model", status="UNPROVEN", offset=start)
            fields = dict(width=64, dst=4, immediate=amount if modrm == 0xc4 else -amount)
        elif shape in ("relative8", "relative32"):
            size = 1 if shape == "relative8" else 4
            if rex:
                refuse("PREFIX_UNKNOWN", "Prefixed branches are not modeled", status="UNPROVEN", offset=start)
            if len(code) - pos < size:
                refuse("DECODE_TRUNCATED", "Truncated branch displacement", offset=start)
            displacement = int.from_bytes(code[pos:pos + size], "little", signed=True)
            pos += size
            fields = dict(target=pos + displacement, condition=int(opcode[-2:], 16) & 15 if operation == "branch" else -1)
        elif rex:
            refuse("PREFIX_UNKNOWN", "Prefixed fixed instructions are not modeled", status="UNPROVEN", offset=start)
        instructions[start] = Instruction(start, pos - start, form["id"], operation, **fields)
    for instruction in instructions.values():
        if instruction.operation in ("jump", "branch"):
            if instruction.target not in instructions:
                refuse("BRANCH_TARGET", "Branch target is outside the function or inside an instruction", offset=instruction.offset)
            if instruction.target <= instruction.offset:
                refuse("CONTROL_CYCLE", "Backward control flow requires a stronger model", status="UNPROVEN", offset=instruction.offset)
    return instructions


def analyze(instructions, contract, target):
    required = {"base"}
    os_required = {}
    for instruction in instructions.values():
        if instruction.operation == "cpuid":
            required.add("cpuid")
            os_required["cpuid_user_enabled"] = True
    if not required <= set(contract["requires"]["features"]) or any(contract["requires"]["os_state"].get(k) != v for k, v in os_required.items()):
        first = next((i.offset for i in instructions.values() if i.operation == "cpuid"), 0)
        refuse("REQUIREMENT_UNDECLARED", "Instruction requirements are missing from the contract", offset=first)
    if not set(contract["requires"]["features"]) <= set(target["features"]) or any(target["os_state"].get(k) != v for k, v in contract["requires"]["os_state"].items()):
        refuse("TARGET_REQUIREMENT", "Declared target configuration does not establish the requirements", status="UNPROVEN")
    initial = tuple(f"entry:{reg}" for reg in REGS)
    # Value provenance is exact only for full-width register copies and saved
    # stack values. Arithmetic and 32-bit writes become unknown; both sides of
    # every conditional branch are explored, including infeasible sides.
    pending = deque([(0, initial, 0, (), False, False, ())])
    visited = set()
    steps = returns = peak = 0
    clobbers = set()
    while pending:
        pc, registers, delta, stack_tuple, df_set, flags_changed, path = pending.popleft()
        state_id = (pc, registers, delta, stack_tuple, df_set, flags_changed)
        if state_id in visited:
            continue
        if len(visited) >= LIMITS["states"] or steps >= LIMITS["steps"]:
            refuse("ANALYSIS_BUDGET", "State/step budget exhausted", status="UNPROVEN", offset=pc, path=path)
        visited.add(state_id)
        steps += 1
        path = path + (pc,)
        if pc not in instructions:
            refuse("MISSING_RETURN", "A modeled path falls beyond the function without RET", offset=pc, path=path)
        ins = instructions[pc]
        regs, stack = list(registers), dict(stack_tuple)
        operation = ins.operation
        if operation == "ret":
            if delta:
                refuse("STACK_UNBALANCED", "RET is reached with an unbalanced stack", offset=pc, path=path, details={"rsp_delta": delta})
            for reg in CALLEE:
                if regs[reg] != initial[reg]:
                    refuse("CALLEE_SAVED", "RET does not preserve a mandatory SysV register", offset=pc, path=path, details={"register": REGS[reg]})
            if df_set:
                refuse("DIRECTION_FLAG", "RET is reached with the direction flag set", offset=pc, path=path)
            changed = {REGS[r] for r in CALLER if regs[r] != initial[r]}
            if flags_changed:
                changed.add("rflags")
            missing = changed - set(contract["clobbers"])
            if missing:
                refuse("CLOBBER_UNDECLARED", "A return may clobber undeclared caller state", offset=pc, path=path, details={"registers": sorted(missing)})
            clobbers.update(changed)
            returns += 1
            continue
        if operation == "mov":
            regs[ins.dst] = regs[ins.src] if ins.width == 64 else f"unknown:{pc}"
        elif operation in ("add", "sub", "xor"):
            regs[ins.dst] = f"unknown:{pc}"
            flags_changed = True
        elif operation in ("cmp", "test"):
            flags_changed = True
        elif operation == "push":
            value = regs[ins.dst] if ins.dst != 4 else f"entry-rsp:{delta}"
            delta -= 8
            stack[delta] = value
        elif operation == "pop":
            if delta >= 0 or delta not in stack:
                refuse("STACK_READ", "POP reads outside initialized private stack slots", offset=pc, path=path)
            regs[ins.dst] = stack.pop(delta)
            delta += 8
        elif operation == "stack":
            old = delta
            delta += ins.immediate
            if delta > 0:
                refuse("STACK_ESCAPE", "Stack adjustment crosses the entry return-address boundary", offset=pc, path=path)
            if ins.immediate > 0:
                stack = {address: value for address, value in stack.items() if not old <= address < delta}
            flags_changed = True
        elif operation == "cpuid":
            for reg in (0, 1, 2, 3):
                regs[reg] = f"unknown:{pc}:{reg}"
        elif operation in ("cld", "std"):
            df_set = operation == "std"
            # SysV assumes DF clear on entry; CLD reestablishes that fact.
            # Other RFLAGS bits are untouched by these two instructions.
        if delta < -contract["max_stack_bytes"]:
            refuse("STACK_BUDGET", "Function exceeds its declared private stack budget", offset=pc, path=path, details={"bytes": -delta})
        peak = max(peak, -delta)
        regs[4] = f"entry-rsp:{delta}" if delta else initial[4]
        following = ins.offset + ins.size
        successors = (ins.target,) if operation == "jump" else (ins.target, following) if operation == "branch" else (following,)
        for successor in successors:
            pending.append((successor, tuple(regs), delta, tuple(sorted(stack.items())), df_set, flags_changed, path))
    if not returns:
        refuse("MISSING_RETURN", "No complete return path was established", status="UNPROVEN")
    return {"return_states": returns, "states": len(visited), "steps": steps,
            "max_stack_bytes": peak, "net_clobbers": sorted(clobbers),
            "required_features": sorted(required), "required_os_state": os_required}


def instruction_json(ins, elf, locations):
    operands = []
    registers = REGS if ins.width == 64 else REGS32
    if ins.dst >= 0:
        operands.append(registers[ins.dst])
    if ins.src >= 0:
        operands.append(registers[ins.src])
    if ins.operation == "stack":
        operands.append(ins.immediate)
    if ins.operation in ("branch", "jump"):
        operands.append({"function_offset": ins.target})
    return {"offset": ins.offset, "section_offset": elf.selected["value"] + ins.offset,
            "file_offset": elf.start + ins.offset, "bytes": elf.code[ins.offset:ins.offset + ins.size].hex(),
            "form": ins.form, "operation": ins.operation, "width": ins.width,
            "operands": operands, "source_line_declared": locations.get(ins.offset)}


def check(object_path, contract_path, target_path=None, source_path=None, expected_path=None):
    checker_hash = sha(read_bounded(__file__, LIMITS["object_bytes"]))
    result = {"schema": RESULT_SCHEMA, "model": {"id": MODEL, "checker_sha256": checker_hash,
              "forms_sha256": sha(canonical(FORMS))}, "status": "REJECTED", "diagnostics": []}
    elf = None
    locations = {}
    source_label = None
    try:
        obj = read_bounded(object_path, LIMITS["object_bytes"])
        contract_bytes = read_bounded(contract_path, LIMITS["contract_bytes"])
        target_bytes = read_bounded(target_path, LIMITS["target_bytes"]) if target_path else canonical(DEFAULT_TARGET)
        contract, target = parse_contract(contract_bytes), parse_target(target_bytes)
        source_bytes = read_bounded(source_path, LIMITS["source_bytes"]) if source_path else None
        result["inputs"] = {"object_sha256": sha(obj), "contract_sha256": sha(contract_bytes),
                            "target_sha256": sha(target_bytes), "source_sha256": sha(source_bytes) if source_bytes is not None else None}
        if "source" in contract:
            if source_bytes is None or sha(source_bytes) != contract["source"]["sha256"]:
                refuse("SOURCE_BINDING", "The declared source identity requires the matching explicit --source input")
            source_label = contract["source"]["label"]
            locations = {x["offset"]: x["line"] for x in contract["source"]["locations"]}
            line_count = source_bytes.count(b"\n") + 1
            if any(line > line_count for line in locations.values()):
                refuse("SOURCE_MAP_LINE", "Source map names a line beyond the supplied source")
        elf = ELF(obj, contract["function"])
        result["function"] = {"name": contract["function"], "section": elf.section["name"],
                              "section_offset": elf.selected["value"], "file_offset": elf.start,
                              "size": len(elf.code), "code_sha256": sha(elf.code)}
        if expected_path:
            expected = load_json(read_bounded(expected_path, LIMITS["receipt_bytes"]))
            if not isinstance(expected, dict) or expected.get("schema") != RESULT_SCHEMA or expected.get("status") != "VERIFIED_WITHIN_MODEL":
                refuse("RECEIPT_FORMAT", "Expected receipt is not an accepted result of this model")
            different = [key for key in ("model", "inputs", "function") if expected.get(key) != result[key]]
            if different:
                refuse("RECEIPT_IDENTITY", "Object, contract, target, source, checker or model differs from the expected receipt",
                       details={"changed_groups": different})
        instructions = decode(elf.code)
        if any(offset not in instructions for offset in locations):
            refuse("SOURCE_MAP_OFFSET", "Declared source offset is not an independently decoded instruction start")
        result["instructions"] = [instruction_json(i, elf, locations) for i in instructions.values()]
        analysis = analyze(instructions, contract, target)
        result.update(status="VERIFIED_WITHIN_MODEL", analysis=analysis,
                      properties={"stack_balance": "VERIFIED_WITHIN_MODEL", "callee_saved": "VERIFIED_WITHIN_MODEL",
                                  "declared_clobbers": "VERIFIED_WITHIN_MODEL", "direction_flag_at_return": "VERIFIED_WITHIN_MODEL",
                                  "cpu_requirements": "VERIFIED_AGAINST_DECLARED_TARGET", "functional_result": "NOT_CHECKED"},
                      preconditions=["Entry is exactly the selected STT_FUNC start in long mode and hosted-user SysV AMD64",
                                     "Entry RSP is 8 modulo 16, points to a valid trusted return address, and DF is clear",
                                     f"At least {analysis['max_stack_bytes']} bytes below entry RSP are private readable/writable stack",
                                     "Declared target CPU/OS configuration is established by the consumer, not probed by this tool",
                                     "No asynchronous modification of code, stack, saved registers, or execution environment",
                                     "Linking preserves these relocation-free function bytes and the consumer enters at the checked symbol"],
                      limits={"checked_region": "one relocation-free acyclic leaf function; all region bytes decoded",
                              "branch_analysis": "both successors, including infeasible paths; conservative refusal is possible",
                              "source_mapping": "declared diagnostic hint; source hash checked, source-to-byte correspondence NOT proved",
                              "outside_scope": ["functional correctness", "general memory safety", "constant time", "final linked image",
                                                "privilege confinement", "signature trust", "fault freedom", "arbitrary x86", "loop invariants"]},
                      source_label=source_label)
    except Refusal as error:
        result["status"] = error.status
        diagnostic = {"code": error.code, "message": error.message, "function_offset": error.offset,
                      "file_offset": elf.start + error.offset if elf is not None and error.offset is not None else None,
                      "source": {"label": source_label, "line": locations.get(error.offset), "status": "DECLARED_DIAGNOSTIC_HINT"}}
        if error.path is not None:
            diagnostic["path_offsets"] = list(error.path)
        if error.details is not None:
            diagnostic["details"] = error.details
        result["diagnostics"].append(diagnostic)
    return result


class Parser(argparse.ArgumentParser):
    def error(self, message):
        refuse("ARGUMENTS", "Invalid command-line arguments")


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--object")
    parser.add_argument("--contract")
    parser.add_argument("--target")
    parser.add_argument("--source")
    parser.add_argument("--expect", help="Pin identities to a prior result, then rerun the independent check")
    parser.add_argument("--describe", action="store_true", help="Export the closed instruction model and fixed budgets")
    parser.add_argument("--compare-contracts", nargs=2, metavar=("BEFORE", "AFTER"),
                        help="Compare validated declarations; never grants verification or publication authority")
    try:
        args = parser.parse_args(argv)
        if args.compare_contracts:
            if args.describe or any((args.object, args.contract, args.target, args.source, args.expect)):
                refuse("ARGUMENTS", "Contract comparison does not take artifact or inventory inputs")
            result = compare_contracts(*args.compare_contracts)
        elif args.describe:
            if any((args.object, args.contract, args.target, args.source, args.expect)):
                refuse("ARGUMENTS", "--describe does not take artifact inputs")
            result = {"schema": "bearbasm-contract-model-v1", "model": MODEL, "forms": FORMS, "limits": LIMITS}
        else:
            if not args.object or not args.contract:
                refuse("ARGUMENTS", "--object and --contract are required")
            result = check(args.object, args.contract, args.target, args.source, args.expect)
    except Refusal as error:
        result = {"schema": RESULT_SCHEMA, "status": error.status,
                  "diagnostics": [{"code": error.code, "message": error.message}]}
    sys.stdout.write(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
    return 0 if result.get("status") in (None, "VERIFIED_WITHIN_MODEL", "DIFF_ONLY") else 1


if __name__ == "__main__":
    raise SystemExit(main())
