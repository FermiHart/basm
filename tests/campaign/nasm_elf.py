#!/usr/bin/env python3
"""Independent, deliberately narrow ELF64 parity gate for assembler benchmarks.

This is not elftool, a linker, or a claim of executable/linker-layout equivalence.
Section ordering can affect eventual linker layout; this is structural ET_REL
parity with that ordering explicitly excluded. It accepts
little-endian x86-64 relocatable objects and rejects unsupported encodings rather
than silently comparing a subset. Storage layout, symbol/string table packing,
and unreferenced FILE/SECTION metadata are reported but not parity inputs.
Section bytes, section attributes, exported definitions, and every relocation's
referenced definition are parity inputs. In particular, .note.GNU-stack is NOT
silently discarded, even when empty. No third-party modules are required.

Public API:
    normalize_elf(path) -> JSON-serializable canonical model
    compare_elf(left, right) -> equality, differences, models and metadata deltas

Malformed and unsupported files raise ElfFormatError. Callers must treat that
exception as a refused comparison, never as a passing or timed benchmark case.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
import struct


SCHEMA = "BASM-NASM-ELF-CANONICAL-v1"
COMPARISON_SCHEMA = "BASM-NASM-ELF-COMPARISON-v1"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 4096
MAX_SYMBOLS = 100_000
MAX_RELOCATIONS = 100_000
MAX_NAME_BYTES = 4096
MAX_TOTAL_SYMBOL_NAME_BYTES = 32 * 1024 * 1024
MAX_CANONICAL_RELOCATION_BYTES = 32 * 1024 * 1024
SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 0, 1, 2, 3
SHT_RELA, SHT_NOTE, SHT_NOBITS, SHT_REL = 4, 7, 8, 9
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE, STT_TLS = 0, 1, 2, 3, 4, 6
# Supported fixed-width x86-64 relocation fields. No implicit-addend REL, TLS
# descriptors, dynamic relocations, or unknown target-specific rules are guessed.
RELOCATION_WIDTHS = {
    0: 0,   # R_X86_64_NONE
    1: 8,   # R_X86_64_64
    2: 4,   # R_X86_64_PC32
    3: 4,   # R_X86_64_GOT32
    4: 4,   # R_X86_64_PLT32
    9: 4,   # R_X86_64_GOTPCREL
    10: 4,  # R_X86_64_32
    11: 4,  # R_X86_64_32S
    12: 2,  # R_X86_64_16
    13: 2,  # R_X86_64_PC16
    14: 1,  # R_X86_64_8
    15: 1,  # R_X86_64_PC8
    24: 8,  # R_X86_64_PC64
    25: 8,  # R_X86_64_GOTOFF64
    26: 4,  # R_X86_64_GOTPC32
    27: 8,  # R_X86_64_GOT64
    28: 8,  # R_X86_64_GOTPCREL64
    29: 8,  # R_X86_64_GOTPC64
    30: 8,  # R_X86_64_GOTPLT64
    31: 8,  # R_X86_64_PLTOFF64
}
# GOTPCRELX / REX_GOTPCRELX are deliberately absent: their relaxation can
# rewrite instruction bytes outside the nominal relocation field.
# W/A/X/M/S/TLS only. Link-order/group/compressed/OS-specific semantics are not
# implemented; accepting their flags while ignoring their dependencies is unsafe.
SUPPORTED_CONTENT_FLAGS = 0x1 | 0x2 | 0x4 | 0x10 | 0x20 | 0x400
COMPARABLE_KEYS = ("header", "content_sections", "exported_symbols", "local_symbols",
                   "relocation_sections", "relocations")


class ElfFormatError(ValueError):
    """Malformed or unsupported ELF object; parity was not established."""


def _require(condition, message):
    if not condition:
        raise ElfFormatError(message)


def _span(data, offset, size, label):
    _require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
             f"{label}: span outside file")
    return data[offset:offset + size]


def _string(data, offset, label):
    _require(0 <= offset < len(data), f"{label}: string offset outside table")
    end = data.find(b"\0", offset, offset + MAX_NAME_BYTES + 1)
    _require(end >= 0, f"{label}: unterminated string or name exceeds 4096-byte limit")
    # ELF names are byte strings. surrogateescape is reversible and json.dumps
    # with its default ensure_ascii=True serializes even non-UTF8 names safely.
    return data[offset:end].decode("utf-8", "surrogateescape")


def _key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _definition(symbol, section_names):
    ndx = symbol["section_index"]
    special = {SHN_UNDEF: "undefined", SHN_ABS: "absolute", SHN_COMMON: "common"}
    section = ({"kind": special[ndx]} if ndx in special else
               {"kind": "section", "name": section_names[ndx]})
    name = symbol["name"]
    # Named and anonymous STT_SECTION are the same definition. A regular local
    # symbol's name/value/type/size is never erased, including in relocations.
    if symbol["type"] == STT_SECTION:
        name = None
    return {"name": name, "bind": symbol["bind"], "type": symbol["type"],
            "visibility": symbol["visibility"], "section": section,
            "value": symbol["value"], "size": symbol["size"]}


def _read(path):
    # Bound the read itself, including a file that grows after opening.
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    _require(len(raw) <= MAX_FILE_BYTES, "file exceeds the 64 MiB comparison limit")
    _require(len(raw) >= 64, "truncated ELF64 header")
    values = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    (ident, etype, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = values
    _require(ident[:4] == b"\x7fELF", "not an ELF file")
    _require(ident[4:7] == b"\x02\x01\x01", "requires ELF64 little-endian version 1")
    _require(not any(ident[9:]), "nonzero ELF identification padding")
    _require(etype == 1 and machine == 62 and version == 1,
             "requires ET_REL / EM_X86_64 / version 1")
    _require(entry == 0, "ET_REL has a nonzero entry point")
    _require(phoff == phentsize == phnum == 0, "program headers are unsupported for ET_REL")
    _require(ehsize == 64 and shentsize == 64, "invalid ELF or section header entry size")
    _require(0 < shnum < 0xFF00, "extended or absent section count is unsupported")
    _require(shnum <= MAX_SECTIONS, "section count exceeds the 4096-entry comparison limit")
    _require(0 < shstrndx < shnum, "invalid section-name string-table index")
    _require(shoff >= 64 and shoff % 8 == 0, "invalid section-header table offset/alignment")
    _span(raw, shoff, shnum * 64, "section-header table")
    sections = []
    occupied = [(0, 64, "ELF header"), (shoff, shoff + shnum * 64, "section-header table")]
    for index in range(shnum):
        fields = struct.unpack_from("<IIQQQQIIQQ", raw, shoff + index * 64)
        if index == 0:
            _require(not any(fields), "section zero must be the all-zero null entry")
        name_off, typ, sflags, addr, off, size, link, info, align, entsize = fields
        section = dict(index=index, name_off=name_off, type=typ, flags=sflags,
                       address=addr, offset=off, size=size, link=link, info=info,
                       alignment=align, entsize=entsize)
        if index:
            _require(typ != SHT_NULL, f"section {index}: extra SHT_NULL is unsupported")
            _require(typ != SHT_REL, f"section {index}: SHT_REL implicit addends are unsupported")
            _require(typ in (SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOTE, SHT_NOBITS),
                     f"section {index}: unsupported section type {typ}")
            _require(addr == 0, f"section {index}: nonzero ET_REL address")
            _require(align == 0 or align & (align - 1) == 0,
                     f"section {index}: alignment is not a power of two")
            _require(not align or off % align == 0,
                     f"section {index}: file offset violates alignment")
            _require(link < shnum, f"section {index}: link outside section table")
            if typ != SHT_NOBITS:
                section["payload"] = _span(raw, off, size, f"section {index}")
                if size:
                    occupied.append((off, off + size, f"section {index}"))
            else:
                _require(off <= len(raw), f"section {index}: NOBITS offset outside file")
                section["payload"] = b""
        else:
            section["payload"] = b""
        sections.append(section)
    occupied.sort()
    for previous, current in zip(occupied, occupied[1:]):
        _require(previous[1] <= current[0],
                 f"overlapping file storage: {previous[2]} and {current[2]}")

    shstrings = sections[shstrndx]
    _require(shstrings["type"] == SHT_STRTAB, "section-name table is not SHT_STRTAB")
    for section in sections[1:]:
        if section["type"] == SHT_STRTAB:
            payload = section["payload"]
            _require(payload and payload[0] == 0 and payload[-1] == 0,
                     f"section {section['index']}: string table must start/end with NUL")
            _require(section["entsize"] == 0, "string table has nonzero entry size")
    names = [_string(shstrings["payload"], s["name_off"], "section name") for s in sections]
    _require(names[0] == "", "null section has a name")
    _require(all(names[1:]), "non-null section has an empty name")
    _require(len(names) == len(set(names)), "duplicate section names")
    for section, name in zip(sections, names):
        section["name"] = name
        if name == ".note.GNU-stack":
            _require(section["type"] == SHT_PROGBITS,
                     ".note.GNU-stack must be an ordinary PROGBITS content section")

    symtabs = [s for s in sections if s["type"] == SHT_SYMTAB]
    _require(len(symtabs) <= 1, "multiple symbol tables are unsupported")
    storage_indices = {shstrndx}
    symbols = []
    total_name_bytes = 0
    external_names = set()
    if symtabs:
        table = symtabs[0]
        _require(table["flags"] == 0 and table["entsize"] == 24 and table["size"] % 24 == 0,
                 "symbol table has invalid flags/entry size")
        _require(table["alignment"] in (0, 1, 2, 4, 8), "unsupported symbol-table alignment")
        _require(table["link"] != 0 and sections[table["link"]]["type"] == SHT_STRTAB,
                 "symbol table link is not a string table")
        count = table["size"] // 24
        _require(count <= MAX_SYMBOLS, "symbol count exceeds the 100000-entry comparison limit")
        _require(count > 0 and 1 <= table["info"] <= count, "invalid symbol-table local/global boundary")
        strings = sections[table["link"]]["payload"]
        storage_indices.update((table["index"], table["link"]))
        for index in range(count):
            name_off, sinfo, other, ndx, value, size = struct.unpack_from("<IBBHQQ", table["payload"], index * 24)
            if index == 0:
                _require((name_off, sinfo, other, ndx, value, size) == (0, 0, 0, 0, 0, 0),
                         "symbol zero must be all-zero STN_UNDEF")
            bind, typ = sinfo >> 4, sinfo & 15
            _require(bind in (STB_LOCAL, STB_GLOBAL, STB_WEAK), f"symbol {index}: unsupported binding")
            _require(typ in (STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE, STT_TLS),
                     f"symbol {index}: unsupported type")
            _require(other <= 3, f"symbol {index}: unsupported visibility/other bits")
            _require((bind == STB_LOCAL) == (index < table["info"]),
                     f"symbol {index}: invalid local/global partition")
            _require(ndx in (SHN_UNDEF, SHN_ABS, SHN_COMMON) or 0 < ndx < shnum,
                     f"symbol {index}: unsupported or invalid section index")
            name = _string(strings, name_off, f"symbol {index}")
            total_name_bytes += len(name.encode("utf-8", "surrogateescape"))
            _require(total_name_bytes <= MAX_TOTAL_SYMBOL_NAME_BYTES,
                     "symbol names exceed the 32 MiB aggregate comparison limit")
            if bind in (STB_GLOBAL, STB_WEAK):
                _require(bool(name), f"symbol {index}: exported/undefined linkage has no name")
                _require(name not in external_names,
                         f"symbol {index}: duplicate global/weak name has ambiguous resolution")
                external_names.add(name)
            if typ == STT_SECTION:
                _require(bind == STB_LOCAL and 0 < ndx < shnum and value == size == 0,
                         f"symbol {index}: malformed section symbol")
            if typ == STT_FILE:
                _require(bind == STB_LOCAL and ndx == SHN_ABS and value == size == 0,
                         f"symbol {index}: malformed file symbol")
            if ndx == SHN_UNDEF:
                _require(value == 0, f"symbol {index}: undefined symbol has a value")
            if ndx == SHN_COMMON:
                _require(value == 0 or value & (value - 1) == 0,
                         f"symbol {index}: COMMON alignment is not a power of two")
            if 0 < ndx < shnum:
                _require(ndx not in storage_indices and sections[ndx]["type"] != SHT_RELA,
                         f"symbol {index}: definition in a storage/relocation table is unsupported")
                # Zero-size symbols may denote a section's end. A definition
                # outside its section is not accepted as benchmark evidence.
                _require(value <= sections[ndx]["size"] and size <= sections[ndx]["size"] - value,
                         f"symbol {index}: definition outside section")
            symbols.append(dict(name=name, bind=bind, type=typ, visibility=other,
                                section_index=ndx, value=value, size=size))

    content = []
    relocation_sections = []
    relocations = []
    referenced = set()
    relocation_fields = {}
    canonical_relocation_bytes = 0
    for section in sections[1:]:
        typ, name = section["type"], section["name"]
        if typ == SHT_RELA:
            _require(symtabs and section["link"] == symtabs[0]["index"],
                     f"{name}: relocation link is not the parsed symbol table")
            _require(0 < section["info"] < shnum, f"{name}: invalid relocation target index")
            target = sections[section["info"]]
            _require(target["type"] in (SHT_PROGBITS, SHT_NOBITS, SHT_NOTE),
                     f"{name}: relocation target is not a content section")
            _require(section["entsize"] == 24 and section["size"] % 24 == 0,
                     f"{name}: invalid RELA entry size")
            _require(len(relocations) + section["size"] // 24 <= MAX_RELOCATIONS,
                     "relocation count exceeds the 100000-entry comparison limit")
            # SHF_INFO_LINK describes the already-normalized sh_info field.
            _require(section["flags"] in (0, 0x40), f"{name}: unsupported RELA flags")
            relocation_sections.append({"name": name, "type": typ, "flags": section["flags"],
                                        "alignment": section["alignment"], "entsize": 24,
                                        "size": section["size"], "target": target["name"]})
            used_fields = relocation_fields.setdefault(target["name"], [])
            for offset in range(0, section["size"], 24):
                place, info, addend = struct.unpack_from("<QQq", section["payload"], offset)
                symidx, rtype = info >> 32, info & 0xFFFFFFFF
                _require(symidx < len(symbols), f"{name}: relocation symbol index outside table")
                _require(rtype in RELOCATION_WIDTHS, f"{name}: unsupported x86-64 relocation type {rtype}")
                width = RELOCATION_WIDTHS[rtype]
                _require(place <= target["size"] and width <= target["size"] - place,
                         f"{name}: relocation field outside target")
                symbol = symbols[symidx]
                _require(symbol["type"] != STT_FILE, f"{name}: relocation references FILE metadata")
                _require(symbol["section_index"] not in storage_indices,
                         f"{name}: relocation references a storage table")
                referenced.add(symidx)
                if width:
                    used_fields.append((place, place + width))
                relocation = {"relocation_section": name, "target": target["name"],
                              "offset": place, "type": rtype, "addend": addend,
                              "symbol": _definition(symbol, names)}
                # Repeated references to one long name otherwise expand a small
                # input into a huge JSON receipt despite the symbol-name budget.
                canonical_relocation_bytes += len(_key(relocation))
                _require(canonical_relocation_bytes <= MAX_CANONICAL_RELOCATION_BYTES,
                         "canonical relocations exceed the 32 MiB comparison limit")
                relocations.append(relocation)
        elif section["index"] not in storage_indices:
            _require(typ in (SHT_PROGBITS, SHT_STRTAB, SHT_NOTE, SHT_NOBITS),
                     f"{name}: unsupported content type")
            _require(section["link"] == section["info"] == 0,
                     f"{name}: unsupported content link/info semantics")
            _require(section["flags"] & ~SUPPORTED_CONTENT_FLAGS == 0,
                     f"{name}: unsupported content flags")
            _require(section["entsize"] == 0 or section["size"] % section["entsize"] == 0,
                     f"{name}: size is not divisible by entry size")
            if section["flags"] & 0x10:
                _require(section["entsize"] > 0 and section["size"] % section["entsize"] == 0,
                         f"{name}: invalid SHF_MERGE entry size")
            if section["flags"] & 0x20:
                _require(section["flags"] & 0x10, f"{name}: SHF_STRINGS without SHF_MERGE")
            content.append({"name": name, "type": typ, "flags": section["flags"],
                            "alignment": section["alignment"], "entsize": section["entsize"],
                            "size": section["size"],
                            "sha256": hashlib.sha256(section["payload"]).hexdigest()
                            if typ != SHT_NOBITS else None})
        if typ == SHT_STRTAB:
            _require(section["link"] == section["info"] == 0,
                     f"{name}: unsupported string-table link/info")
            if section["index"] in storage_indices:
                _require(section["flags"] == 0, f"{name}: storage string table has flags")

    # Refuse overlapping nominal fields, including fields stored in different
    # relocation sections with the same target. This remains a structural gate,
    # not a simulation of every linker transformation.
    for target, fields in relocation_fields.items():
        fields.sort()
        for previous, current in zip(fields, fields[1:]):
            _require(previous[1] <= current[0], f"{target}: overlapping relocation fields are unsupported")

    exported = [_definition(symbol, names) for symbol in symbols
                if symbol["bind"] in (STB_GLOBAL, STB_WEAK)]
    locals_ = [_definition(symbol, names) for index, symbol in enumerate(symbols)
               if index and symbol["bind"] == STB_LOCAL and symbol["type"] not in (STT_FILE, STT_SECTION)]
    ignored_locals = [_definition(symbol, names) for index, symbol in enumerate(symbols)
                      if index and symbol["type"] in (STT_FILE, STT_SECTION) and index not in referenced]
    table_metadata = [{"name": sections[index]["name"], "type": sections[index]["type"],
                       "size": sections[index]["size"], "alignment": sections[index]["alignment"],
                       "sha256": hashlib.sha256(sections[index]["payload"]).hexdigest()}
                      for index in storage_indices]
    model = {
        "schema": SCHEMA,
        "supported_limits": {"file_bytes": MAX_FILE_BYTES, "sections": MAX_SECTIONS,
                             "symbols": MAX_SYMBOLS, "relocations": MAX_RELOCATIONS,
                             "name_bytes": MAX_NAME_BYTES,
                             "aggregate_symbol_name_bytes": MAX_TOTAL_SYMBOL_NAME_BYTES,
                             "canonical_relocation_bytes": MAX_CANONICAL_RELOCATION_BYTES},
        "header": {"class": 64, "byte_order": "little", "type": etype, "machine": machine,
                   "version": version, "osabi": ident[7], "abi_version": ident[8], "flags": flags},
        "content_sections": sorted(content, key=lambda item: item["name"]),
        "exported_symbols": sorted(exported, key=_key),
        "local_symbols": sorted(locals_, key=_key),
        "relocation_sections": sorted(relocation_sections, key=lambda item: item["name"]),
        "relocations": sorted(relocations, key=_key),
        "ignored_metadata": {
            "policy": ["file offsets and nonoverlapping padding", "section/symbol/string-table ordering and indices",
                       "designated symbol and string storage tables", "NULL symbol zero",
                       "unreferenced FILE/SECTION symbols only; application locals are compared",
                       "STT_SECTION symbol name only (definition preserved)"],
            "storage_tables": sorted(table_metadata, key=lambda item: item["name"]),
            "unreferenced_file_section_symbols": sorted(ignored_locals, key=_key),
        },
    }
    payloads = {s["name"]: s["payload"] for s in sections[1:]
                if s["index"] not in storage_indices and s["type"] != SHT_RELA}
    return model, payloads


def normalize_elf(path):
    """Validate one supported object and return its JSON-serializable model.

    Section payload digests make receipts compact. compare_elf additionally
    compares the original payload bytes, so parity does not rely on hash equality.
    """
    model, _ = _read(path)
    return model


def _differences(left, right, path=""):
    if type(left) is not type(right):
        return [{"path": path, "left": left, "right": right}]
    if isinstance(left, dict):
        result = []
        for key in sorted(left.keys() | right.keys()):
            where = f"{path}.{key}" if path else key
            if key not in left or key not in right:
                result.append({"path": where, "left": left.get(key), "right": right.get(key)})
            else:
                result.extend(_differences(left[key], right[key], where))
        return result
    if isinstance(left, list):
        # Multiset deltas avoid reporting every following symbol as changed when
        # one inserted definition shifts its position in canonical ordering.
        if left == right:
            return []
        left_counts, right_counts = Counter(map(_key, left)), Counter(map(_key, right))
        removed, added = left_counts - right_counts, right_counts - left_counts
        def examples(counts):
            return [{"value": json.loads(item), "count": count}
                    for item, count in sorted(counts.items())[:20]]
        return [{"path": path, "left_only": examples(removed), "right_only": examples(added),
                 "left_only_count": sum(removed.values()), "right_only_count": sum(added.values()),
                 "left_examples_truncated": len(removed) > 20, "right_examples_truncated": len(added) > 20}]
    return [] if left == right else [{"path": path, "left": left, "right": right}]


def compare_elf(path_a, path_b):
    """Compare supported objects; every unallowlisted semantic delta fails.

    .note.GNU-stack differences are returned separately as an auxiliary delta
    AND remain in ordinary differences. No optional bypass is provided here.
    """
    left, left_bytes = _read(path_a)
    right, right_bytes = _read(path_b)
    differences = _differences({key: left[key] for key in COMPARABLE_KEYS},
                               {key: right[key] for key in COMPARABLE_KEYS})
    for name in sorted(left_bytes.keys() & right_bytes.keys()):
        if left_bytes[name] != right_bytes[name]:
            differences.append({"path": f"content_sections[{name}].exact_bytes", "equal": False,
                                "left_size": len(left_bytes[name]), "right_size": len(right_bytes[name])})
    stack_left = [s for s in left["content_sections"] if s["name"] == ".note.GNU-stack"]
    stack_right = [s for s in right["content_sections"] if s["name"] == ".note.GNU-stack"]
    return {"schema": COMPARISON_SCHEMA, "equal": not differences,
            "differences": differences, "left": left, "right": right,
            "ignored_metadata": {"left": left["ignored_metadata"], "right": right["ignored_metadata"]},
            "auxiliary_metadata_delta": _differences(stack_left, stack_right, ".note.GNU-stack"),
            "exact_content_bytes_compared": True}
