#!/usr/bin/env python3
"""Synthetic independent ELF parity tests. No assembler or emitted code runs."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from nasm_elf import ElfFormatError, compare_elf, normalize_elf


def elf_fixture(*, repack=False, anonymous_sections=False, file_name="left.asm",
                include_stack=True, text=None, symbol_changes=None, relocation_changes=None,
                section_changes=None, extra_section=False, reverse_relocations=False,
                second_relocation=False):
    """Write an independent ET_REL fixture with configurable storage and meaning."""
    text = bytes(range(16)) if text is None else text
    # type, flags, payload, memory-size, link-name, info-target, align, entsize
    sections = {
        ".text": [1, 6, text, len(text), None, None, 16, 0],
        ".data": [1, 3, b"D" * 16, 16, None, None, 8, 0],
        ".bss": [8, 3, b"", 32, None, None, 8, 0],
    }
    if include_stack:
        sections[".note.GNU-stack"] = [1, 0, b"", 0, None, None, 1, 0]
    if extra_section:
        sections[".arbitrary-empty"] = [1, 0, b"", 0, None, None, 1, 0]
    sections.update({
        ".shstrtab": [3, 0, b"", 0, None, None, 1, 0],
        ".strtab": [3, 0, b"", 0, None, None, 1, 0],
        ".symtab": [2, 0, b"", 0, ".strtab", None, 8, 24],
        ".rela.text": [4, 0, b"", 0, ".symtab", ".text", 8, 24],
    })
    if second_relocation:
        sections[".rela.other"] = [4, 0, b"", 0, ".symtab", ".text", 8, 24]
    for name, changes in (section_changes or {}).items():
        fields = {"type": 0, "flags": 1, "payload": 2, "size": 3,
                  "link": 4, "info": 5, "alignment": 6, "entsize": 7}
        for field, value in changes.items():
            sections[name][fields[field]] = value
    symbols = {
        "file": dict(name=file_name, bind=0, type=4, visibility=0, section="ABS", value=0, size=0),
        "text_section": dict(name="" if anonymous_sections else ".text", bind=0, type=3,
                             visibility=0, section=".text", value=0, size=0),
        "data_section": dict(name="" if anonymous_sections else ".data", bind=0, type=3,
                             visibility=0, section=".data", value=0, size=0),
        "local": dict(name="local_label", bind=0, type=0, visibility=0, section=".text", value=12, size=0),
        "entry": dict(name="entry", bind=1, type=2, visibility=0, section=".text", value=0, size=16),
        "external": dict(name="external", bind=1, type=0, visibility=0, section="UNDEF", value=0, size=0),
        "weak": dict(name="weak_object", bind=2, type=1, visibility=0, section=".data", value=0, size=8),
    }
    for name, changes in (symbol_changes or {}).items():
        symbols[name].update(changes)
    locals_ = [name for name, symbol in symbols.items() if symbol["bind"] == 0]
    exports = [name for name, symbol in symbols.items() if symbol["bind"] != 0]
    order = list(sections)
    if repack:
        order.reverse()
        locals_.reverse()
        exports.reverse()
    section_indices = {name: index for index, name in enumerate(order, 1)}
    symbol_order = locals_ + exports
    symbol_indices = {name: index for index, name in enumerate(symbol_order, 1)}
    names = list(order)
    if repack:
        names.reverse()
    section_names = bytearray(b"\0")
    name_offsets = {}
    for name in names:
        name_offsets[name] = len(section_names)
        section_names.extend(name.encode() + b"\0")
    string_names = sorted({symbol["name"] for symbol in symbols.values() if symbol["name"]}, reverse=repack)
    symbol_strings = bytearray(b"\0padding\0" if repack else b"\0")
    string_offsets = {"": 0}
    for name in string_names:
        string_offsets[name] = len(symbol_strings)
        symbol_strings.extend(name.encode() + b"\0")
    symbytes = bytearray(24)
    for name in symbol_order:
        symbol = symbols[name]
        section = symbol["section"]
        ndx = {"ABS": 0xFFF1, "COMMON": 0xFFF2, "UNDEF": 0}.get(section, section_indices.get(section))
        symbytes.extend(struct.pack("<IBBHQQ", string_offsets[symbol["name"]],
                                    symbol["bind"] << 4 | symbol["type"], symbol["visibility"], ndx,
                                    symbol["value"], symbol["size"]))
    relocations = [dict(offset=0, type=1, symbol="external", addend=7),
                   dict(offset=8, type=2, symbol="data_section", addend=0)]
    for index, changes in (relocation_changes or {}).items():
        relocations[index].update(changes)
    if reverse_relocations:
        relocations.reverse()
    relabytes = b"".join(struct.pack("<QQq", r["offset"], symbol_indices[r["symbol"]] << 32 | r["type"],
                                     r["addend"]) for r in relocations)
    for name, payload in ((".shstrtab", section_names), (".strtab", symbol_strings),
                          (".symtab", symbytes), (".rela.text", relabytes)):
        sections[name][2] = bytes(payload)
        sections[name][3] = len(payload)
    sections[".symtab"][5] = len(locals_) + 1
    if second_relocation:
        sections[".rela.other"][2:4] = [relabytes, len(relabytes)]
    blob = bytearray(64 + 64 * (len(order) + 1))
    headers = {}
    for name in order:
        typ, flags, payload, size, link, info, align, entsize = sections[name]
        if repack:
            blob.extend(b"PADDING!")
        while len(blob) % max(align, 1):
            blob.append(0)
        off = len(blob)
        if typ != 8:
            blob.extend(payload)
        header = 64 + 64 * section_indices[name]
        link = section_indices[link] if isinstance(link, str) else (link or 0)
        info = section_indices[info] if isinstance(info, str) else (info or 0)
        struct.pack_into("<IIQQQQIIQQ", blob, header, name_offsets[name], typ, flags, 0,
                         off, size, link, info, align, entsize)
        headers[name] = dict(header=header, offset=off, size=size)
    struct.pack_into("<16sHHIQQQIHHHHHH", blob, 0, b"\x7fELF\x02\x01\x01" + bytes(9),
                     1, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, len(order) + 1,
                     section_indices[".shstrtab"])
    return blob, headers, symbol_indices


class StrictElfParityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bearbasm-nasm-elf-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.number = 0
        self.raw, self.headers, self.symbols = elf_fixture()
        self.original = self.save(self.raw)

    def save(self, raw):
        self.number += 1
        path = self.dir / f"fixture-{self.number}.o"
        path.write_bytes(raw)
        return path

    def compare(self, **kwargs):
        raw, _, _ = elf_fixture(**kwargs)
        return compare_elf(self.original, self.save(raw))

    def changed(self, offset, fmt, value):
        raw = bytearray(self.raw)
        struct.pack_into("<" + fmt, raw, offset, value)
        return raw

    def reject(self, raw, message=None):
        with self.assertRaisesRegex(ElfFormatError, message or ".+"):
            normalize_elf(self.save(raw))

    def test_valid_model_json_and_exact_self_parity(self):
        result = compare_elf(self.original, self.original)
        self.assertTrue(result["equal"])
        self.assertTrue(result["exact_content_bytes_compared"])
        self.assertEqual(result["differences"], [])
        json.dumps(result)
        model = normalize_elf(self.original)
        self.assertEqual(len(model["exported_symbols"]), 3)
        self.assertEqual(len(model["local_symbols"]), 1)
        self.assertEqual(len(model["relocations"]), 2)

    def test_section_symbol_string_index_order_repacking_is_equal(self):
        result = self.compare(repack=True, anonymous_sections=True, file_name="right.asm",
                              reverse_relocations=True)
        self.assertTrue(result["equal"], result["differences"])
        self.assertNotEqual(result["ignored_metadata"]["left"], result["ignored_metadata"]["right"])

    def test_exact_byte_change_fails_even_with_digest_collision(self):
        class ConstantDigest:
            def hexdigest(self):
                return "0" * 64
        with mock.patch("nasm_elf.hashlib.sha256", return_value=ConstantDigest()):
            result = self.compare(text=b"X" + bytes(range(1, 16)))
        self.assertFalse(result["equal"])
        self.assertTrue(any(d["path"].endswith(".exact_bytes") for d in result["differences"]))

    def test_content_attributes_and_nobits_size_are_compared(self):
        for name, changes in ((".text", {"flags": 2}), (".text", {"alignment": 8}),
                              (".bss", {"size": 64}), (".data", {"type": 7}),
                              (".data", {"entsize": 8})):
            with self.subTest(name=name, changes=changes):
                result = self.compare(section_changes={name: changes})
                self.assertFalse(result["equal"])

    def test_arbitrary_empty_section_is_not_ignored(self):
        result = self.compare(extra_section=True)
        self.assertFalse(result["equal"])
        self.assertEqual(result["auxiliary_metadata_delta"], [])

    def test_stack_marker_missing_or_executable_fails_with_auxiliary_delta(self):
        for kwargs in ({"include_stack": False},
                       {"section_changes": {".note.GNU-stack": {"flags": 4}}}):
            with self.subTest(kwargs=kwargs):
                result = self.compare(**kwargs)
                self.assertFalse(result["equal"])
                self.assertTrue(result["auxiliary_metadata_delta"])

    def test_global_and_weak_linkage_definition_changes_fail(self):
        for symbol, changes in (("entry", {"bind": 2}), ("entry", {"type": 0}),
                                 ("entry", {"visibility": 2}), ("entry", {"size": 15}),
                                 ("entry", {"value": 1, "size": 15}),
                                 ("entry", {"name": "renamed"}), ("entry", {"section": ".data"}),
                                 ("weak", {"bind": 1})):
            with self.subTest(symbol=symbol, changes=changes):
                result = self.compare(symbol_changes={symbol: changes})
                self.assertFalse(result["equal"])

    def test_unreferenced_application_local_is_not_erased(self):
        for changes in ({"name": "renamed_local"}, {"value": 13}, {"type": 1}, {"size": 1}):
            with self.subTest(changes=changes):
                self.assertFalse(self.compare(symbol_changes={"local": changes})["equal"])

    def test_referenced_local_meaning_is_preserved(self):
        raw, _, _ = elf_fixture(relocation_changes={0: {"symbol": "local"}})
        self.original = self.save(raw)
        result = self.compare(relocation_changes={0: {"symbol": "local"}},
                              symbol_changes={"local": {"value": 13}})
        self.assertFalse(result["equal"])
        self.assertTrue(any(d["path"] == "relocations" for d in result["differences"]))

    def test_relocation_type_addend_offset_symbol_and_target_changes_fail(self):
        for changes in ({"type": 24}, {"addend": -7}, {"offset": 1, "type": 2},
                        {"symbol": "weak"}):
            with self.subTest(changes=changes):
                self.assertFalse(self.compare(relocation_changes={0: changes})["equal"])
        result = self.compare(section_changes={".rela.text": {"info": ".data"}})
        self.assertFalse(result["equal"])

    def test_header_architecture_and_section_table_bounds_rejected(self):
        for offset, fmt, value in ((4, "B", 1), (5, "B", 2), (16, "H", 2), (18, "H", 3),
                                   (40, "Q", (1 << 64) - 8), (40, "Q", 0),
                                   (58, "H", 63), (60, "H", 0), (60, "H", 65535),
                                   (62, "H", 65535), (52, "H", 63), (6, "B", 0)):
            with self.subTest(offset=offset, value=value):
                self.reject(self.changed(offset, fmt, value))
        self.reject(self.raw[:63])

    def test_file_backed_spans_overlaps_and_alignment_rejected(self):
        for name in (".text", ".data", ".shstrtab", ".strtab", ".symtab", ".rela.text"):
            header = self.headers[name]["header"]
            with self.subTest(section=name):
                self.reject(self.changed(header + 24, "Q", (1 << 64) - 16))
                self.reject(self.changed(header + 32, "Q", (1 << 64) - 16))
        self.reject(self.changed(self.headers[".data"]["header"] + 24, "Q", self.headers[".text"]["offset"]),
                    "overlapping")
        self.reject(self.changed(self.headers[".text"]["header"] + 48, "Q", 3), "power of two")

    def test_duplicate_names_and_unterminated_strings_rejected(self):
        original_name = struct.unpack_from("<I", self.raw, self.headers[".text"]["header"])[0]
        self.reject(self.changed(self.headers[".data"]["header"], "I", original_name), "duplicate")
        for name in (".strtab", ".shstrtab"):
            with self.subTest(section=name):
                self.reject(self.changed(self.headers[name]["offset"] + self.headers[name]["size"] - 1,
                                         "B", 65), "start/end with NUL")
        entry = self.headers[".symtab"]["offset"] + self.symbols["entry"] * 24
        self.reject(self.changed(entry, "I", self.headers[".strtab"]["size"]), "string offset")

    def test_invalid_links_entry_sizes_and_symbol_indices_rejected(self):
        for name in (".symtab", ".rela.text"):
            header = self.headers[name]["header"]
            with self.subTest(section=name):
                self.reject(self.changed(header + 40, "I", 1), "link")
                self.reject(self.changed(header + 56, "Q", 16), "entry size")
        rel = self.headers[".rela.text"]["offset"]
        self.reject(self.changed(rel + 8, "Q", (1000 << 32) | 1), "symbol index")
        self.reject(self.changed(self.headers[".rela.text"]["header"] + 44, "I", 0), "target index")
        self.reject(self.changed(self.headers[".symtab"]["header"] + 44, "I", 1), "partition")

    def test_rel_unknown_types_flags_and_invalid_relocation_fields_rejected(self):
        self.reject(self.changed(self.headers[".rela.text"]["header"] + 4, "I", 9), "SHT_REL")
        self.reject(self.changed(self.headers[".text"]["header"] + 4, "I", 17), "unsupported section type")
        self.reject(self.changed(self.headers[".text"]["header"] + 8, "Q", 0x800), "unsupported content flags")
        rel = self.headers[".rela.text"]["offset"]
        self.reject(self.changed(rel + 8, "Q", (self.symbols["external"] << 32) | 255), "relocation type")
        for rtype in (41, 42):
            self.reject(self.changed(rel + 8, "Q", (self.symbols["external"] << 32) | rtype),
                        "relocation type")
        self.reject(self.changed(rel, "Q", 15), "outside target")
        self.reject(self.changed(rel + 24, "Q", 4), "overlapping relocation")

    def test_cross_section_relocation_overlap_rejected(self):
        raw, _, _ = elf_fixture(second_relocation=True)
        self.reject(raw, "overlapping relocation")

    def test_symbols_in_noncontent_tables_rejected(self):
        for symbol, section in (("entry", ".strtab"), ("entry", ".rela.text"),
                                 ("data_section", ".rela.text")):
            with self.subTest(symbol=symbol, section=section):
                raw, _, _ = elf_fixture(symbol_changes={symbol: {"section": section}})
                self.reject(raw, "storage/relocation table")

    def test_storage_typed_stack_and_ambiguous_globals_rejected(self):
        raw, _, _ = elf_fixture(section_changes={".note.GNU-stack": {
            "type": 3, "payload": b"\0", "size": 1}})
        self.reject(raw, "GNU-stack")
        raw, _, _ = elf_fixture(symbol_changes={"weak": {"name": "entry"}})
        self.reject(raw, "duplicate global/weak")

    def test_aggregate_relocation_receipt_budget_is_enforced(self):
        model = normalize_elf(self.original)
        from nasm_elf import _key
        one_entry_limit = max(len(_key(entry)) for entry in model["relocations"])
        with mock.patch("nasm_elf.MAX_CANONICAL_RELOCATION_BYTES", one_entry_limit):
            self.reject(self.raw, "canonical relocations")

    def test_symbol_partition_visibility_bounds_and_section_indices_rejected(self):
        entry = self.headers[".symtab"]["offset"] + self.symbols["entry"] * 24
        for offset, fmt, value in ((4, "B", 0xF2), (4, "B", 0x1F), (5, "B", 0x80),
                                   (6, "H", 0xFFFF), (8, "Q", 17), (16, "Q", 17)):
            with self.subTest(offset=offset, value=value):
                self.reject(self.changed(entry + offset, fmt, value))

    def test_differences_are_bounded_and_preserve_multiplicity(self):
        # Exercise receipt diagnostics directly without generating a giant ELF.
        from nasm_elf import _differences
        result = _differences([{"name": f"left-{i}"} for i in range(40)] + [{"name": "dup"}] * 2,
                              [{"name": f"right-{i}"} for i in range(50)] + [{"name": "dup"}], "symbols")
        self.assertEqual(result[0]["left_only_count"], 41)
        self.assertEqual(result[0]["right_only_count"], 50)
        self.assertEqual(len(result[0]["left_only"]), 20)
        self.assertTrue(result[0]["left_examples_truncated"])
        self.assertTrue(result[0]["right_examples_truncated"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
