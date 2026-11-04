#!/usr/bin/env python3
"""W23-W28: independent-byte ABI pilot, hostile inputs, and a real C consumer.

Only the reviewed max_u64 fixture is executed, after independent GAS byte parity
and checker acceptance. Malformed objects, mutations and CPUID fixtures are
never linked for execution. BASM_CANDIDATE selects an explicit tested lane.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("contract_check_under_test", ROOT / "tools/contract_check.py")
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)
MAX_BYTES = bytes.fromhex("53 48 89 fb 48 39 f3 73 03 48 89 f3 48 89 d8 5b c3")


def object_bytes(code, relocation=False):
    """An independently constructed, small ELF ET_REL fixture, no assembler."""
    names = b"\0.text\0.strtab\0.symtab\0.shstrtab\0.rela.text\0"
    payloads = [bytes(code), b"\0f\0", b"\0" * 24 + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, len(code)), names]
    if relocation:
        payloads.append(struct.pack("<QQq", 0, (1 << 32) | 2, 0))
    data = bytearray(64)
    headers = [(0,) * 10]
    descriptions = [(1, 1, 6, 0, 0, 1, 0), (7, 3, 0, 0, 0, 1, 0),
                    (15, 2, 0, 2, 1, 8, 24), (23, 3, 0, 0, 0, 1, 0)]
    if relocation:
        descriptions.append((33, 4, 0, 3, 1, 8, 24))
    for payload, description in zip(payloads, descriptions):
        name, kind, flags, link, info, align, entsize = description
        while len(data) % align:
            data.append(0)
        offset = len(data)
        data.extend(payload)
        headers.append((name, kind, flags, 0, offset, len(payload), link, info, align, entsize))
    while len(data) % 8:
        data.append(0)
    shoff = len(data)
    for header in headers:
        data.extend(struct.pack("<IIQQQQIIQQ", *header))
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), 4)
    return data


def base_contract():
    return {"schema": "bearbasm-contract-v1", "function": "f", "abi": "sysv-amd64",
            "domain": "hosted-user", "requires": {"features": ["base"], "os_state": {}},
            "clobbers": [checker.REGS[i] for i in checker.CALLER] + ["rflags"], "max_stack_bytes": 64}


class Contracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="basm-contracts-")
        self.root = Path(self.temp.name)
        self.obj = self.root / "case.o"
        self.contract = self.root / "contract.json"

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self, code=b"\xc3", contract=None, target=None, raw=None, source=None, expected=None):
        self.obj.write_bytes(object_bytes(code) if raw is None else raw)
        self.contract.write_text(json.dumps(contract if contract is not None else base_contract()))
        target_path = source_path = expected_path = None
        if target is not None:
            target_path = self.root / "target.json"
            target_path.write_text(json.dumps(target))
        if source is not None:
            source_path = self.root / "source.basm"
            source_path.write_bytes(source)
        if expected is not None:
            expected_path = self.root / "expected.json"
            expected_path.write_text(json.dumps(expected))
        return checker.check(self.obj, self.contract, target_path, source_path, expected_path)

    def accepted(self, result):
        self.assertEqual(result["status"], "VERIFIED_WITHIN_MODEL", result.get("diagnostics"))
        self.assertEqual(result["properties"]["functional_result"], "NOT_CHECKED")

    def refused(self, result, code=None, status=None):
        self.assertNotEqual(result["status"], "VERIFIED_WITHIN_MODEL", result)
        if code:
            self.assertEqual(result["diagnostics"][0]["code"], code, result)
        if status:
            self.assertEqual(result["status"], status)

    def test_inventory_is_generated_from_closed_checker_model(self):
        expected = {"schema": "bearbasm-contract-model-v1", "model": checker.MODEL,
                    "forms": list(checker.FORMS), "limits": checker.LIMITS}
        self.assertEqual(json.loads((ROOT / "contracts/instruction-forms-v1.json").read_text()), expected)
        self.assertEqual(len(checker.OPCODES), sum(len(form["opcodes"]) for form in checker.FORMS))

    def test_maximum_fixture_abi_and_concrete_operands(self):
        result = self.run_check(MAX_BYTES)
        self.accepted(result)
        self.assertEqual(result["analysis"]["max_stack_bytes"], 8)
        self.assertEqual(result["analysis"]["net_clobbers"], ["rax", "rflags"])
        self.assertEqual(result["instructions"][1]["operands"], ["rbx", "rdi"])
        self.assertEqual(result["instructions"][3]["operands"], [{"function_offset": 12}])
        self.assertIn("DECLARED_TARGET", result["properties"]["cpu_requirements"])

    def test_callee_save_violation_has_causal_path_and_source_hint(self):
        contract = base_contract()
        source = b"mov rbx, rdi\nret\n"
        contract["source"] = {"label": "example.basm", "sha256": hashlib.sha256(source).hexdigest(),
                              "locations": [{"offset": 0, "line": 1}, {"offset": 3, "line": 2}]}
        result = self.run_check(bytes.fromhex("48 89 fb c3"), contract, source=source)
        self.refused(result, "CALLEE_SAVED")
        diagnostic = result["diagnostics"][0]
        self.assertEqual(diagnostic["path_offsets"], [0, 3])
        self.assertEqual(diagnostic["details"], {"register": "rbx"})
        self.assertEqual(diagnostic["file_offset"], 67)
        self.assertEqual(diagnostic["source"]["line"], 2)
        self.assertEqual(diagnostic["source"]["status"], "DECLARED_DIAGNOSTIC_HINT")

    def test_32_bit_self_copy_does_not_preserve_callee_64_bits(self):
        self.accepted(self.run_check(bytes.fromhex("48 89 db c3")))
        self.refused(self.run_check(bytes.fromhex("89 db c3")), "CALLEE_SAVED")

    def test_high_register_operand_binding_and_stack_restore(self):
        result = self.run_check(bytes.fromhex("41 54 49 89 fc 41 5c c3"))
        self.accepted(result)
        self.assertEqual(result["instructions"][1]["operands"], ["r12", "rdi"])
        self.refused(self.run_check(bytes.fromhex("41 89 fc c3")), "CALLEE_SAVED")

    def test_unbalanced_stack_and_read_above_entry(self):
        self.refused(self.run_check(bytes.fromhex("53 c3")), "STACK_UNBALANCED")
        self.refused(self.run_check(bytes.fromhex("5b c3")), "STACK_READ")

    def test_stack_adjustment_and_uninitialized_slot(self):
        result = self.run_check(bytes.fromhex("48 83 ec 20 48 83 c4 20 c3"))
        self.accepted(result)
        self.assertEqual(result["analysis"]["max_stack_bytes"], 32)
        self.refused(self.run_check(bytes.fromhex("48 83 ec 08 58 c3")), "STACK_READ")
        self.refused(self.run_check(bytes.fromhex("48 83 c4 08 c3")), "STACK_ESCAPE")
        self.refused(self.run_check(bytes.fromhex("48 83 ec 03 c3")), "STACK_ADJUST_RANGE")

    def test_contract_stack_limit_is_enforced(self):
        contract = base_contract()
        contract["max_stack_bytes"] = 0
        self.refused(self.run_check(bytes.fromhex("53 5b c3"), contract), "STACK_BUDGET")
        for budget in (True, -8, 1, 520, 2 ** 63):
            with self.subTest(budget=budget):
                contract["max_stack_bytes"] = budget
                self.refused(self.run_check(contract=contract), "CONTRACT_STACK")

    def test_undeclared_clobber_is_rejected(self):
        contract = base_contract()
        contract["clobbers"] = ["rax"]
        self.refused(self.run_check(bytes.fromhex("48 39 f7 c3"), contract), "CLOBBER_UNDECLARED")
        contract["clobbers"] = []
        self.refused(self.run_check(bytes.fromhex("48 89 f8 c3"), contract), "CLOBBER_UNDECLARED")

    def test_direction_flag_obligation(self):
        self.refused(self.run_check(bytes.fromhex("fd c3")), "DIRECTION_FLAG")
        self.accepted(self.run_check(bytes.fromhex("fd fc c3")))

    def test_unknown_memory_rsp_call_and_privileged_instructions(self):
        for data in ("48 8b 07 c3", "48 89 fc c3", "5c c3", "e8 00 00 00 00 c3",
                     "0f 05 c3", "0f 01 d0 c3", "fa c3", "f0 48 31 c0 c3", "66 89 db c3", "90 0f 0b"):
            with self.subTest(data=data):
                self.refused(self.run_check(bytes.fromhex(data)), status="UNPROVEN")

    def test_truncation_is_not_silent_success(self):
        for data in ("48", "0f", "48 89", "e9 00", "0f 84 00"):
            with self.subTest(data=data):
                self.refused(self.run_check(bytes.fromhex(data)), "DECODE_TRUNCATED")

    def test_branch_into_middle_outside_or_cycle(self):
        self.refused(self.run_check(bytes.fromhex("eb 01 48 89 f8 c3")), "BRANCH_TARGET")
        self.refused(self.run_check(bytes.fromhex("eb 7f c3")), "BRANCH_TARGET")
        self.refused(self.run_check(bytes.fromhex("eb fe c3")), "CONTROL_CYCLE", "UNPROVEN")

    def test_all_paths_and_fallthrough_are_checked(self):
        result = self.run_check(bytes.fromhex("48 39 f7 73 03 48 89 f3 c3"))
        self.refused(result, "CALLEE_SAVED")
        self.assertEqual(result["diagnostics"][0]["path_offsets"], [0, 3, 5, 8])
        self.refused(self.run_check(b"\x90"), "MISSING_RETURN")

    def test_all_short_and_near_condition_forms(self):
        for condition in range(16):
            with self.subTest(condition=condition):
                self.accepted(self.run_check(bytes([0x70 + condition, 1, 0x90, 0xc3])))
                self.accepted(self.run_check(bytes([0x0f, 0x80 + condition, 1, 0, 0, 0, 0x90, 0xc3])))

    def test_required_cpu_and_os_state_are_independently_derived(self):
        data = bytes.fromhex("53 0f a2 5b c3")
        self.refused(self.run_check(data), "REQUIREMENT_UNDECLARED")
        contract = base_contract()
        contract["requires"] = {"features": ["base", "cpuid"], "os_state": {"cpuid_user_enabled": True}}
        self.refused(self.run_check(data, contract), "TARGET_REQUIREMENT", "UNPROVEN")
        target = copy.deepcopy(checker.DEFAULT_TARGET)
        target.update(features=["base", "cpuid"], os_state={"cpuid_user_enabled": False})
        self.refused(self.run_check(data, contract, target), "TARGET_REQUIREMENT", "UNPROVEN")
        target["os_state"]["cpuid_user_enabled"] = True
        self.accepted(self.run_check(data, contract, target))
        self.refused(self.run_check(bytes.fromhex("0f a2 c3"), contract, target), "CALLEE_SAVED")

    def test_contract_cannot_disable_policy_or_expand_model(self):
        for key, value in (("domain", "kernel"), ("abi", "private"), ("schema", "next-version")):
            contract = base_contract()
            contract[key] = value
            self.refused(self.run_check(contract=contract), "CONTRACT_MODEL", "UNPROVEN")
        contract = base_contract()
        contract["clobbers"].append("rbx")
        self.refused(self.run_check(contract=contract), "SCHEMA_VALUE")
        contract = base_contract()
        contract["skip_unknown"] = True
        self.refused(self.run_check(contract=contract), "SCHEMA_MEMBERS")

    def test_receipt_is_invalidated_by_abi_equivalent_byte_change(self):
        original = self.run_check(bytes.fromhex("90 c3"))
        self.accepted(original)
        self.accepted(self.run_check(bytes.fromhex("90 c3"), expected=original))
        self.accepted(self.run_check(bytes.fromhex("fc c3")))
        self.refused(self.run_check(bytes.fromhex("fc c3"), expected=original), "RECEIPT_IDENTITY")

    def test_receipt_pins_contract_and_target_and_does_not_grant_trust(self):
        contract = base_contract()
        original = self.run_check(contract=contract)
        contract["max_stack_bytes"] = 8
        self.refused(self.run_check(contract=contract, expected=original), "RECEIPT_IDENTITY")
        target = copy.deepcopy(checker.DEFAULT_TARGET)
        target["features"].append("cpuid")
        self.refused(self.run_check(target=target, expected=original), "RECEIPT_IDENTITY")
        fake = self.run_check(bytes.fromhex("48 89 fb c3"))
        fake["status"] = "VERIFIED_WITHIN_MODEL"
        self.refused(self.run_check(bytes.fromhex("48 89 fb c3"), expected=fake), "CALLEE_SAVED")

    def test_source_identity_and_hints_are_bounded(self):
        contract = base_contract()
        source = b"ret\n"
        contract["source"] = {"label": "source.basm", "sha256": hashlib.sha256(source).hexdigest(),
                              "locations": [{"offset": 0, "line": 1}]}
        self.accepted(self.run_check(contract=contract, source=source))
        self.refused(self.run_check(contract=contract, source=b"nop\n"), "SOURCE_BINDING")
        self.refused(self.run_check(contract=contract), "SOURCE_BINDING")
        contract["source"]["locations"][0]["line"] = 999
        self.refused(self.run_check(contract=contract, source=source), "SOURCE_MAP_LINE")
        contract["source"]["locations"][0] = {"offset": 1, "line": 1}
        self.refused(self.run_check(bytes.fromhex("48 89 f8 c3"), contract=contract, source=source), "SOURCE_MAP_OFFSET")

    def test_contract_difference_reports_obligations_without_authorizing(self):
        before = base_contract()
        after = copy.deepcopy(before)
        after["max_stack_bytes"] = 32
        after["clobbers"] = ["rax"]
        after["requires"] = {"features": ["base", "cpuid"], "os_state": {"cpuid_user_enabled": True}}
        self.contract.write_text(json.dumps(before))
        after_path = self.root / "after.json"
        after_path.write_text(json.dumps(after))
        diff = checker.compare_contracts(self.contract, after_path)
        self.assertEqual({change["field"] for change in diff["changes"]}, {"max_stack_bytes", "clobbers", "requires"})
        self.assertEqual(diff["status"], "DIFF_ONLY")
        self.assertFalse(diff["authorizes_publication"])
        self.assertTrue(diff["requires_reverification"])
        self.assertIn("rbx", diff["mandatory_callee_saved"])
        completed = subprocess.run([sys.executable, str(ROOT / "tools/contract_check.py"), "--compare-contracts",
                                    str(self.contract), str(after_path)], check=True, capture_output=True, timeout=5)
        self.assertEqual(json.loads(completed.stdout), diff)

    def test_elf_range_overflow_and_section_table_bounds(self):
        data = object_bytes(b"\xc3")
        shoff = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<QQ", data, shoff + 64 + 24, 2 ** 64 - 16, 32)
        self.refused(self.run_check(raw=data), "ELF_CONTENT_RANGE")
        data = object_bytes(b"\xc3")
        struct.pack_into("<Q", data, 40, 2 ** 64 - 8)
        self.refused(self.run_check(raw=data), "ELF_SECTION_RANGE")

    def test_elf_symbols_links_extents_and_names(self):
        for change, error in (("link", "ELF_SYMBOL_NAMES"), ("extent", "ELF_SYMBOL_RANGE"),
                              ("entrysize", "ELF_SYMBOL_SIZE"), ("name", "ELF_STRING_RANGE")):
            with self.subTest(change=change):
                data = object_bytes(b"\xc3")
                shoff = struct.unpack_from("<Q", data, 40)[0]
                symoff = struct.unpack_from("<Q", data, shoff + 3 * 64 + 24)[0]
                if change == "link": struct.pack_into("<I", data, shoff + 3 * 64 + 40, 127)
                if change == "extent": struct.pack_into("<Q", data, symoff + 24 + 16, 2 ** 64 - 1)
                if change == "entrysize": struct.pack_into("<Q", data, shoff + 3 * 64 + 56, 0)
                if change == "name": struct.pack_into("<I", data, symoff + 24, 0xffffffff)
                self.refused(self.run_check(raw=data), error)

    def test_relocations_are_checked_before_semantic_admission(self):
        self.refused(self.run_check(raw=object_bytes(bytes.fromhex("48 89 f8 c3"), True)), "FUNCTION_RELOCATION", "UNPROVEN")
        data = object_bytes(bytes.fromhex("48 89 f8 c3"), True)
        shoff = struct.unpack_from("<Q", data, 40)[0]
        relocation = struct.unpack_from("<Q", data, shoff + 5 * 64 + 24)[0]
        struct.pack_into("<Q", data, relocation, 2 ** 64 - 1)
        self.refused(self.run_check(raw=data), "ELF_RELOCATION_RANGE")

    def test_fixed_instruction_and_state_budgets_fail_closed(self):
        self.refused(self.run_check(b"\x90" * 512 + b"\xc3"), "INSTRUCTION_LIMIT", "UNPROVEN")
        data = bytearray()
        for reg in checker.CALLER:
            rex = 0x4d if reg >= 8 else 0x48
            low = reg & 7
            data.extend([0x74, 3, rex, 0x31, 0xc0 | (low << 3) | low])
        data.append(0xc3)
        self.refused(self.run_check(data), "ANALYSIS_BUDGET", "UNPROVEN")

    def test_json_duplicate_unknown_and_nonfinite(self):
        self.obj.write_bytes(object_bytes(b"\xc3"))
        for data, code in ((b'{"schema":1,"schema":2}', "JSON_DUPLICATE"),
                           (b'{"number":NaN}', "JSON_NUMBER"), (b'[' * 20 + b'0' + b']' * 20, "JSON_DEPTH")):
            self.contract.write_bytes(data)
            self.refused(checker.check(self.obj, self.contract), code)

    def test_cli_errors_are_structured_and_inventory_is_read_only(self):
        command = [sys.executable, str(ROOT / "tools/contract_check.py")]
        for args in ([], ["--unknown"], ["--describe", "--object", "arbitrary"]):
            result = subprocess.run(command + args, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["schema"], checker.RESULT_SCHEMA)
            self.assertNotIn(b"Traceback", result.stderr)
        result = subprocess.run(command + ["--describe"], capture_output=True, timeout=5, check=True)
        self.assertEqual(json.loads(result.stdout)["limits"], checker.LIMITS)

    def test_nonregular_and_oversize_input_refuse(self):
        self.contract.write_text(json.dumps(base_contract()))
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        self.refused(checker.check(fifo, self.contract), "INPUT_NOT_REGULAR")
        with self.obj.open("wb") as stream:
            stream.truncate(checker.LIMITS["object_bytes"] + 1)
        self.refused(checker.check(self.obj, self.contract), "INPUT_LIMIT")

    def test_mutated_elf_and_code_do_not_escape_with_python_errors(self):
        rng = random.Random(23028)
        original = object_bytes(MAX_BYTES)
        for case in range(150):
            data = bytearray(original)
            for _ in range(1 + case % 4):
                data[rng.randrange(len(data))] = rng.randrange(256)
            result = self.run_check(raw=data)
            self.assertIn(result["status"], ("REJECTED", "UNPROVEN", "VERIFIED_WITHIN_MODEL"))
            # A mutation preserving the modeled property may pass; the receipt
            # still binds different object bytes, not the earlier identity.
            if result["status"] == "VERIFIED_WITHIN_MODEL":
                self.assertEqual(result["inputs"]["object_sha256"], hashlib.sha256(data).hexdigest())

    def test_gas_oracle_covers_every_declared_form(self):
        cc = shutil.which(os.environ.get("CC", "cc"))
        if not cc:
            self.skipTest("independent GAS oracle requires a host C compiler")
        bodies = [("mov_rr", "mov %rdx,%rcx"), ("mov_rr", "mov %edx,%ecx"),
                  ("add_rr", "add %rdx,%rcx"), ("sub_rr", "sub %rdx,%rcx"),
                  ("xor_rr", "xor %rdx,%rcx"), ("cmp_rr", "cmp %rdx,%rcx"), ("test_rr", "test %rdx,%rcx"),
                  ("push_r64", "push %r12\n pop %r12"), ("pop_r64", "push %r12\n pop %r12"),
                  ("stack_adjust", "sub $256,%rsp\n add $256,%rsp"),
                  ("jmp_rel8", "jmp 1f\n nop\n1:"), ("jmp_rel32", "jmp 1f\n .fill 130,1,0x90\n1:"),
                  ("jcc_rel8", "jae 1f\n nop\n1:"), ("jcc_rel32", "jae 1f\n .fill 130,1,0x90\n1:"),
                  ("nop", "nop"), ("ret", ""), ("cld", "cld"), ("std", "std\n cld"), ("cpuid", "cpuid")]
        source = self.root / "oracle.S"
        lines = [".text"]
        for index, (_form, body) in enumerate(bodies):
            name = f"f{index}"
            lines.extend([f".globl {name}", f".type {name},@function", f"{name}:", body, "ret", f".size {name},.-{name}"])
        lines.append('.section .note.GNU-stack,"",@progbits')
        source.write_text("\n".join(lines) + "\n")
        out = self.root / "oracle.o"
        subprocess.run([cc, "-c", str(source), "-o", str(out)], check=True, capture_output=True, timeout=15)
        data = out.read_bytes()
        forms = set()
        for index, (expected, _body) in enumerate(bodies):
            decoded = checker.decode(checker.ELF(data, f"f{index}").code)
            actual = {i.form for i in decoded.values()}
            self.assertIn(expected, actual)
            forms.update(actual)
        self.assertEqual(forms, {form["id"] for form in checker.FORMS})

    def test_basm_object_is_checked_then_linked_to_real_c_consumer(self):
        candidate = os.environ.get("BASM_CANDIDATE")
        cc = shutil.which(os.environ.get("CC", "cc"))
        if not candidate:
            self.skipTest("set BASM_CANDIDATE to the explicitly selected assembler lane")
        if not cc:
            self.skipTest("real consumer requires a host C compiler/linker")
        basm = str(Path(candidate).resolve())
        example = ROOT / "contracts/examples/max_u64.basm"
        obj = self.root / "max.basm.o"
        subprocess.run([basm, "--target-profile", "public", "-f", "elf64", "-o", str(obj), str(example)],
                       check=True, capture_output=True, timeout=15)
        result = checker.check(obj, ROOT / "contracts/max_u64.json", source_path=example)
        self.accepted(result)
        actual_bytes = checker.ELF(obj.read_bytes(), "bb_max_u64").code
        self.assertEqual(actual_bytes, MAX_BYTES, "Only reviewed bytes may enter the host execution fixture")
        oracle = self.root / "max.gas.o"
        subprocess.run([cc, "-c", str(ROOT / "contracts/examples/max_u64.S"), "-o", str(oracle)],
                       check=True, capture_output=True, timeout=15)
        self.assertEqual(checker.ELF(oracle.read_bytes(), "bb_max_u64").code, actual_bytes,
                         "Independent GAS parity is required before executing the basm fixture")
        executable = self.root / "consumer"
        subprocess.run([cc, "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "contracts/examples/consumer.c"),
                        str(ROOT / "contracts/examples/consumer_probe.S"), str(obj), "-Wl,-z,noexecstack", "-o", str(executable)],
                       check=True, capture_output=True, timeout=15)
        consumer = subprocess.run([str(executable)], check=True, capture_output=True, timeout=5)
        self.assertIn(b"10243 functional/ABI observations", consumer.stdout)
        print(consumer.stdout.decode().strip(), flush=True)
        cpuid_source = ROOT / "contracts/examples/cpuid_leaf.basm"
        cpuid_obj = self.root / "cpuid.o"
        subprocess.run([basm, "--target-profile", "public", "-f", "elf64", "-o", str(cpuid_obj), str(cpuid_source)],
                       check=True, capture_output=True, timeout=15)
        self.accepted(checker.check(cpuid_obj, ROOT / "contracts/cpuid_leaf.json", ROOT / "contracts/target-cpuid.json", cpuid_source))
        # Deliberately no linking or execution of the CPUID fixture.

    def test_gas_oracle_binds_all_gpr_pairs_and_widths(self):
        cc = shutil.which(os.environ.get("CC", "cc"))
        if not cc:
            self.skipTest("independent GPR binding oracle requires a host C compiler")
        lines = [".text"]
        cases = []
        for operation in ("mov", "add", "sub", "xor", "cmp", "test"):
            for width, registers in ((32, checker.REGS32), (64, checker.REGS)):
                name = f"{operation}{width}"
                expected = []
                lines.extend([f".globl {name}", f".type {name},@function", f"{name}:"])
                for dst in range(16):
                    if dst == 4 and operation not in ("cmp", "test"):
                        continue  # General RSP writes are deliberately outside the model.
                    for src in range(16):
                        lines.append(f"{operation} %{registers[src]},%{registers[dst]}")
                        expected.append((dst, src))
                lines.extend(["ret", f".size {name},.-{name}"])
                cases.append((name, operation, width, expected))
        lines.append('.section .note.GNU-stack,"",@progbits')
        source, output = self.root / "pairs.S", self.root / "pairs.o"
        source.write_text("\n".join(lines) + "\n")
        subprocess.run([cc, "-c", str(source), "-o", str(output)], check=True, capture_output=True, timeout=15)
        data = output.read_bytes()
        checked = 0
        for name, operation, width, expected in cases:
            instructions = list(checker.decode(checker.ELF(data, name).code).values())
            self.assertEqual(len(instructions), len(expected) + 1)
            for instruction, (dst, src) in zip(instructions, expected):
                self.assertEqual((instruction.operation, instruction.width, instruction.dst, instruction.src),
                                 (operation, width, dst, src))
                checked += 1
        self.assertEqual(checked, 2944)


if __name__ == "__main__":
    unittest.main(verbosity=2)
