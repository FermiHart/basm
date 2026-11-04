#!/usr/bin/env python3
"""Integration regressions for input ownership and evidence publication."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def run(argv, good=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == good, (argv, result.returncode, result.stderr)
    assert result.returncode >= 0, "process terminated by signal"
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--basm", required=True)
    args = ap.parse_args()
    basm = str(Path(args.basm).resolve())
    tool = Path(__file__).resolve().parents[2] / "tools/publish_generation.py"
    repo = tool.parent.parent
    passed = 0
    with tempfile.TemporaryDirectory(prefix="basm-main-") as temporary:
        root = Path(temporary)
        source = root / "input.basm"
        source_bytes = b"bits 64\nsection .text\nglobal entry\nentry: ret\n"
        source.write_bytes(source_bytes)
        run([basm, "-o", str(source), str(source)], good=False)
        assert source.read_bytes() == source_bytes
        passed += 1
        output, proof = root / "out.o", root / "out.basmproof"
        alias = str(root) + "/./out.o"
        run([basm, "-o", str(output), "--emit-attestation", alias, str(source)], good=False)
        assert not output.exists()
        passed += 1
        output.write_bytes(b"prior object")
        proof.write_bytes(b"prior proof")
        run([basm, "-o", str(output), "--emit-attestation", str(proof),
             "--sign", str(root / "missing-key"), str(source)], good=False)
        assert output.read_bytes() == b"prior object" and proof.read_bytes() == b"prior proof"
        passed += 1
        dep = root / "dep.inc"
        dep.write_bytes(b"nop\n")
        source.write_text('bits 64\nsection .text\n%include "' + str(dep) + '"\nret\n')
        run([basm, "-o", str(dep), str(source)], good=False)
        assert dep.read_bytes() == b"nop\n"
        passed += 1
        source.write_bytes(source_bytes)
        store = root / "published"
        base = [sys.executable, str(tool)]
        run(base + ["publish", "--basm", basm, "--root", str(store), "--source", str(source)])
        pointer = (store / "current.json").read_bytes()
        run(base + ["verify", "--basm", basm, "--root", str(store)])
        source.write_text("bits 64\nunknown_instruction\n")
        run(base + ["publish", "--basm", basm, "--root", str(store), "--source", str(source)], good=False)
        assert (store / "current.json").read_bytes() == pointer
        source.write_bytes(source_bytes)
        run(base + ["verify", "--basm", basm, "--root", str(store)])
        passed += 1
        manifest = json.loads(pointer)
        member = store / manifest["files"]["object"]["path"]
        member.chmod(0o644)
        data = member.read_bytes()
        member.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        run(base + ["verify", "--basm", basm, "--root", str(store)], good=False)
        passed += 1
        # W28: the same real leaf object must pass the independent checker
        # before current.json can select its complete generation.
        contract_source = root / "max_u64.basm"
        original_source = (repo / "contracts/examples/max_u64.basm").read_bytes()
        contract_source.write_bytes(original_source)
        contract = root / "max_u64.json"
        original_contract = (repo / "contracts/max_u64.json").read_bytes()
        contract.write_bytes(original_contract)
        contract_store = root / "contract-published"
        contract_args = ["--basm", basm, "--root", str(contract_store),
                         "--source", str(contract_source), "--contract", str(contract)]
        run(base + ["publish"] + contract_args)
        contract_pointer = (contract_store / "current.json").read_bytes()
        contract_manifest = json.loads(contract_pointer)
        receipt_path = contract_store / contract_manifest["files"]["contract_result"]["path"]
        receipt = json.loads(receipt_path.read_bytes())
        assert receipt["status"] == "VERIFIED_WITHIN_MODEL"
        assert receipt["properties"]["functional_result"] == "NOT_CHECKED"
        verification = run(base + ["verify"] + contract_args)
        assert json.loads(verification.stdout)["contract_status"] == "VERIFIED_WITHIN_MODEL"
        run(base + ["verify", "--basm", basm, "--root", str(contract_store)], good=False)
        passed += 1
        # Source is rebound deliberately so rejection must come from the ABI
        # failure, not merely from an old source hash or a parsing error.
        bad_source = original_source.replace(b"pop rbx", b"pop rcx")
        contract_source.write_bytes(bad_source)
        bad_contract = json.loads(original_contract)
        bad_contract["source"]["sha256"] = hashlib.sha256(bad_source).hexdigest()
        contract.write_text(json.dumps(bad_contract))
        failure = run(base + ["publish"] + contract_args, good=False)
        assert "CALLEE_SAVED" in failure.stderr, failure.stderr
        assert (contract_store / "current.json").read_bytes() == contract_pointer
        assert len(list((contract_store / "generations").iterdir())) == 1
        contract_source.write_bytes(original_source)
        contract.write_bytes(original_contract)
        run(base + ["verify"] + contract_args)
        passed += 1
        # Changing the consumer contract does not reuse an old approval, even
        # when the new stack allowance alone would still accept the function.
        changed_contract = json.loads(original_contract)
        changed_contract["max_stack_bytes"] = 16
        contract.write_text(json.dumps(changed_contract))
        refusal = run(base + ["verify"] + contract_args, good=False)
        assert "RECEIPT_IDENTITY" in refusal.stderr, refusal.stderr
        contract.write_bytes(original_contract)
        passed += 1
        # A manifest edited to drop the receipt cannot satisfy a caller that
        # explicitly requires the contract. No trust label grants that property.
        stripped = json.loads(contract_pointer)
        del stripped["files"]["contract_result"]
        (contract_store / "current.json").write_text(json.dumps(stripped))
        run(base + ["verify"] + contract_args, good=False)
        (contract_store / "current.json").write_bytes(contract_pointer)
        run(base + ["verify"] + contract_args)
        passed += 1
    print(json.dumps({"suite": "main-publication", "passed": passed}))


if __name__ == "__main__":
    main()
