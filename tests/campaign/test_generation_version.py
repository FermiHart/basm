#!/usr/bin/env python3
"""Reject valid legacy attestations in generations while basm retains compatibility.

Real basm produces v2/v3/v4 evidence. Object, proof, checker receipt and manifest
are kept mutually consistent, so the wrapper must reject solely by version.
All seed/key bytes are public synthetic test material; no object is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = ROOT / "tools/publish_generation.py"
CHECKER = ROOT / "tools/contract_check.py"


def identity(path):
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", required=True, type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    basm = args.basm.resolve()
    env = dict(os.environ, SOURCE_DATE_EPOCH="0")
    env.pop("BASM_DDC_COMPILER_HASH", None)
    env.pop("BASM_DDC_COMPILER_PATH", None)
    cases = []

    def run(argv, expected=0):
        result = subprocess.run([str(x) for x in argv], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=30)
        if result.returncode != expected:
            raise AssertionError({"argv": [str(x) for x in argv], "expected": expected,
                                  "returncode": result.returncode,
                                  "stdout": result.stdout[-4000:], "stderr": result.stderr[-4000:]})
        return result

    with tempfile.TemporaryDirectory(prefix="basm-generation-version-") as temporary:
        work = Path(temporary)
        source = work / "max_u64.basm"
        source.write_bytes((ROOT / "contracts/examples/max_u64.basm").read_bytes())
        contract = ROOT / "contracts/max_u64.json"
        seed, trusted = work / "fixture.seed", work / "fixture.pub"
        # Fixed public Ed25519 test vector, selected independently of the proof.
        seed.write_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        trusted.write_bytes(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
        seed.chmod(0o600)

        for signed in (False, True):
            store = work / ("signed" if signed else "unsigned")
            policy = ["--basm", basm, "--root", store, "--source", source, "--contract", contract]
            signing = ["--sign", seed, "--trusted-key", trusted] if signed else []
            verification = ["--trusted-key", trusted] if signed else []
            run([sys.executable, PUBLISHER, "publish", *policy, *signing])
            initial = json.loads(run([sys.executable, PUBLISHER, "verify", *policy, *verification]).stdout)
            assert initial["status"] == "verified"
            assert initial["contract_status"] == "VERIFIED_WITHIN_MODEL"
            assert initial["trust"] == ("external-key-verified" if signed else "integrity-only")
            pointer = store / "current.json"
            manifest = json.loads(pointer.read_text())
            members = {name: store / record["path"] for name, record in manifest["files"].items()}
            assert members["attestation"].read_bytes().startswith(b"basm attestation v4\n")
            cases.append({"version": 4, "signed": signed, "generation": "accepted"})

            for version in (2, 3):
                profile = ["--target-profile", "public"] if version == 3 else []
                sign = ["--sign", seed] if signed else []
                run([basm, "-f", "elf64", "-o", members["object"], *profile,
                     "--emit-attestation", members["attestation"], *sign, source])
                header = ("basm attestation v%d\n" % version).encode()
                assert members["attestation"].read_bytes().startswith(header)
                mode = "--verify-attestation-strict" if signed else "--verify-attestation"
                run([basm, mode, members["attestation"], *verification])

                # Regenerate the receipt for the actual replacement object;
                # profile-related object differences cannot cause a stale hash failure.
                checked = run([sys.executable, CHECKER, "--object", members["object"],
                               "--contract", contract, "--source", source])
                report = json.loads(checked.stdout)
                assert report["status"] == "VERIFIED_WITHIN_MODEL"
                assert report["properties"]["functional_result"] == "NOT_CHECKED"
                members["contract_result"].chmod(0o644)
                members["contract_result"].write_text(checked.stdout)
                members["contract_result"].chmod(0o444)
                for name, path in members.items():
                    manifest["files"][name].update(identity(path))
                pointer.write_text(json.dumps(manifest, sort_keys=True) + "\n")

                refused = run([sys.executable, PUBLISHER, "verify", *policy, *verification], expected=1)
                rejection = json.loads(refused.stderr)
                assert rejection["status"] == "rejected", rejection
                assert rejection["reason"] == "generation requires attestation v4", rejection
                cases.append({"version": version, "signed": signed,
                              "basm_compatibility": "accepted", "contract_check": "accepted",
                              "manifest_digests": "updated", "generation": "rejected",
                              "reason": rejection["reason"]})

    result = {"suite": "generation-version-policy", "passed": len(cases),
              "basm_sha256": identity(basm)["sha256"],
              "publisher_sha256": identity(PUBLISHER)["sha256"],
              "object_code_executed": False, "cases": cases}
    assert len(cases) == 6
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.json:
        args.json.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
