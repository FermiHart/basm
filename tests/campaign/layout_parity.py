#!/usr/bin/env python3
"""W16 regression: existing layout fixtures and branch farms against frozen W12.

This proves byte parity for selected inputs, not NASM parity or machine-code
semantics. It never executes assembled code or interprets latency as a result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]

def identity(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--elftool", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if out.exists():
        parser.error("output directory must be fresh")
    out.mkdir(parents=True)
    generator = ROOT / "tests/layout/generate.pl"
    fixture_file = ROOT / "tests/layout_stability_test.sh"
    tools = {name: identity(getattr(args, name).resolve()) for name in ("baseline", "candidate", "elftool")}
    receipt = {"schema": "BASM-W16-LAYOUT-PARITY-v1", "tools": tools,
               "scope": "HOST_DIAGNOSTIC_BYTE_PARITY_NOT_NASM_OR_SEMANTIC_PROOF",
               "inputs": [identity(generator), identity(fixture_file), identity(Path(__file__))],
               "seed": 1, "farm_count": 32, "cases": [], "commands": []}
    shutil.copyfile(generator, out / generator.name)
    shutil.copyfile(fixture_file, out / fixture_file.name)
    shutil.copyfile(__file__, out / "layout_parity.py")
    started = time.monotonic()
    try:
        perl = shutil.which("perl")
        if not perl:
            raise RuntimeError("Perl is required by the retained branch-farm generator")
        generated = subprocess.run([perl, str(out / generator.name), "1", "32"], capture_output=True, text=True, check=True, timeout=5).stdout
        sources = [("farm-%02d" % i, text) for i, text in enumerate(generated.split("%%CASE%%\n"))]
        sources += re.findall(r'cat >"\$TMP/([^"\n]+)\.basm" <<\'EOF\'\n(.*?)\nEOF', fixture_file.read_text(), re.S)
        if len(sources) != 35:
            raise RuntimeError("existing fixture corpus changed; review extraction")
        def run(argv, tag):
            if time.monotonic() - started > 25:
                raise RuntimeError("aggregate functional-test budget exhausted")
            result = subprocess.run(argv, capture_output=True, timeout=5)
            (out / (tag + ".stdout")).write_bytes(result.stdout)
            (out / (tag + ".stderr")).write_bytes(result.stderr)
            receipt["commands"].append({"argv": argv, "returncode": result.returncode,
                                         "stdout": str(out / (tag + ".stdout")), "stderr": str(out / (tag + ".stderr"))})
            if result.returncode:
                raise RuntimeError("fixture command failed: " + tag)
        for name, text in sources:
            source = out / (name + ".basm")
            source.write_text(text.rstrip("\n") + "\n")
            objects = {}
            for role in ("baseline", "candidate"):
                obj = out / (name + "-" + role + ".o")
                run([tools[role]["path"], "-f", "elf64", "-o", str(obj), str(source)], name + "-" + role)
                objects[role] = identity(obj)
            if objects["baseline"]["sha256"] != objects["candidate"]["sha256"]:
                raise RuntimeError("layout bytes differ: " + name)
            run([tools["elftool"]["path"], "audit", objects["candidate"]["path"]], name + "-audit")
            receipt["cases"].append({"name": name, "source": identity(source), "objects": objects, "status": "PASS"})
        for name, original in tools.items():
            if identity(Path(original["path"])) != original:
                raise RuntimeError("selected tool changed: " + name)
        receipt["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        receipt["status"] = "FAIL"
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(receipt["status"], "W16 layout byte parity:", len(receipt["cases"]), "cases;", out / "result.json")
    return 0 if receipt["status"] == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
