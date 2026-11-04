#!/usr/bin/env python3
"""Compile both SHA modes and compare streaming/tail cases with Python hashlib."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    temp = None
    if args.output_dir:
        output = args.output_dir.resolve()
        output.mkdir(parents=True, exist_ok=False)
    else:
        temp = tempfile.TemporaryDirectory(prefix="basm-sha-modes-")
        output = Path(temp.name)
    executable = output / "sha-modes"
    cc = shutil.which(args.cc)
    if not cc:
        raise SystemExit("missing host compiler")
    command = [cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(ROOT),
               str(Path(__file__).with_name("sha_modes.c")), "-o", str(executable)]
    subprocess.run(command, check=True)
    cases = [(b"", 1), (b"abc", 3)]
    cases += [(bytes(i % 256 for i in range(length)), chunk)
              for length in (1, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 4097)
              for chunk in (1, 7, 63, 64, 65, 1024)]
    observations = []
    used_sha_ni = False
    for index, (data, chunk) in enumerate(cases):
        payload = output / ("case-%d.bin" % index)
        payload.write_bytes(data)
        result = subprocess.run([str(executable), str(payload), str(chunk)], check=True,
                                capture_output=True, text=True)
        value = json.loads(result.stdout)
        expected = hashlib.sha256(data).hexdigest()
        assert value["software"] == expected and value["dispatch"] == expected, (index, value, expected)
        used_sha_ni |= value["sha_ni_selected"]
        observations.append({"bytes": len(data), "chunk": chunk, "digest": expected,
                             "sha_ni_selected": value["sha_ni_selected"]})
    receipt = {"status": "PASS", "cases": observations, "build_argv": command,
               "sha_ni_exercised": used_sha_ni,
               "scope": "host diagnostic scalar/runtime equivalence and hashlib oracle, not sovereign linkage"}
    (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS SHA modes: %d streaming/tail cases; SHA-NI exercised=%s" % (len(cases), used_sha_ni))
    if args.output_dir:
        print(output / "result.json")
    if temp:
        temp.cleanup()

if __name__ == "__main__":
    main()
