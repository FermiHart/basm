#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Check memory displacement boundaries and rejection without publishing bad output."""
import argparse
from pathlib import Path
import subprocess
import sys

if not __debug__:
    sys.exit("assertions required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", required=True, type=Path)
    parser.add_argument("--compat", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=False)

    accepted = (
        ("signed-low", args.basm,
         "bits 64\nmov rax,[rbx-2147483648]\n", bytes.fromhex("488b8300000080")),
        ("signed-high", args.basm,
         "bits 64\nmov rax,[abs 2147483647]\n", bytes.fromhex("488b0425ffffff7f")),
        ("rip-low", args.basm,
         "bits 64\nmov rax,[rel target-2147483648]\ntarget: db 0\n",
         bytes.fromhex("488b050000008000")),
        ("rip-high", args.basm,
         "bits 64\nmov rax,[rel target+2147483647]\ntarget: db 0\n",
         bytes.fromhex("488b05ffffff7f00")),
        ("addr32-unsigned", args.basm,
         "bits 64\nmov eax,[eax+4294967295]\n", bytes.fromhex("678b80ffffffff")),
        ("compat32-unsigned", args.compat,
         "bits 32\nmov eax,[4294967295]\n", bytes.fromhex("a1ffffffff")),
        ("compat32-store", args.compat,
         "bits 32\nmov [4294967295],al\n", bytes.fromhex("a2ffffffff")),
        ("compat16-unsigned", args.compat,
         "bits 16\nmov al,[65535]\n", bytes.fromhex("8a06ffff")),
        ("compat16-negative", args.compat,
         "bits 16\nmov al,[-32768]\n", bytes.fromhex("8a060080")),
    )
    for name, binary, source_text, expected in accepted:
        source = out / f"{name}.basm"
        output = out / f"{name}.bin"
        source.write_text(source_text)
        command = [str(binary), "-f", "bin", "-o", str(output), str(source)]
        if binary == args.basm:
            command[1:1] = ["--target-profile", "public"]
        result = subprocess.run(command, capture_output=True, timeout=15)
        assert result.returncode == 0, (name, result.stderr)
        assert output.read_bytes() == expected, (name, output.read_bytes().hex())

    rejected = (
        ("base64-high", args.basm, "bits 64\nmov rax,[rbx+2147483648]\n"),
        ("base64-low", args.basm, "bits 64\nmov rax,[rbx-2147483649]\n"),
        ("absolute64-high", args.basm, "bits 64\nmov rax,[abs 2147483648]\n"),
        ("absolute64-low", args.basm, "bits 64\nmov rax,[abs -2147483649]\n"),
        ("rip-high", args.basm,
         "bits 64\nmov rax,[rel target+2147483648]\ntarget: db 0\n"),
        ("rip-low", args.basm,
         "bits 64\nmov rax,[rel target-2147483649]\ntarget: db 0\n"),
        ("rip-arithmetic-overflow", args.basm,
         "bits 64\nmov rax,[rel target+9223372036854775807]\ntarget: db 0\n"),
        ("addr32-high", args.basm, "bits 64\nmov eax,[eax+4294967296]\n"),
        ("addr32-low", args.basm, "bits 64\nmov eax,[eax-2147483649]\n"),
        ("compat32-high", args.compat, "bits 32\nmov eax,[4294967296]\n"),
        ("compat32-low", args.compat, "bits 32\nmov eax,[-2147483649]\n"),
        ("compat32-store-high", args.compat, "bits 32\nmov [4294967296],al\n"),
        ("compat16-high", args.compat, "bits 16\nmov al,[65536]\n"),
        ("compat16-low", args.compat, "bits 16\nmov al,[-32769]\n"),
    )
    sentinel = b"previous published output\n"
    for name, binary, source_text in rejected:
        source = out / f"reject-{name}.basm"
        output = out / f"reject-{name}.bin"
        source.write_text(source_text)
        output.write_bytes(sentinel)
        command = [str(binary), "-f", "bin", "-o", str(output), str(source)]
        if binary == args.basm:
            command[1:1] = ["--target-profile", "public"]
        result = subprocess.run(command, capture_output=True, timeout=15)
        assert result.returncode != 0, name
        assert b"memory displacement" in result.stderr, (name, result.stderr)
        assert output.read_bytes() == sentinel, name

    print(f"PASS memory displacements: {len(accepted)} boundaries, {len(rejected)} refusals")


if __name__ == "__main__":
    main()
