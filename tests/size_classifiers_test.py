#!/usr/bin/env python3
"""Test the actual module classifiers with both host char modes and pinned Bear.

Only builds isolated host-safe classifier probes, never the product or guest ISA.
The Bear arm tests backend lowering linked to host libc; full product regressions
separately cover the pinned blibc runtime.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--bear", type=Path, required=True)
    p.add_argument("--cc", default="cc")
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        p.error("use a new evidence directory")
    modules = {path.name: path.read_text() for path in (ROOT / "modules").glob("*.inc")}
    helpers = []
    for file, name in (("01_foundation.inc", "char_in"),
                       ("03_parser.inc", "data_directive_unit"),
                       ("05_preprocessor.inc", "pp_keyword")):
        source = modules[file]
        start = source.index("static int " + name + "(")
        end = source.index("\n}", start) + 2
        helpers.append(source[start:end].removeprefix("static "))
    source = out / "classifiers.c"
    source.write_text("typedef unsigned long size_t;\n#define NULL ((void *)0)\n"
                      "extern size_t strlen(const char *);\n"
                      "extern int strncmp(const char *,const char *,size_t);\n"
                      "extern char *strchr(const char *,int);\n" + "\n".join(helpers) + "\n")
    text = "\n".join(modules.values())
    literal = r'"(?:\\.|[^"\\])*"'
    sets = set(re.findall(r'char_in\([^,\n]+,\s*(' + literal + ')', text))
    sets.update(re.findall(r'strchr\(\s*(' + literal + r')\s*,', text))
    # Empty and high-bit sets also check the generic helper's signed-char ABI.
    sets.update(('""', '"\\200\\377"'))
    # INV-586: body terminators now reach pp_keyword through the shared scanner.
    words = set(re.findall(r'(?:pp_keyword|pp_read_body)\([^,\n]+,\s*(' + literal + ')', text))
    words.update(json.dumps(w) for w in ("", "d", "res", "db", "dw", "dd", "dq", "resb", "resw", "resd", "resq"))
    (out / "size_inputs.inc").write_text(
        "static const char *sets[]={" + ",".join(sorted(sets)) + "};\n" +
        "static const char *words[]={" + ",".join(sorted(words)) + "};\n")
    report = []

    def run(label, command):
        result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=120)
        (out / (label + ".log")).write_text(result.stdout + result.stderr)
        report.append({"label": label, "command": [str(x) for x in command], "returncode": result.returncode})
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(f"{label}: {result.stdout}{result.stderr}")
        if result.stdout:
            print(label + ": " + result.stdout.rstrip())

    harness = ROOT / "tests/size_classifiers_test.c"
    common = [args.cc, "-O2", "-Wall", "-Wextra", "-Werror", "-fno-pie", "-no-pie",
              "-fsanitize=address,undefined", "-I" + str(out)]
    for mode in ("signed", "unsigned"):
        binary = out / mode
        run(mode + "-build", [*common, "-f" + mode + "-char", source, harness, "-o", binary])
        run(mode, [binary])
    obj = out / "bear.o"
    run("bear-compile", [args.bear.resolve(), "-c", source, "-o", obj])
    binary = out / "bear-host"
    run("bear-link", [*common, "-fsigned-char", obj, harness, "-o", binary])
    run("bear-host", [binary])


if __name__ == "__main__":
    main()
