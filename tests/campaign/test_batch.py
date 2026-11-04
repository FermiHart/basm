#!/usr/bin/env python3
"""Bounded batch integration: preflight refusals and isolated output parity."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def invoke(argv, good=True, cwd=None):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, cwd=cwd)
    assert (result.returncode == 0) == good, (argv, result.returncode, result.stderr)
    assert result.returncode >= 0, result.stderr
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--basm", required=True)
    args = ap.parse_args()
    basm = str(Path(args.basm).resolve())
    count = 0
    with tempfile.TemporaryDirectory(prefix="basm-batch-v2-") as temporary:
        root = Path(temporary)
        sources = []
        for i in range(12):
            path = root / ("input%d.basm" % i)
            path.write_text("bits 64\nsection .text\nglobal f%d\nf%d:\nmov eax, %d\nret\n" % (i, i, i))
            sources.append(path)
        expected = []
        for i, source in enumerate(sources):
            obj = root / ("serial%d.o" % i)
            invoke([basm, "--target-profile", "public", "-o", str(obj), str(source)])
            expected.append(obj.read_bytes())
        manifest = root / "jobs.tsv"
        for jobs in (1, 2, 8, 32):
            outputs = [root / ("parallel-%d-%d.o" % (jobs, i)) for i in range(len(sources))]
            manifest.write_text("".join("elf64\t%s\t%s\n" % pair for pair in zip(outputs, sources)))
            result = invoke([basm, "--target-profile", "public", "--jobs", str(jobs), "--batch", str(manifest)])
            assert "concurrency=%d" % jobs in result.stderr
            assert [path.read_bytes() for path in outputs] == expected
            count += 1
        target = root / "must-not-exist.o"
        valid = "elf64\t%s\t%s\n" % (target, sources[0])
        invalid_rows = [valid + "malformed\n", valid + "elf64\t\tmissing\n",
                        valid + "elf64\toutput\tinput\textra\n", valid + "\0hidden\n",
                        valid + valid,
                        valid + "elf64\t%s/./must-not-exist.o\t%s\n" % (root, sources[1]),
                        valid + "elf64\t%s\t%s\n" % (sources[0], sources[1])]
        for text in invalid_rows:
            manifest.write_bytes(text.encode())
            invoke([basm, "--batch", str(manifest)], good=False)
            assert not target.exists(), "a child ran before full preflight"
            count += 1
        dash_source=root / "-option.basm"
        dash_source.write_text("bits 64\nret\n")
        manifest.write_text(valid + "elf64\t%s\t-option.basm\n" % (root / "dash.o"))
        invoke([basm,"--batch",str(manifest)],good=False,cwd=root)
        assert not target.exists()
        count += 1
        manifest.write_text(valid)
        for value in ("0", "33", "-1", "1garbage", "18446744073709551616"):
            invoke([basm, "--batch", str(manifest), "--jobs", value], good=False)
            assert not target.exists()
            count += 1
        invoke([basm, "--jobs", "2", "-o", str(target), str(sources[0])], good=False)
        count += 1
        # Exhaustion is rejected before any child; the old artifact remains intact.
        manifest.write_text(valid * 4097)
        invoke([basm, "--batch", str(manifest)], good=False)
        assert not target.exists()
        count += 1
        print(json.dumps({"suite": "batch", "passed": count,
                          "isolated_output_comparisons": 48}))


if __name__ == "__main__":
    main()
