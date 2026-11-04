#!/usr/bin/env python3
"""W14 timing boundaries, successful-job coverage and byte preservation.

Absolute durations are deliberately not performance assertions. The native
paired benchmark is responsible for elapsed process time and dispersion.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


PHASES = ("source_ns", "preprocess_ns", "layout_ns", "emit_ns", "write_ns",
          "cache_ns", "attestation_ns", "explain_ns", "cleanup_ns")
FIELDS = set(PHASES) | {"total_ns", "layout_passes", "final_pass", "source_bytes",
    "output_bytes", "cache_hit", "expanded_bytes", "scan_bytes", "file_bytes",
    "hash_tool_calls", "hash_tool_reuses", "hash_dependency_calls", "hash_dependency_reuses"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basm", required=True, type=Path)
    args = parser.parse_args()
    basm = args.basm.resolve()
    observations = []
    with tempfile.TemporaryDirectory(prefix="basm-profile-complete-") as name:
        root = Path(name)
        source = root / "input.basm"
        source.write_text("bits 64\nsection .text\nglobal f\nf:\nmov eax,7\nret\n")
        output, proof = root / "out.o", root / "out.proof"
        seed = root / "test.seed"
        seed.write_bytes(bytes(range(32)))
        seed.chmod(0o600)
        cache = root / "cache"
        cache.mkdir(mode=0o700)
        base = [str(basm), "--target-profile", "public", "-o", str(output)]

        def run(label, extra=(), profiled=True):
            command = base + (["--profile"] if profiled else []) + list(extra) + [str(source)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, (label, result.returncode, result.stderr)
            lines = [line for line in result.stderr.splitlines() if line.startswith("BASM_PROFILE ")]
            if not profiled:
                assert not lines
                return output.read_bytes(), result.stdout, None
            assert len(lines) == 1
            pairs = [part.split("=") for part in lines[0].split()[1:]]
            assert len({key for key, value in pairs}) == len(pairs)
            assert all(value.isdecimal() for key, value in pairs)
            profile = {key: int(value) for key, value in pairs}
            assert FIELDS <= profile.keys(), profile
            assert 0 < sum(profile[field] for field in PHASES) <= profile["total_ns"]
            assert profile["source_bytes"] == source.stat().st_size
            assert profile["file_bytes"] == output.stat().st_size
            assert profile["final_pass"] in (0, 1) and profile["cache_hit"] in (0, 1)
            assert profile["cleanup_ns"] > 0
            observations.append({"case": label, "telemetry": profile})
            return output.read_bytes(), result.stdout, profile

        plain, _, _ = run("plain", profiled=False)
        # Looking ahead for the timing clock must not interpret a value of -o
        # as the telemetry flag. The ordinary CLI parser owns that decision.
        literal = subprocess.run([str(basm), "-o", "--profile", str(source)], cwd=root,
                                 capture_output=True, text=True, timeout=30)
        assert literal.returncode == 0 and (root / "--profile").read_bytes() == plain
        assert "BASM_PROFILE " not in literal.stderr
        profiled, _, timing = run("plain-profiled")
        assert plain == profiled
        assert timing["attestation_ns"] == timing["explain_ns"] == timing["cache_ns"] == 0
        assert timing["scan_bytes"] >= timing["expanded_bytes"] > 0
        assert timing["hash_tool_calls"] == 0
        before, explanation, _ = run("explain", ["--explain"], profiled=False)
        after, explanation_profiled, timing = run("explain-profiled", ["--explain"])
        assert before == after == plain and explanation == explanation_profiled
        assert json.loads(explanation) and timing["explain_ns"] > 0
        modes = [("unsigned-v4", ["--emit-attestation-v4", str(proof)]),
                 ("signed-v4", ["--emit-attestation-v4", str(proof), "--sign", str(seed)])]
        for label, extra in modes:
            before, _, _ = run(label, extra, profiled=False)
            previous = proof.read_bytes()
            after, _, timing = run(label + "-profiled", extra)
            assert before == after == plain and previous == proof.read_bytes()
            assert timing["attestation_ns"] > 0 and timing["hash_tool_calls"] == 1
        cache_flags = ["--rel8-escrow", str(cache), "--rel8-key", str(seed),
                       "--emit-attestation-v4", str(proof)]
        before, _, cold = run("cache-cold", cache_flags)
        after, _, warm = run("cache-warm", cache_flags)
        assert before == after == plain and cold["cache_hit"] == 0 and warm["cache_hit"] == 1
        assert warm["layout_ns"] == warm["emit_ns"] == warm["write_ns"] == 0
        assert warm["layout_passes"] == warm["scan_bytes"] == 0
        assert warm["cache_ns"] > 0 and warm["attestation_ns"] > 0
        for timing in (cold, warm):
            assert timing["hash_tool_calls"] == 1 and timing["hash_tool_reuses"] >= 1
        combined = cache_flags + ["--sign", str(seed), "--emit-exec-proof",
                                  "--sign-exec-proof", str(seed)]
        _, _, timing = run("combined-cold", combined)
        assert timing["cache_hit"] == 0
        assert timing["hash_tool_calls"] == 1 and timing["hash_tool_reuses"] >= 2
        assert timing["hash_dependency_calls"] == 1 and timing["hash_dependency_reuses"] > 0
        print(json.dumps({"suite": "complete-profile", "passed": len(observations) + 1,
                          "option_value_does_not_enable_profile": True,
                          "observations": observations}, indent=2))


if __name__ == "__main__":
    main()
