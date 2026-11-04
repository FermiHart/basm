#!/bin/sh
# Host-only deterministic publication checks against the actual modular source.
# Usage: sh tests/publication_fault_test.sh
# BASM_PUBLICATION_KEEP=1 retains this run's private binary, fixtures and logs.
# BASM_PUBLICATION_DIAGNOSTIC=1 explicitly selects the corrected bundled crypto;
# the default still requires the canonical external ../../crypto dependency.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
exec python3 - "$ROOT" <<'PY'
import os
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
if platform.system() != "Linux":
    sys.exit("FAIL publication faults: requires Linux host GCC and GNU ld --wrap")
work = Path(tempfile.mkdtemp(prefix="basm-publication-fault.",
                            dir=os.environ.get("BASM_PUBLICATION_TMPDIR")))
binary = work / "basm-host-fault"
env = {k: v for k, v in os.environ.items()
       if not k.startswith("BASM_TEST_PUBLISH_") and k not in ("LD_PRELOAD", "LD_AUDIT")}
env.update(TMPDIR=str(work), LC_ALL="C")
if os.environ.get("BASM_PUBLICATION_SANITIZE") == "1":
    # LSan cannot inspect /proc tasks under this environment's ptrace boundary.
    # Address/undefined-behavior sanitizers remain enabled, including die paths.
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1"
marker = "BASM_PUBLICATION_SPY "
failures = []
passed = 0
case_results = []
receipt = {"schema": "BASM-PUBLICATION-FAULT-GATE-v2", "source_inputs": {},
           "scope": "host-only GNU linker fault injection; never a shipped executable",
           "tests": case_results}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command, directory, label, extra=None, timeout=30, cwd=None):
    # Child output goes to private files, not unbounded capture_output buffers.
    with (directory / (label + ".stdout")).open("wb") as stdout, \
         (directory / (label + ".stderr")).open("wb") as stderr:
        result = subprocess.run(command, cwd=cwd or directory, env={**env, **(extra or {})},
                                stdout=stdout, stderr=stderr, timeout=timeout)
    with (directory / (label + ".stderr")).open("rb") as stderr:
        log = stderr.read(65537)
    require(len(log) <= 65536, label + ": stderr exceeds 64 KiB; see private log")
    text = log.decode("utf-8", errors="replace")
    require(not any(marker in text for marker in
                    ("runtime error:", "AddressSanitizer", "UndefinedBehaviorSanitizer", "LeakSanitizer")),
            label + ": sanitizer diagnostic; see private log")
    return result.returncode, text


def spy(log, mode):
    lines = [line for line in log.splitlines() if line.startswith(marker)]
    require(len(lines) == 1, "expected exactly one publication spy sentinel")
    fields = dict(item.split("=", 1) for item in lines[0][len(marker):].split())
    require(fields.pop("mode") == mode, "spy mode mismatch")
    return {key: int(value) for key, value in fields.items()}


def require_hit(mode, counts):
    expected = {
        "none": (), "short": ("short",), "eintr": ("eintr",),
        "retry": ("short", "eintr"), "enospc": ("short", "enospc"),
        "fclose": ("fclose",), "rename": ("rename",),
        "interloper": ("interloper",), "fopen": ("fopen",),
        "escrow-fopen": ("cache_fopen",), "escrow-receipt-fopen": ("cache_fopen",),
    }[mode]
    for key in ("short", "eintr", "enospc", "fclose", "rename", "interloper", "fopen", "cache_fopen"):
        require(counts[key] > 0 if key in expected else counts[key] == 0,
                f"{mode}: injection counter {key}={counts[key]} (expected {expected})")
    if mode == "enospc":
        require(counts["bytes"] == 97, "ENOSPC was not injected after a real 97-byte prefix")
    if mode in ("eintr", "retry"):
        require(counts["eintr"] == 1, "EINTR injection must occur exactly once")
    if mode in ("fclose", "rename", "interloper"):
        require(counts[mode] == 1, mode + " injection must occur exactly once")
    if mode == "fopen":
        require(counts["fopen"] == 1 and counts["opens"] == 0,
                "output FILE allocation failure must precede creation")
    if mode in ("escrow-fopen", "escrow-receipt-fopen"):
        require(counts["cache_fopen"] == 1, "cache FILE failure must occur exactly once")
        require(counts["cache_opens"] == (mode == "escrow-receipt-fopen"),
                "cache FILE failure missed its object/receipt allocation boundary")


def clean(directory):
    # This directory belongs solely to this case; never sweep older WIP temps.
    temps = [str(p.relative_to(directory)) for p in directory.rglob("*")
             if ".tmp." in p.name]
    require(not temps, "owned temporary files remain: " + ", ".join(temps))


def assemble(directory, label, fmt, output, mode="none", cache=None, source=None,
             target=None, other=None, cache_target=None):
    command = [str(binary), "-f", fmt, "-o", str(output)]
    if cache is not None:
        command += ["--rel8-escrow", str(cache), "--rel8-key", str(work / "key.seed")]
    command += [str(source or (work / "a.basm"))]
    extra = {"BASM_TEST_PUBLISH_FAULT": mode,
             "BASM_TEST_PUBLISH_OUTPUT": str(target or output)}
    if other is not None:
        extra["BASM_TEST_PUBLISH_INTERLOPER"] = str(other)
    if cache is not None:
        extra["BASM_TEST_PUBLISH_CACHE"] = str(cache_target or cache)
    rc, log = run(command, directory, label, extra)
    counts = spy(log, mode)
    require(rc not in (120, 121) and rc >= 0, f"spy setup failure or signal: rc={rc}")
    return rc, log, counts


def case(name, body):
    global passed
    directory = work / name
    directory.mkdir()
    try:
        body(directory)
        passed += 1
        case_results.append({"name": name, "pass": True})
        print("PASS " + name, flush=True)
    except (AssertionError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        failures.append(name)
        case_results.append({"name": name, "pass": False, "error": str(error)})
        print(f"FAIL {name}: {error}", flush=True)


def baseline(directory, fmt):
    for name in ("a", "b"):
        output = directory / (name + ".out")
        rc, log, counts = assemble(directory, name, fmt, output,
                                   source=work / (name + ".basm"))
        require_hit("none", counts)
        require(rc == 0, f"ordinary {name} failed: rc={rc}: {log[:1000]}")
        data = output.read_bytes()
        require(len(data) > 131072, "fixture does not cross writer buffer boundary")
        if fmt == "elf64":
            require(data[:4] == b"\x7fELF", "baseline is not an ELF object")
        baselines[fmt, name] = data
    require(baselines[fmt, "a"] != baselines[fmt, "b"], "A and B must differ")
    clean(directory)


def publication(directory, fmt, mode, lane):
    output = directory / "final.out"
    cache = directory / "escrow" if lane != "ordinary" else None
    if lane == "warm":
        rc, log, counts = assemble(directory, "seed", fmt, directory / "seed.out", cache=cache)
        require(rc == 0 and "rel8 escrow hit" not in log, "warm seed was not a cold success")
        require_hit("none", counts)
        require((directory / "seed.out").read_bytes() == baselines[fmt, "a"], "seed differs")
        clean(directory)
    output.write_bytes(baselines[fmt, "b"])
    rc, log, counts = assemble(directory, "run", fmt, output, mode, cache)
    require_hit(mode, counts)
    require(counts["opens"] == (0 if mode == "fopen" else 1),
            "spy must track the actual output stream acquisition")
    expected_failure = mode in ("enospc", "fclose", "rename", "fopen",
                                "escrow-fopen", "escrow-receipt-fopen")
    problems = []
    if (rc != 0) != expected_failure:
        problems.append(f"rc={rc}, expected {'failure' if expected_failure else 'success'}")
    expected = baselines[fmt, "b" if expected_failure else "a"]
    if not output.exists() or output.read_bytes() != expected:
        problems.append("old final changed on failure" if expected_failure else "bytes differ from baseline")
    try:
        clean(directory)
    except AssertionError as error:
        problems.append(str(error))
    require(not problems, "; ".join(problems) + f"; spy={counts}")
    if not expected_failure:
        require(("rel8 escrow hit" in log) == (lane == "warm"), "unexpected cache hit/miss")
        if lane != "warm":
            require(counts["bytes"] == len(expected), "spy did not observe all output bytes")
    if expected_failure and lane == "warm":
        # A failed restore must not damage the live authenticated cache pair.
        rc, log, counts = assemble(directory, "retry", fmt, output, cache=cache)
        require_hit("none", counts)
        require(rc == 0 and "rel8 escrow hit" in log, "failed restore damaged the cache")
        require(output.read_bytes() == baselines[fmt, "a"], "retry restored wrong bytes")
        clean(directory)


def contamination(directory, fmt):
    output, other, cache = directory / "final.out", directory / "other.out", directory / "escrow"
    output.write_bytes(baselines[fmt, "b"])
    other.write_bytes(baselines[fmt, "b"])
    rc, log, counts = assemble(directory, "race", fmt, output, "interloper", cache, other=other)
    require_hit("interloper", counts)
    require(rc == 0 and "rel8 escrow hit" not in log, "race must publish on a cold miss")
    require(not other.exists() and output.read_bytes() == baselines[fmt, "b"],
            "interloper did not replace the final with valid assembled B")
    clean(directory)
    restored = directory / "restored.out"
    rc, log, counts = assemble(directory, "restore", fmt, restored, cache=cache)
    require_hit("none", counts)
    require(rc == 0 and "rel8 escrow hit" in log, "verification must be a real authenticated cache hit")
    clean(directory)
    data = restored.read_bytes()
    require(data == baselines[fmt, "a"],
            "cache key A restored interloper B" if data == baselines[fmt, "b"]
            else "cache key A restored bytes different from baseline A")


def spy_selftest(directory):
    for mode in ("short", "eintr", "retry", "enospc", "fclose", "rename", "interloper", "fopen"):
        output, other = directory / "final.out", directory / "other.out"
        other.write_bytes(baselines["elf64", "b"])
        rc, log, counts = assemble(directory, mode, "elf64", output, mode,
                                   target=directory / "not-the-output", other=other)
        require(rc == 0 and output.read_bytes() == baselines["elf64", "a"], "wrong-target control failed")
        require(all(value == 0 for value in counts.values()), "spy affected an unrelated path")
        try:
            require_hit(mode, counts)
        except AssertionError:
            pass
        else:
            raise AssertionError(mode + ": missed injection would silently pass")
    for mode in ("escrow-fopen", "escrow-receipt-fopen"):
        cache = directory / (mode + "-cache")
        output = directory / (mode + ".out")
        rc, _, counts = assemble(directory, mode, "elf64", output, mode, cache=cache,
                                 target=directory / "not-the-output", cache_target=directory / "not-the-cache")
        require(rc == 0 and output.read_bytes() == baselines["elf64", "a"], "wrong-cache control failed")
        require(all(value == 0 for value in counts.values()), "spy affected an unrelated cache")
        try:
            require_hit(mode, counts)
        except AssertionError:
            pass
        else:
            raise AssertionError(mode + ": missed cache injection would silently pass")
    for bad_log in ("", log + log):
        try:
            spy(bad_log, "interloper")
        except AssertionError:
            pass
        else:
            raise AssertionError("missing/duplicate sentinel would silently pass")
    clean(directory)


try:
    cc = os.environ.get("HOST_CC", "gcc")
    diagnostic = os.environ.get("BASM_PUBLICATION_DIAGNOSTIC", "0")
    require(diagnostic in ("0", "1"), "BASM_PUBLICATION_DIAGNOSTIC must be 0 or 1")
    staged = work / "source"
    staged.mkdir()
    source_files = ["basm.c", "sign.c", "sign.h", "sha256_ni.h", "tests/publication_fault_test.c"]
    source_files += [str(p.relative_to(root)) for folder, pattern in
                     (("modules", "*.inc"), ("intent", "*.inc"), ("isa", "*.h"))
                     for p in sorted((root / folder).glob(pattern))]
    if diagnostic == "1":
        source_files += ["bear_ed25519.c", "bear_ed25519.h"]
        receipt["lane"] = "HOST_DIAGNOSTIC_CORRECTED_BUNDLED_CRYPTO_NOT_SOVEREIGN"
        receipt["canonical_crypto"] = "ABSENT_OR_UNUSED_NOT_VALIDATED"
    else:
        crypto = (root / "../../crypto").resolve()
        require((crypto / "ed25519.c").is_file() and (crypto / "ed25519.h").is_file(),
                "canonical ../../crypto/ed25519.c/h required; no automatic fallback. "
                "BASM_PUBLICATION_DIAGNOSTIC=1 explicitly enables the separate bundled diagnostic lane")
        receipt["lane"] = "HOST_WITH_CANONICAL_EXTERNAL_CRYPTO"
        receipt["canonical_crypto"] = str(crypto)
    for relative in source_files:
        source = root / relative
        content = source.read_bytes()
        destination = staged / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        receipt["source_inputs"][relative] = {"path": str(source), "bytes": len(content),
                                              "sha256": hashlib.sha256(content).hexdigest()}
    include_flags = ["-I" + str(staged)]
    if diagnostic == "1":
        include = work / "include/crypto"
        include.mkdir(parents=True)
        shutil.copyfile(staged / "bear_ed25519.h", include / "ed25519.h")
        include_flags.append("-I" + str(include.parent))
        crypto_source = staged / "bear_ed25519.c"
    else:
        include_flags.append("-I" + str(crypto.parent))
        crypto_source = crypto / "ed25519.c"
        for name in ("ed25519.c", "ed25519.h"):
            content = (crypto / name).read_bytes()
            receipt["source_inputs"]["external-crypto/" + name] = {
                "path": str(crypto / name), "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    command = [cc, "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
               "-Wno-stringop-truncation", "-Wno-format-truncation"] + include_flags + [
               str(staged / "basm.c"), str(staged / "sign.c"), str(crypto_source),
               str(staged / "tests/publication_fault_test.c"),
               "-Wl,--wrap=fopen", "-Wl,--wrap=write", "-Wl,--wrap=fclose", "-Wl,--wrap=rename",
               "-o", str(binary)]
    if os.environ.get("BASM_PUBLICATION_SANITIZE") == "1":
        command += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    receipt["compile_argv"] = command
    receipt["sanitizers"] = os.environ.get("BASM_PUBLICATION_SANITIZE") == "1"
    receipt["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS")
    rc, log = run(command, work, "build", timeout=180, cwd=root)
    require(rc == 0, f"host GCC build failed: rc={rc}: {log[:4000]}")
    for identity in receipt["source_inputs"].values():
        require(hashlib.sha256(Path(identity["path"]).read_bytes()).hexdigest() == identity["sha256"],
                "source changed during publication fault build; repeat with a stable source snapshot")
    receipt["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    print("publication fault lane: " + receipt["lane"], flush=True)
    # SHA-NI functions carry their own target attributes; no global ISA flags.
    (work / "key.seed").write_bytes(bytes(range(32)))
    for name, value in (("a", 17), ("b", 23)):
        (work / (name + ".basm")).write_text(
            "bits 64\nsection .text\nglobal entry\nentry:\n"
            f"mov eax, {value}\nret\nsection .data\ntimes 131072 db {value}\n", encoding="ascii")
    baselines = {}
    for fmt in ("elf64", "bin"):
        case("baseline-" + fmt, lambda d, fmt=fmt: baseline(d, fmt))
    require(not failures, "ordinary baseline failed; fault tests are not meaningful")
    case("spy-selftest", spy_selftest)
    for fmt in ("elf64", "bin"):
        for lane in ("ordinary", "cold", "warm"):
            # GNU --wrap cannot intercept glibc's internal fwrite writes on
            # warm copies; exercise their output fclose/rename boundaries.
            modes = ("none", "fopen", "fclose", "rename") if lane == "warm" else (
                "none", "fopen", "short", "eintr", "retry", "enospc", "fclose", "rename")
            if lane == "cold":
                modes += ("escrow-fopen", "escrow-receipt-fopen")
            for mode in modes:
                case(f"{fmt}-{lane}-{mode}",
                     lambda d, fmt=fmt, mode=mode, lane=lane: publication(d, fmt, mode, lane))
        case(fmt + "-escrow-interloper", lambda d, fmt=fmt: contamination(d, fmt))
    print(f"publication faults: {passed} passed, {len(failures)} failed", flush=True)
except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
    failures.append("setup")
    print(f"FAIL publication faults setup: {error}", flush=True)
finally:
    receipt["passed"] = passed
    receipt["failures"] = failures
    (work / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if failures or os.environ.get("BASM_PUBLICATION_KEEP") == "1":
        print("publication fault artifacts: " + str(work), flush=True)
    else:
        shutil.rmtree(work)
sys.exit(bool(failures))
PY
