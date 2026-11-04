#!/usr/bin/env python3
"""Bounded, paired performance evidence for matching HOST_DIAGNOSTIC builds.

This is not the sovereign/NASM gate. No emitted instruction is executed. Timing
and child RSS come from the retained native wait4 launcher, not Python's child.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "BASM-CAMPAIGN-PERFORMANCE-v1"
PROOF_MODES = ("unsigned", "signed", "cache-cold", "cache-warm", "combined-proof")
SIGNED_MODES = ("signed", "combined-proof")
V4_MODES = ("cache-cold", "cache-warm", "combined-proof")
# Public test fixture from RFC 8032 section 7.1, also covered by test_crypto_ub.py.
# This seed is intentionally public and must never be a production identity.
TEST_SIGNER_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TEST_SIGNER_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

def identity(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}

def summary(values):
    median = statistics.median(values)
    mad = statistics.median(abs(v - median) for v in values)
    return {"median": median, "mad": mad,
            "relative_mad": mad / median if median else 0,
            "minimum": min(values), "maximum": max(values)}

def semantic_flags(receipt):
    return [f for f in receipt["flags"] if not f.startswith("-I")]

def load_lane(binary, receipt_path):
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("lane") != "HOST_DIAGNOSTIC_NOT_SOVEREIGN" or receipt.get("sanitizers"):
        raise ValueError("performance requires an unsanitized explicit host diagnostic receipt")
    if receipt.get("status") != "BUILT_FROM_RETAINED_HOST_SNAPSHOT":
        raise ValueError("build receipt is not successful")
    actual = identity(binary)
    expected = receipt.get("artifacts", {}).get("basm-host", {})
    if (actual["sha256"], actual["bytes"]) != (expected.get("sha256"), expected.get("bytes")):
        raise ValueError("selected assembler does not match the host build receipt")
    if not os.access(binary, os.X_OK):
        raise ValueError("selected assembler is not executable")
    return {"binary": actual, "receipt": identity(receipt_path), "build": receipt}

def validate_matching_lanes(baseline, candidate, sha_configuration_experiment=False):
    properties = ("compiler", "compiler_version", "sanitizers")
    if not sha_configuration_experiment:
        properties += ("sha_mode",)
    for key in properties:
        if baseline["build"][key] != candidate["build"][key]:
            raise ValueError("baseline/candidate differ in toolchain property: " + key)
    def comparison_flags(build):
        flags = semantic_flags(build)
        if sha_configuration_experiment:
            flags = [f for f in flags if f != "-DSHA256NI_FORCE_SOFTWARE=1"]
        return flags
    if comparison_flags(baseline["build"]) != comparison_flags(candidate["build"]):
        raise ValueError("baseline/candidate compiler flags differ")
    if sha_configuration_experiment:
        if {baseline["build"]["sha_mode"], candidate["build"]["sha_mode"]} != {"software", "runtime"}:
            raise ValueError("SHA configuration experiment requires software and runtime lanes")
        def inputs(build):
            return {name: (record["bytes"], record["sha256"]) for name, record in build["source_inputs"].items()}
        if inputs(baseline["build"]) != inputs(candidate["build"]):
            raise ValueError("SHA configuration experiment requires identical source inputs")
    for key in ("bear_ed25519.c", "bear_ed25519.h"):
        if baseline["build"]["source_inputs"][key]["sha256"] != candidate["build"]["source_inputs"][key]["sha256"]:
            raise ValueError("baseline/candidate bundled crypto differs: " + key)

def fixtures(directory):
    directory.mkdir()
    header = "bits 64\nsection .text\nglobal entry\nentry:\n"
    cases = []
    def add(name, text, fmt="elf64", mode="bare", extra=None):
        path = directory / (name + ".basm")
        path.write_text(text)
        cases.append({"name": name, "source": str(path), "format": fmt,
                      "mode": mode, "extra": extra or []})
    tiny = header + "mov rax, rbx\nadd rax, 7\nxor rcx, rcx\nret\n"
    add("tiny", tiny)
    add("instructions", header + "".join("add rax, %d\nxor rcx, %d\n" % (i % 997, i % 127)
                                         for i in range(4000)) + "ret\n")
    add("branches", header + "".join("cmp rax, %d\njne .L%d\nnop\n.L%d:\n" % (i, i, i)
                                     for i in range(1000)) + "ret\n")
    add("macros", "bits 64\n%macro M 1\nadd rax, %1\n%endmacro\nsection .text\nglobal entry\nentry:\n" +
        "".join("M %d\n" % (i % 997) for i in range(2000)) + "ret\n")
    include_dir = directory / "include"
    include_dir.mkdir()
    include_text = header
    for part in range(12):
        name = "part%02d.inc" % part
        (include_dir / name).write_text("".join("add rax, %d\nxor rbx, %d\n" % (part * 32 + i, i)
                                               for i in range(32)))
        include_text += '%%include "%s"\n' % name
    add("includes", include_text + "ret\n", extra=["-I" + str(include_dir) + "/"])
    add("relocations", "bits 64\nextern external_target\nsection .text\nglobal entry\nentry:\n" +
        "call external_target\n" * 2000 + "ret\n")
    custom = "bits 64\n"
    for sec in range(8):
        custom += "section .campaign%d alloc noexec nowrite progbits align=16\n" % sec
        custom += "global data%d\ndata%d:\n" % (sec, sec)
        custom += "".join("dq %d\n" % (sec * 256 + i) for i in range(128))
    add("custom-sections", custom + "section .text\nglobal entry\nentry:\nret\n")
    add("flat-bin", "bits 64\norg 0x1000\nsection .text\n" +
        "".join("add rax, %d\njne next%d\nnop\nnext%d:\n" % (i, i, i) for i in range(128)) + "ret\n", "bin")
    payload = directory / "payload.bin"
    payload.write_bytes(bytes(range(256)) * 4096)
    add("incbin", 'bits 64\nsection .rodata\nglobal payload\npayload:\nincbin "%s"\n' % payload)
    add("contextual-expressions", "bits 64\nsection .data\n" + "dd $\n" * 1000)
    # Explicit local declarations control first-intern order without making the
    # labels globals. This actually exercises defseq ordering, unlike forward
    # calls that only consult sym_find and do not intern the unresolved target.
    count = 1000
    add("symbols-reversed", "bits 64\n" + "".join("static L%d:notype 1\n" % i for i in range(count-1, -1, -1)) +
        "section .text\n" + "".join("L%d:\nnop\n" % i for i in range(count)) + "ret\n")
    for reverse in (False, True):
        count = 10000
        order = range(count-1, -1, -1) if reverse else range(count)
        add("symbols-" + ("reversed" if reverse else "ordered") + "-10000",
            "bits 64\n" + "".join("static L%d:notype 1\n" % i for i in order) +
            "section .text\n" + "".join("L%d:\nnop\n" % i for i in range(count)) + "ret\n")
    add("tiny-unsigned", tiny, mode="unsigned")
    add("tiny-signed", tiny, mode="signed")
    add("tiny-explain", tiny, mode="explain", extra=["--target-profile", "public", "--explain"])
    add("cache-cold-v4", tiny, mode="cache-cold", extra=["--target-profile", "public"])
    add("cache-warm-v4", tiny, mode="cache-warm", extra=["--target-profile", "public"])
    add("combined-proof-v4", tiny, mode="combined-proof", extra=["--target-profile", "public"])
    return cases

def validate_proof(path, tool, source, output, signed, expected_pub=None):
    content = path.read_text()
    rows = content.splitlines()
    if not rows or rows[0] not in ("basm attestation v2", "basm attestation v3", "basm attestation v4"):
        raise ValueError("missing/unknown attestation framing")
    fields = {}
    dependencies = []
    for row in rows[1:]:
        key, sep, value = row.partition(": ")
        if key == "dependency" and rows[0] == "basm attestation v4":
            dependencies.append(value)
            continue
        if not sep or key in fields:
            raise ValueError("malformed/duplicate attestation field")
        fields[key] = value
    checks = {"tool_sha256": identity(tool)["sha256"],
              "source_sha256": identity(source)["sha256"],
              "output_sha256": identity(output)["sha256"],
              "source_path": str(source), "output_path": str(output),
              "output_format": "elf64", "build_epoch": "0"}
    for key, expected in checks.items():
        if fields.get(key) != expected:
            raise ValueError("proof does not bind actual " + key)
    if signed:
        if fields.get("signature_alg") != "ed25519-over-sha256" or fields.get("signature") == "unsigned":
            raise ValueError("signed workload has no signature")
        if expected_pub is not None and fields.get("signature_pub") != expected_pub:
            raise ValueError("proof signer differs from requested test identity")
    elif fields.get("signature") != "unsigned":
        raise ValueError("unsigned workload unexpectedly signed")
    if rows[0] == "basm attestation v4":
        if int(fields.get("dependency_count", "-1")) != len(dependencies) or not dependencies:
            raise ValueError("v4 dependency count mismatch")
        closure = hashlib.sha256(b"basm-input-closure-v1\x00" + struct.pack("<Q", len(dependencies)))
        for dependency in dependencies:
            kind, size, digest, path_hex = dependency.split(" ")
            path_bytes = bytes.fromhex(path_hex)
            actual = identity(Path(os.fsdecode(path_bytes)))
            if (actual["bytes"], actual["sha256"]) != (int(size), digest):
                raise ValueError("v4 consumed dependency differs")
            closure.update(bytes([int(kind)]) + struct.pack("<Q", int(size)) + path_bytes + b"\x00" + bytes.fromhex(digest))
        if fields.get("dependency_root") != closure.hexdigest():
            raise ValueError("v4 dependency root differs")
        for name in ("expanded_sha256", "configuration_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", fields.get(name, "")):
                raise ValueError("v4 digest missing: " + name)
    return fields

def elf_sections(data):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected ELF64 little-endian object")
    if struct.unpack_from("<HH", data, 16) != (1, 62):
        raise ValueError("expected x86-64 relocatable object")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strings_index = struct.unpack_from("<HHH", data, 58)
    if entsize != 64 or not 1 <= count <= 128 or strings_index >= count or shoff + count*64 > len(data):
        raise ValueError("invalid section table bounds")
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i*64) for i in range(count)]
    strings = rows[strings_index]
    if strings[4] + strings[5] > len(data):
        raise ValueError("section names out of range")
    names = data[strings[4]:strings[4]+strings[5]]
    result = {}
    for row in rows[1:]:
        name, kind, flags, _, offset, size, _, _, alignment, _ = row
        end = names.find(b"\x00", name)
        if name >= len(names) or end < 0 or (kind != 8 and offset + size > len(data)):
            raise ValueError("section bounds/name invalid")
        text = names[name:end].decode("utf-8")
        if text in result:
            raise ValueError("duplicate section name")
        result[text] = {"type": kind, "flags": flags, "offset": offset, "size": size,
                        "align": alignment, "data": b"" if kind == 8 else data[offset:offset+size]}
    return result

def validate_exec_note(data, tool, source, signer):
    sections = elf_sections(data)
    note = sections.get(".note.TinaProof")
    if not note or note["type"] != 7:
        raise ValueError("requested exec proof note missing")
    payload = note["data"]
    if len(payload) < 24:
        raise ValueError("truncated proof note")
    namesz, descsz, kind = struct.unpack_from("<III", payload)
    if (namesz, descsz, kind) != (12, 2288, 0x54494e41) or len(payload) != 24 + descsz:
        raise ValueError("unsupported exec proof v1 representation")
    if payload[12:24] != b"TinaLinux\x00\x00\x00":
        raise ValueError("incorrect proof note name")
    desc = payload[24:]
    if struct.unpack_from("<II", desc) != (0x54494e50, 1):
        raise ValueError("incorrect exec proof framing")
    if desc[8:40] != hashlib.sha256(source.read_bytes()).digest() or desc[40:72] != hashlib.sha256(tool.read_bytes()).digest():
        raise ValueError("exec proof does not bind tool/source")
    nsec = struct.unpack_from("<I", desc, 72)[0]
    if not 1 <= nsec <= 24:
        raise ValueError("exec proof section count invalid")
    declared = set()
    for i in range(nsec):
        entry = 80 + i*56
        raw_name = desc[entry:entry+32]
        if b"\x00" not in raw_name:
            raise ValueError("unterminated exec proof section name")
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8")
        section = sections.get(name)
        if not section or name in declared:
            raise ValueError("missing/duplicate exec proof section")
        declared.add(name)
        kind = struct.unpack_from("<I", desc, entry+32)[0]
        flags, align = struct.unpack_from("<QQ", desc, entry+40)
        if (kind, flags, align) != (section["type"], section["flags"], section["align"]):
            raise ValueError("exec proof section metadata differs")
        digest = desc[1424 + i*32:1456 + i*32]
        if digest != hashlib.sha256(section["data"]).digest():
            raise ValueError("exec proof section bytes differ")
    content_names = {name for name, section in sections.items()
                     if name not in (".note.TinaProof", ".symtab", ".strtab", ".shstrtab") and section["type"] != 4}
    if declared != content_names:
        raise ValueError("exec proof does not cover every source section")
    if desc[2192:2224].hex() != signer:
        raise ValueError("exec proof signer differs from requested sidecar signer")
    normalized = bytearray(data)
    normalized[note["offset"]:note["offset"]+note["size"]] = b"\x00" * note["size"]
    return bytes(normalized), desc[2192:2224].hex(), hashlib.sha256(desc[:2224]).hexdigest(), desc[2224:2288].hex()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--candidate-receipt", type=Path)
    parser.add_argument("--elftool", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=15)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cases", help="comma-separated names; omitted runs the complete fixed corpus")
    parser.add_argument("--sha-configuration-experiment", action="store_true",
                        help="compare identical-source software/runtime SHA lanes; explicitly not a source optimization gate")
    args = parser.parse_args()
    if not 5 <= args.rounds <= 15 or not 1 <= args.warmups <= 3 or not 1 <= args.timeout <= 10:
        parser.error("rounds 5..15, warmups 1..3, timeout 1..10 required")
    if bool(args.candidate) != bool(args.candidate_receipt):
        parser.error("candidate binary and receipt must be supplied together")
    if args.sha_configuration_experiment and not args.candidate:
        parser.error("SHA configuration experiment requires both lanes")
    if platform.system() != "Linux":
        parser.error("this bounded measurement protocol currently requires Linux")
    out = args.output_dir.resolve()
    if out.exists():
        parser.error("output directory must be fresh; no rerun into an existing receipt")
    lanes = {"baseline": load_lane(args.baseline.resolve(), args.baseline_receipt.resolve())}
    if args.candidate:
        lanes["candidate"] = load_lane(args.candidate.resolve(), args.candidate_receipt.resolve())
        validate_matching_lanes(lanes["baseline"], lanes["candidate"], args.sha_configuration_experiment)
    elftool = args.elftool.resolve()
    if not os.access(elftool, os.X_OK):
        parser.error("ELF inspector must be executable")
    out.mkdir(parents=True, mode=0o700)
    runner = Path(__file__).resolve()
    shutil.copyfile(runner, out / "perf_campaign.py")
    for role, lane in lanes.items():
        copy = out / (role + ".executable")
        shutil.copyfile(lane["binary"]["path"], copy)
        copy.chmod(0o500)
        lane["snapshot"] = identity(copy)
        if lane["snapshot"]["sha256"] != lane["binary"]["sha256"]:
            raise ValueError("executable changed during snapshot")
        shutil.copyfile(lane["receipt"]["path"], out / (role + ".build-receipt.json"))
    native_source = Path(__file__).with_name("measure_process.c")
    shutil.copyfile(native_source, out / "measure_process.c")
    native = out / "measure_process"
    cc = lanes["baseline"]["build"]["compiler"]["path"]
    compile_argv = [cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", str(out / "measure_process.c"), "-o", str(native)]
    compiled = subprocess.run(compile_argv, capture_output=True, text=True)
    (out / "launcher-build.stdout").write_text(compiled.stdout)
    (out / "launcher-build.stderr").write_text(compiled.stderr)
    if compiled.returncode:
        raise RuntimeError("native launcher compilation failed: " + compiled.stderr)
    # The verifier consumes hashes produced by Python's independent ELF parser.
    # It uses the retained diagnostic crypto bytes, not a new trust provider.
    verifier_source = Path(__file__).with_name("verify_note_signature.c")
    shutil.copyfile(verifier_source, out / verifier_source.name)
    crypto_snapshot = Path(lanes["baseline"]["build"]["source_snapshot"])
    for name in ("bear_ed25519.c", "bear_ed25519.h"):
        crypto = crypto_snapshot / name
        if identity(crypto)["sha256"] != lanes["baseline"]["build"]["source_inputs"][name]["sha256"]:
            raise ValueError("retained diagnostic crypto snapshot differs: " + name)
        shutil.copyfile(crypto, out / name)
    verifier = out / "verify_note_signature"
    verifier_argv = [cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                     "-I" + str(out), str(out / verifier_source.name), str(out / "bear_ed25519.c"), "-o", str(verifier)]
    verified_build = subprocess.run(verifier_argv, capture_output=True, text=True)
    (out / "note-verifier-build.stdout").write_text(verified_build.stdout)
    (out / "note-verifier-build.stderr").write_text(verified_build.stderr)
    if verified_build.returncode:
        raise RuntimeError("note signature verifier compilation failed: " + verified_build.stderr)
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"}
    cases = fixtures(out / "fixtures")
    if args.cases:
        requested = set(args.cases.split(","))
        unknown = requested - {c["name"] for c in cases}
        if unknown:
            parser.error("unknown cases: " + ",".join(sorted(unknown)))
        cases = [c for c in cases if c["name"] in requested]
    fixture_identities = [identity(p) for p in sorted((out / "fixtures").rglob("*")) if p.is_file()]
    key = out / "test-only-key.seed"
    key.write_bytes(bytes.fromhex(TEST_SIGNER_SEED))
    key.chmod(0o600)
    commands = []
    results = []
    receipt = {"schema": SCHEMA,
               "scope": "SHA_CONFIGURATION_EXPERIMENT_NOT_SOURCE_OPTIMIZATION" if args.sha_configuration_experiment else "MATCHED_HOST_DIAGNOSTIC_ONLY_NOT_SOVEREIGN_OR_NASM",
               "runner": identity(runner), "runner_snapshot": identity(out / "perf_campaign.py"),
               "complete_default_protocol": not args.cases and args.rounds == 15 and args.warmups == 3 and not args.sha_configuration_experiment,
               "python": {"executable": identity(Path(sys.executable).resolve()), "version": sys.version},
               "lanes": lanes, "inspector": identity(elftool), "launcher": identity(native),
               "launcher_source": identity(out / "measure_process.c"), "launcher_build_argv": compile_argv,
               "note_verifier": {"binary": identity(verifier), "build_argv": verifier_argv,
                                 "inputs": [identity(out / name) for name in (verifier_source.name, "bear_ed25519.c", "bear_ed25519.h")],
                                 "limits": "Python independently validates ELF metadata and digest binding; signature primitive shares the retained bundled diagnostic crypto."},
               "test_signer": {"public_key": TEST_SIGNER_PUB, "fixture": "RFC 8032 section 7.1 test 1; public test seed, never production"},
               "fixtures": fixture_identities, "cases": results, "commands": commands,
               "host": {"uname": list(platform.uname()), "affinity": sorted(os.sched_getaffinity(0)),
                        "cpuinfo_first_processor": Path("/proc/cpuinfo").read_text().split("\n\n")[0],
                        "loadavg_before": list(os.getloadavg())},
               "method": {"rounds": args.rounds, "warmups": args.warmups, "paired_order": "alternating AB/BA",
                          "workload_count": len(cases), "selected_workloads": [case["name"] for case in cases],
                          "clock": "CLOCK_MONOTONIC around native fork/exec/wait4",
                          "rss": "native child ru_maxrss in KiB; includes small native pre-exec image, never Python image",
                          "cache": "page-cache warm; object cache absent except explicit cold/warm-v4 workloads, each lane has its own directory",
                          "affinity": "not pinned", "frequency": "not fixed",
                          "validation": "every output hash, ELF audit before timing, cross-lane byte identity except verified tool-specific exec note payload, proof binding and signature verification outside timing",
                          "environment": environment, "per_command_timeout_s": args.timeout, "aggregate_timeout_s": 60,
                          "interpretation": "STABLE is MAD threshold <=0.25, not statistical significance. No emitted code execution."}}
    started = time.monotonic()
    def execute(argv, tag, measured=False):
        if time.monotonic() - started >= 55:
            raise RuntimeError("aggregate measurement budget exhausted")
        stdout = out / (tag + ".stdout")
        stderr = out / (tag + ".stderr")
        launch = [str(native), str(stdout), str(stderr), str(args.timeout), "--"] + argv
        done = subprocess.run(launch, capture_output=True, text=True, env=environment, timeout=args.timeout + 2)
        if done.returncode:
            raise RuntimeError("measurement launcher refused: " + done.stderr)
        stat = json.loads(done.stdout)
        stat.update({"argv": argv, "stdout": str(stdout), "stderr": str(stderr), "measured": measured})
        commands.append(stat)
        if stat["returncode"] or stat["timed_out"]:
            raise RuntimeError("child failed: " + tag + "; " + stderr.read_text())
        profile = {}
        for line in stderr.read_text().splitlines():
            if line.startswith("BASM_PROFILE "):
                if profile:
                    raise RuntimeError("duplicate profile record: " + tag)
                fields = line.split()[1:]
                for field in fields:
                    matched = re.fullmatch(r"([a-z0-9_]+)=(\d+)", field)
                    if not matched or matched[1] in profile:
                        raise RuntimeError("malformed profile field: " + tag)
                    profile[matched[1]] = int(matched[2])
        if "--profile" in argv:
            required = {"source_ns", "preprocess_ns", "layout_ns", "emit_ns", "write_ns",
                        "layout_passes", "final_pass", "source_bytes", "output_bytes", "cache_hit"}
            if not required <= profile.keys():
                raise RuntimeError("profile metrics missing: " + tag)
        stat["phase_telemetry"] = profile
        return stat
    try:
        for case in cases:
            name = case["name"]
            record = {"name": name, "format": case["format"], "mode": case["mode"], "lanes": {}, "observations": []}
            results.append(record)
            outputs = {}
            proofs = {}
            caches = {}
            expected_bytes = None
            frozen_proofs = {}
            frozen_outputs = {}
            def assemble(role, index, measured):
                nonlocal expected_bytes
                obj = outputs[role]
                proof = proofs[role]
                obj.unlink(missing_ok=True)
                proof.unlink(missing_ok=True)
                argv = [lanes[role]["binary"]["path"], "--profile", "-f", case["format"], "-o", str(obj)] + case["extra"]
                if case["mode"] in PROOF_MODES:
                    argv += ["--emit-attestation-v4" if case["mode"] in V4_MODES else "--emit-attestation", str(proof)]
                if case["mode"] in SIGNED_MODES:
                    argv += ["--sign", str(key)]
                if case["mode"] == "combined-proof":
                    argv += ["--emit-exec-proof", "--sign-exec-proof", str(key)]
                if case["mode"] in ("cache-cold", "cache-warm"):
                    if case["mode"] == "cache-cold" and caches[role].exists():
                        shutil.rmtree(caches[role])
                    argv += ["--rel8-escrow", str(caches[role]), "--rel8-key", str(key)]
                argv += [case["source"]]
                tag = name + "-" + role + "-" + index
                sample = execute(argv, tag, measured)
                if not obj.is_file() or not obj.stat().st_size:
                    raise RuntimeError("assembler succeeded without fresh output")
                sample["object"] = identity(obj)
                object_bytes = obj.read_bytes()
                if role in frozen_outputs and frozen_outputs[role] != object_bytes:
                    raise RuntimeError("object nondeterministic within one lane")
                frozen_outputs.setdefault(role, object_bytes)
                if case["mode"] in ("cache-cold", "cache-warm"):
                    expected_hit = int(case["mode"] == "cache-warm" and index != "validation")
                    if sample["phase_telemetry"]["cache_hit"] != expected_hit:
                        raise RuntimeError("cache workload did not exercise requested cold/hit state")
                if case["mode"] in PROOF_MODES:
                    fields = validate_proof(proof, Path(argv[0]), Path(case["source"]), obj,
                                            case["mode"] in SIGNED_MODES, TEST_SIGNER_PUB)
                    if role in frozen_proofs and proof.read_bytes() != frozen_proofs[role]:
                        raise RuntimeError("proof nondeterministic within one lane")
                    frozen_proofs.setdefault(role, proof.read_bytes())
                    sample["proof"] = identity(proof)
                    if case["mode"] == "combined-proof":
                        object_bytes, pubkey, digest, signature = validate_exec_note(object_bytes, Path(argv[0]),
                                                                                   Path(case["source"]), fields.get("signature_pub"))
                        execute([str(verifier), pubkey, digest, signature], tag + "-notecheck")
                        sample["normalized_object_sha256"] = hashlib.sha256(object_bytes).hexdigest()
                if expected_bytes is None:
                    expected_bytes = object_bytes
                elif object_bytes != expected_bytes:
                    raise RuntimeError("output bytes differ: " + name + "/" + role)
                if case["mode"] == "explain":
                    trace = json.loads(Path(sample["stdout"]).read_text())
                    if trace.get("schema") != "basm-intent-trace-v1" or trace.get("profile") != "public":
                        raise RuntimeError("explanation framing/profile differs")
                    if trace.get("coverage", {}).get("instructions") != 4:
                        raise RuntimeError("explanation lost a tiny instruction")
                    normalized = json.dumps(trace, sort_keys=True, separators=(",", ":"))
                    if "explain_identity" in record and record["explain_identity"] != normalized:
                        raise RuntimeError("explanation differs between samples/lanes")
                    record.setdefault("explain_identity", normalized)
                    sample["explanation_sha256"] = hashlib.sha256(normalized.encode()).hexdigest()
                return sample
            for role in lanes:
                outputs[role] = out / (name + "-" + role + ".o")
                proofs[role] = out / (name + "-" + role + ".basmproof")
                caches[role] = out / (name + "-" + role + "-cache")
                first = assemble(role, "validation", False)
                if case["format"] == "elf64":
                    execute([str(elftool), "audit", str(outputs[role])], name + "-" + role + "-audit")
                if case["mode"] in PROOF_MODES:
                    argv = [str(elftool), "attest"]
                    if case["mode"] in SIGNED_MODES:
                        argv += ["--strict"]
                    execute(argv + [str(proofs[role])], name + "-" + role + "-proofcheck")
                record["lanes"][role] = {"initial_output": first["object"]}
            for index in range(args.warmups + args.rounds):
                order = list(lanes)
                if index % 2:
                    order.reverse()
                pair = {"round": index, "warmup": index < args.warmups}
                for role in order:
                    pair[role] = assemble(role, str(index), not pair["warmup"])
                record["observations"].append(pair)
            measured = [p for p in record["observations"] if not p["warmup"]]
            stable = True
            for role in lanes:
                lane_result = record["lanes"][role]
                for field in ("wall_ns", "user_us", "system_us", "peak_rss_kib"):
                    lane_result[field] = summary([p[role][field] for p in measured])
                common = set.intersection(*(set(p[role]["phase_telemetry"]) for p in measured))
                lane_result["phase_telemetry"] = {field: summary([p[role]["phase_telemetry"][field] for p in measured]) for field in sorted(common)}
                stable &= lane_result["wall_ns"]["relative_mad"] <= .25
            if "candidate" in lanes:
                record["paired_baseline_over_candidate"] = summary([p["baseline"]["wall_ns"] / p["candidate"]["wall_ns"] for p in measured])
                ratio = record["paired_baseline_over_candidate"]
                stable &= ratio["relative_mad"] <= .25
                record["performance_boundary"] = "REGRESSION_OVER_15_PERCENT" if ratio["median"] < 1 / 1.15 else "WITHIN_15_PERCENT_BOUNDARY"
            record["status"] = "STABLE" if stable else "INCONCLUSIVE"
            print(name, record["status"], {role: round(record["lanes"][role]["wall_ns"]["median"] / 1e6, 3) for role in lanes}, flush=True)
        for role, lane in lanes.items():
            if identity(Path(lane["binary"]["path"])) != lane["binary"] or identity(Path(lane["snapshot"]["path"])) != lane["snapshot"]:
                raise RuntimeError("tool identity drifted: " + role)
        for old in fixture_identities:
            if identity(Path(old["path"])) != old:
                raise RuntimeError("fixture drifted")
        if identity(elftool) != receipt["inspector"]:
            raise RuntimeError("inspector drifted")
        if identity(verifier) != receipt["note_verifier"]["binary"] or identity(native) != receipt["launcher"]:
            raise RuntimeError("measurement helper drifted")
        if identity(Path(__file__).resolve()) != receipt["runner"]:
            raise RuntimeError("measurement runner drifted")
        if identity(out / "perf_campaign.py")["sha256"] != receipt["runner"]["sha256"]:
            raise RuntimeError("retained runner snapshot differs")
        receipt["status"] = "INCONCLUSIVE" if any(c["status"] == "INCONCLUSIVE" for c in results) else "STABLE"
        receipt["regressions_over_15_percent"] = [c["name"] for c in results if c.get("performance_boundary") == "REGRESSION_OVER_15_PERCENT"]
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        receipt["status"] = "REFUSED"
        receipt["error"] = str(exc)
        print(str(exc), file=sys.stderr)
    finally:
        receipt["elapsed_s"] = time.monotonic() - started
        receipt["host"]["loadavg_after"] = list(os.getloadavg())
        (out / "result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print("RESULT", out / "result.json", receipt["status"], flush=True)
    if receipt["status"] == "REFUSED": return 1
    if receipt["status"] == "INCONCLUSIVE": return 2
    if receipt.get("regressions_over_15_percent"): return 3
    return 0

if __name__ == "__main__":
    sys.exit(main())
