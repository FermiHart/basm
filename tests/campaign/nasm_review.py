#!/usr/bin/env python3
"""Independently recompute N30 per-case correctness/time/CPU/RSS verdicts.

Uses only the Python standard library. It never imports the collector, its
statistics, the artifact ledger, or an assembler, and never executes a process.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys

WORKLOADS = ("tiny", "instructions", "instructions-large", "branches", "macros",
             "macros-large", "includes", "relocations", "custom-sections", "flat-bin",
             "incbin", "incbin-large", "labels-10000", "globals-reversed-10000",
             "contextual-expressions", "addressing")
FIELDS = ("wall_ns", "user_us", "system_us", "peak_rss_kib", "cpu_total_us")
CORE = ("sample_count", "lanes", "paired_nasm_over_basm", "paired_cpu_nasm_over_basm",
        "status", "lower_paired_median")


def median(values):
    ordered = sorted(values)
    count = len(ordered)
    if not count:
        raise ValueError("cannot summarize an empty sample")
    middle = count // 2
    return ordered[middle] if count % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def distribution(values):
    center = median(values)
    deviation = median([abs(value - center) for value in values])
    return {"median": center, "mad": deviation, "relative_mad": deviation / center if center else 0,
            "minimum": min(values), "maximum": max(values)}


def statistics_for(pairs):
    lanes = {}
    for role in ("nasm", "basm"):
        lanes[role] = {field: distribution([pair[role][field] for pair in pairs]) for field in FIELDS[:-1]}
        lanes[role]["cpu_total_us"] = distribution([pair[role]["user_us"] + pair[role]["system_us"] for pair in pairs])
    wall = distribution([pair["nasm"]["wall_ns"] / pair["basm"]["wall_ns"] for pair in pairs])
    cpu_denominators = [pair["basm"]["user_us"] + pair["basm"]["system_us"] for pair in pairs]
    cpu = (distribution([(pair["nasm"]["user_us"] + pair["nasm"]["system_us"]) / denominator
                         for pair, denominator in zip(pairs, cpu_denominators)])
           if all(value > 0 for value in cpu_denominators) else None)
    stable = (wall["relative_mad"] <= .25 and lanes["nasm"]["wall_ns"]["relative_mad"] <= .25
              and lanes["basm"]["wall_ns"]["relative_mad"] <= .25)
    return {"sample_count": len(pairs), "lanes": lanes, "paired_nasm_over_basm": wall,
            "paired_cpu_nasm_over_basm": cpu, "status": "STABLE" if stable else "INCONCLUSIVE",
            "lower_paired_median": ("basm" if wall["median"] > 1 else "nasm" if wall["median"] < 1 else "equal") if stable else None,
            "gates": {"dispersion": stable, "wall": wall["median"] > 1,
                      "cpu": cpu is not None and cpu["median"] > 1,
                      "rss": lanes["basm"]["peak_rss_kib"]["median"] <= lanes["nasm"]["peak_rss_kib"]["median"]}}


def differences(actual, expected, prefix):
    """Find altered collector summaries, allowing only floating rounding noise."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [prefix]
        return [item for key, value in expected.items()
                for item in differences(actual.get(key), value, prefix + "/" + key)]
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        equal = (isinstance(actual, (int, float)) and not isinstance(actual, bool)
                 and math.isfinite(actual) and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12))
    else:
        equal = actual == expected
    return [] if equal else [prefix]


def parity_pass(validation):
    proof = validation.get("receipt", {}) if validation else {}
    return bool(validation and validation.get("equal") is True and not validation.get("requires_review")
                and validation.get("secondary_returncode") in (None, 0) and proof.get("path")
                and isinstance(proof.get("bytes"), int) and proof["bytes"] > 0 and len(str(proof.get("sha256", ""))) == 64)


def final_configuration(receipt):
    method = receipt.get("method", {})
    basm = receipt.get("tools", {}).get("basm", {})
    nasm = receipt.get("tools", {}).get("nasm", {})
    build = basm.get("build", {})
    flags = build.get("flags", [])
    required = {
        "all_sixteen_original_cases": [case.get("name") for case in receipt.get("cases", [])] == list(WORKLOADS),
        "performance_mode": receipt.get("mode") == "performance",
        "three_blocks": method.get("blocks") == 3,
        "fifteen_measured_pairs": method.get("rounds") == 15,
        "three_warmup_pairs": method.get("warmups") == 3,
        "original_dispersion_limit": method.get("dispersion_threshold_relative_mad") == .25,
        "native_timeout_bounds": method.get("per_command_timeout_s") == 10 and method.get("aggregate_timeout_s") == 600,
        "cpu_zero_affinity": receipt.get("host", {}).get("cpu_requested") == 0 and receipt.get("host", {}).get("affinity_effective") == [0]
                             and receipt.get("host", {}).get("affinity_after") == [0],
        "environment_allowlist": method.get("environment") == {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "0"},
        "full_software_sha_host": build.get("lane") == "HOST_DIAGNOSTIC_NOT_SOVEREIGN" and build.get("sha_mode") == "software" and not build.get("sanitizers")
                                  and basm.get("binary", {}).get("sha256") == build.get("artifacts", {}).get("basm-host", {}).get("sha256"),
        "gcc13_o2_basm": "13.3.0" in build.get("compiler_version", "") and [flag for flag in flags if flag.startswith("-O")] == ["-O2"]
                         and not any("BASM_PUBLIC_ONLY" in flag for flag in flags),
        "nasm302_receipt": str(nasm.get("version", "")).startswith("NASM version 3.02 ") and bool(nasm.get("build_receipt"))
                           and nasm.get("binary", {}).get("sha256") == nasm.get("build", {}).get("artifacts", {}).get("nasm", {}).get("sha256"),
        "nasm_default_optimization": bool(receipt.get("nasm_default_optimization_check", {}).get("comparisons"))
                                     and all(item.get("matches_default_raw_object") for item in receipt.get("nasm_default_optimization_check", {}).get("comparisons", [])),
        "original_generator": receipt.get("preregistered_protocol", {}).get("content", {}).get("fixture_generator_sha256")
                              == "148e1f57d7ab03ade65f702cef6f0bbd78e63c4391a249834d66019eb65402fb",
    }
    return required


def review_result(receipt):
    """Pure reconstruction. Separate audit_files re-reads evidence after collection."""
    errors = []
    if receipt.get("schema") != "BASM-NASM-BENCHMARK-v2":
        errors.append("unsupported collector schema")
    method = receipt.get("method", {})
    blocks, rounds, warmups = (method.get(key) for key in ("blocks", "rounds", "warmups"))
    if blocks not in (1, 3) or not isinstance(rounds, int) or not 5 <= rounds <= 15 or not isinstance(warmups, int) or not 1 <= warmups <= 3:
        return {"schema": "BASM-NASM-INDEPENDENT-REVIEW-v1", "status": "REFUSED", "errors": ["invalid predeclared sample counts"],
                "cases": [], "summary": {"full_goal_met": False, "effective_goal": "0/16", "goal_status": "REFUSED"}}
    commands = {}
    output_paths = set()
    lengths = set()
    output_index = 0
    for command in receipt.get("commands", []):
        key = command.get("stdout")
        if not key or key in commands:
            errors.append("missing or duplicated command stdout identity")
        commands[key] = command
        if "output_path" in command:
            path = command["output_path"]
            if path in output_paths:
                errors.append("reused output path: " + path)
            output_paths.add(path)
            lengths.add(len(path))
            if Path(path).name != "%06d-%s.o" % (output_index, command.get("tool")) or Path(path).parent.name != "objects":
                errors.append("output path is not the predeclared fixed-width invocation path")
            output_index += 1
            argv = command.get("argv", [])
            if "-o" not in argv or argv.index("-o") + 1 >= len(argv) or argv[argv.index("-o") + 1] != path:
                errors.append("output path disagrees with assembler argv: " + path)
    if len(lengths) > 1:
        errors.append("assembler output paths have different lengths")
    names = [case.get("name") for case in receipt.get("cases", [])]
    if len(names) != len(set(names)) or any(name not in WORKLOADS for name in names):
        errors.append("duplicate or unknown workload")
    integrity = receipt.get("artifact_integrity", {}).get("status") == "PASS" and not receipt.get("artifact_integrity", {}).get("failed")
    admissible = receipt.get("status") in ("STABLE", "INCONCLUSIVE", "PARTIAL_INCOMPATIBLE", "VALIDATED_ALL", "VALIDATED_WITH_EXCLUSIONS")
    expected_sequence = []
    if receipt.get("mode") != "validation_only":
        for block in range(1, blocks + 1):
            for case in receipt.get("cases", []):
                if case.get("eligible"):
                    for index in range(rounds + warmups):
                        order = ("nasm", "basm") if (index + block - 1) % 2 == 0 else ("basm", "nasm")
                        expected_sequence += [(case["name"], block, index, role) for role in order]
    actual_sequence = [(command.get("case"), command.get("block"), command.get("round"), command.get("tool"))
                       for command in receipt.get("commands", []) if "block" in command]
    if actual_sequence != expected_sequence:
        errors.append("native command sequence differs from predeclared block/case/pair order")
    used_commands = set()
    cases = []
    for case in receipt.get("cases", []):
        name = case["name"]
        result = {"name": name, "eligible": bool(case.get("eligible")), "block_results": [], "pooled": None,
                  "gates": {"correctness": False, "integrity": integrity and admissible,
                            "schedule": False, "summary_consistency": False,
                            "dispersion": False, "wall": False, "cpu": False, "rss": False}}
        cases.append(result)
        if not case.get("eligible"):
            result.update({"verdict": "EXCLUDED_INCOMPATIBLE", "unmet_gates": ["correctness"],
                           "validation_before": case.get("validation_before")})
            if case.get("observations"):
                errors.append(name + ": incompatible case was sampled")
            continue
        if receipt.get("mode") == "validation_only":
            result["gates"]["correctness"] = parity_pass(case.get("validation_before")) and parity_pass(case.get("validation_after"))
            result.update({"verdict": "NOT_MEASURED", "unmet_gates": ["performance_not_measured"]})
            continue
        case_errors = []
        observations = case.get("observations", [])
        if len(observations) != blocks * (rounds + warmups):
            case_errors.append("unexpected total pair count")
        measured_all = []
        for block in range(1, blocks + 1):
            block_pairs = [pair for pair in observations if pair.get("block") == block]
            if len(block_pairs) != rounds + warmups:
                case_errors.append("unexpected pair count in block %d" % block)
                continue
            measured = []
            for index, pair in enumerate(block_pairs):
                order = ["nasm", "basm"] if (index + block - 1) % 2 == 0 else ["basm", "nasm"]
                if pair.get("round") != index or pair.get("warmup") != (index < warmups) or pair.get("order") != order:
                    case_errors.append("pair schedule changed in block %d" % block)
                for role in ("nasm", "basm"):
                    sample = pair.get(role, {})
                    key = sample.get("stdout")
                    if key in used_commands or commands.get(key) != sample:
                        case_errors.append("pair does not identify one original native command")
                    used_commands.add(key)
                    if sample.get("case") != name or sample.get("tool") != role or sample.get("block") != block or sample.get("round") != index or sample.get("measured") != (index >= warmups):
                        case_errors.append("sample metadata disagrees with its pair")
                    expected_argv = [receipt.get("tools", {}).get(role, {}).get("binary", {}).get("path"),
                                     "-f", case.get("format"), "-o", sample.get("output_path")]
                    expected_argv += case.get("extra", []) + [case.get("source")]
                    if sample.get("argv") != expected_argv:
                        case_errors.append("sample argv differs from the same-source default assembler command")
                    if sample.get("returncode") != 0 or sample.get("timed_out") is not False:
                        case_errors.append("sample command failed or timed out")
                    for field in FIELDS[:-1]:
                        value = sample.get(field)
                        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or (field in ("wall_ns", "peak_rss_kib") and value == 0):
                            case_errors.append("invalid native integer field: " + field)
                    initial = case.get("lanes", {}).get(role, {}).get("initial_output", {})
                    if not isinstance(initial.get("bytes"), int) or initial["bytes"] <= 0 or len(str(initial.get("sha256", ""))) != 64:
                        case_errors.append("missing initial object identity")
                    if sample.get("object", {}).get("path") != sample.get("output_path"):
                        case_errors.append("sample object is not its recorded output path")
                    if any(sample.get("object", {}).get(field) != initial.get(field) for field in ("bytes", "sha256")):
                        case_errors.append("per-lane object identity changed")
                if index >= warmups:
                    measured.append(pair)
            if case_errors:
                continue
            stats = statistics_for(measured)
            stats["block"] = block
            result["block_results"].append(stats)
            measured_all.extend(measured)
        stored_blocks = case.get("block_results", [])
        if len(stored_blocks) != blocks:
            case_errors.append("collector omitted a block summary")
        if not case_errors:
            result["pooled"] = statistics_for(measured_all)
            for recomputed, stored in zip(result["block_results"], stored_blocks):
                if stored.get("block") != recomputed["block"]:
                    case_errors.append("collector block summary order changed")
                case_errors.extend(differences(stored, {key: recomputed[key] for key in CORE}, "block-%d" % recomputed["block"]))
            case_errors.extend(differences(case.get("pooled"), {key: result["pooled"][key] for key in CORE}, "pooled"))
            for role in ("nasm", "basm"):
                case_errors.extend(differences(case.get("lanes", {}).get(role), result["pooled"]["lanes"][role], "lanes/" + role))
            for field in ("paired_nasm_over_basm", "paired_cpu_nasm_over_basm"):
                case_errors.extend(differences(case.get(field), result["pooled"][field], field))
        validations = [case.get("validation_before"), case.get("validation_after")]
        validations += [item.get(field) for item in stored_blocks for field in ("validation_before", "validation_after")]
        result["gates"]["correctness"] = all(parity_pass(value) for value in validations)
        result["gates"]["schedule"] = not case_errors
        result["gates"]["summary_consistency"] = not case_errors
        if result["pooled"]:
            for gate in ("dispersion", "wall", "cpu", "rss"):
                result["gates"][gate] = all(item["gates"][gate] for item in result["block_results"] + [result["pooled"]])
        result["unmet_gates"] = [gate for gate, passed in result["gates"].items() if not passed]
        result["verdict"] = ("REFUSED" if case_errors or not integrity or not admissible else
                             "WIN" if not result["unmet_gates"] else
                             "INCONCLUSIVE" if not result["gates"]["dispersion"] else "NOT_MET")
        if case_errors:
            result["errors"] = sorted(set(case_errors))
            errors.extend(name + ": " + error for error in result["errors"])
    unused_measured = [key for key, command in commands.items() if command.get("measured") and key not in used_commands]
    if unused_measured:
        errors.append("measured commands exist outside the reported pairs")
    if errors:
        for case in cases:
            case["gates"]["summary_consistency"] = False
            if case["eligible"] and case["verdict"] != "NOT_MEASURED":
                case["verdict"] = "REFUSED"
                case["unmet_gates"] = [gate for gate, passed in case["gates"].items() if not passed]
    configuration = final_configuration(receipt)
    wins = sum(case["verdict"] == "WIN" for case in cases)
    final_protocol = all(configuration.values())
    full_goal = wins == 16 and final_protocol and not errors and integrity and admissible
    goal_status = ("REFUSED" if errors or not integrity or not admissible else "MET" if full_goal else
                   "NOT_MET" if final_protocol else "NOT_EVALUATED_UNDER_COMPLETE_FINAL_PROTOCOL")
    return {"schema": "BASM-NASM-INDEPENDENT-REVIEW-v1", "status": "REFUSED" if errors or not integrity or not admissible else "RECOMPUTED",
            "implementation": "Independent order-statistic median/MAD and native-command reconstruction; no collector statistics imported.",
            "collector_status": receipt.get("status"), "protocol_purpose": receipt.get("protocol_purpose"),
            "errors": errors, "final_configuration": configuration, "cases": cases,
            "summary": {"reported_cases": len(cases), "required_cases": 16, "winning_cases": wins,
                        "effective_goal": "%d/16" % wins, "full_goal_met": full_goal, "goal_status": goal_status,
                        "gate_counts": {gate: sum(case["gates"][gate] for case in cases)
                                        for gate in ("correctness", "integrity", "schedule", "summary_consistency", "dispersion", "wall", "cpu", "rss")},
                        "nonwinning_cases": [{"name": case["name"], "verdict": case["verdict"], "unmet_gates": case["unmet_gates"]}
                                             for case in cases if case["verdict"] != "WIN"]}}


def file_record(path, single_link=False):
    path = Path(os.path.abspath(path))
    def state(info):
        return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode, "nlink": info.st_nlink,
                "bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink != 1):
        raise ValueError("nonregular or aliased evidence: " + str(path))
    digest, size = hashlib.sha256(), 0
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        closed = os.fstat(stream.fileno())
    after = path.lstat()
    if not state(before) == state(opened) == state(closed) == state(after) or size != after.st_size:
        raise ValueError("evidence changed during independent read: " + str(path))
    return {"path": str(path), "bytes": size, "sha256": digest.hexdigest(), "file_state": state(after)}


def short_identity(path):
    record = file_record(path)
    return {key: record[key] for key in ("path", "bytes", "sha256")}


def audit_files(receipt):
    """Independently re-read every ledger identity and cross-check its coverage."""
    errors, checks = [], []
    audit_identity = receipt.get("artifact_integrity", {}).get("receipt", {})
    try:
        if short_identity(audit_identity["path"]) != audit_identity:
            raise ValueError("artifact ledger identity changed")
        ledger = json.loads(Path(audit_identity["path"]).read_text())
        if ledger.get("status") != "PASS" or ledger.get("failed"):
            errors.append("recorded final artifact audit did not pass")
        entries = {entry["path"]: entry for entry in ledger["entries"]}
        if len(entries) != ledger["tracked"] or len(entries) != len(ledger["entries"]):
            errors.append("artifact ledger count or path uniqueness changed")
        if receipt.get("artifact_integrity", {}).get("tracked") != ledger["tracked"]:
            errors.append("result and ledger artifact counts disagree")
        for entry in ledger["entries"]:
            try:
                actual = file_record(entry["path"], entry["single_link"]) if os.path.lexists(entry["path"]) else None
                matches = actual == entry["expected"]
                checks.append({"path": entry["path"], "kind": entry["kind"], "matches": matches,
                               "actual": actual})
                if not matches:
                    errors.append("artifact changed: " + entry["path"])
                if not entry.get("matches"):
                    errors.append("artifact had already failed the collection-time audit: " + entry["path"])
            except (OSError, ValueError) as exc:
                errors.append(str(exc))
        expected_paths = []
        def check_reference(reference):
            path = reference["path"]
            expected_paths.append(path)
            expected = entries.get(path, {}).get("expected")
            if expected is None or any(reference.get(key) != expected.get(key) for key in ("path", "bytes", "sha256")):
                errors.append("result reference disagrees with ledger identity: " + path)
        for command in receipt.get("commands", []):
            expected_paths.extend([command["stdout"], command["stderr"]])
            if "output_path" in command:
                expected_paths.append(command["output_path"])
                expected = entries.get(command["output_path"], {}).get("expected")
                obj = command.get("object")
                if (obj is None) != (expected is None) or (obj and any(obj[key] != expected[key] for key in ("path", "bytes", "sha256"))):
                    errors.append("output command and ledger identity disagree: " + command["output_path"])
        for reference in receipt.get("fixtures", []) + receipt.get("retained_helpers", []):
            check_reference(reference)
        for lane in receipt.get("tools", {}).values():
            for key in ("binary", "snapshot", "build_receipt"):
                if key in lane:
                    check_reference(lane[key])
        for case in receipt.get("cases", []):
            validations = [case.get("validation_before"), case.get("validation_after")]
            validations += [item.get(key) for item in case.get("block_results", []) for key in ("validation_before", "validation_after")]
            for validation in validations:
                if not validation or "receipt" not in validation:
                    if case.get("eligible"):
                        errors.append("eligible case is missing its parity receipt: " + case["name"])
                    continue
                path = validation["receipt"]["path"]
                check_reference(validation["receipt"])
                saved = json.loads(Path(path).read_text())
                if saved.get("equal") != validation.get("equal"):
                    errors.append("saved parity disagrees with result: " + path)
                for snapshot in saved.get("artifacts", {}).values():
                    check_reference(snapshot)
        for path in set(expected_paths):
            if path not in entries:
                errors.append("artifact missing from final ledger: " + path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append("cannot validate artifact ledger: " + str(exc))
    return {"status": "PASS" if not errors else "REFUSED", "checked": len(checks), "errors": errors, "checks": checks}


def markdown_report(review):
    summary = review["summary"]
    lines = ["# Independent NASM benchmark review", "", "Goal: **%s**, **%s**." % (summary["effective_goal"], summary["goal_status"]), "",
             "Ratios are medians of paired NASM/BearBasm values; above one favors BearBasm. RSS is native KiB. Each gate must pass in every block and pooled. The original 25% relative-MAD rule remains required.", "",
             "| Case | Scope | NASM ms | BearBasm ms | Wall ratio | CPU ratio | NASM RSS | BearBasm RSS | Unmet gates |",
             "|---|---|---:|---:|---:|---:|---:|---:|---|"]
    for case in review["cases"]:
        if not case["pooled"]:
            lines.append("| %s | %s | — | — | — | — | — | — | %s |" % (case["name"], case["verdict"], ", ".join(case["unmet_gates"])))
            continue
        for item in case["block_results"] + [case["pooled"]]:
            lanes = item["lanes"]
            cpu = item["paired_cpu_nasm_over_basm"]
            lines.append("| %s | %s | %.6f | %.6f | %.6f | %s | %g | %g | %s |" %
                         (case["name"], "block %d" % item["block"] if "block" in item else "pooled / " + case["verdict"],
                          lanes["nasm"]["wall_ns"]["median"] / 1e6, lanes["basm"]["wall_ns"]["median"] / 1e6,
                          item["paired_nasm_over_basm"]["median"], "%.6f" % cpu["median"] if cpu else "undefined",
                          lanes["nasm"]["peak_rss_kib"]["median"], lanes["basm"]["peak_rss_kib"]["median"],
                          ", ".join(gate for gate, passed in item["gates"].items() if not passed) or "none"))
    lines += ["", "## Full final protocol configuration", ""]
    lines += ["- %s: %s" % (name, "PASS" if passed else "NOT MET") for name, passed in review.get("final_configuration", {}).items()]
    lines += ["", "## Limits", "", "This is one fixed corpus on a shared host with warm caches, no fixed frequency and no exclusive core. No generated code was executed. No cross-case aggregate or claim about all workloads is computed. The independent JSON preserves all medians, MAD, ranges, units, block results and failed gates.", ""]
    if review.get("errors"):
        lines += ["## Refusal reasons", ""] + ["- " + error for error in review["errors"]] + [""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output.exists():
        parser.error("independent review output directory must be fresh")
    output.mkdir(parents=True, mode=0o700)
    initial = short_identity(args.result)
    receipt = json.loads(args.result.read_text())
    review = review_result(receipt)
    file_audit = audit_files(receipt)
    if file_audit["status"] != "PASS" or short_identity(args.result) != initial:
        review["status"] = "REFUSED"
        review["summary"].update({"goal_status": "REFUSED", "full_goal_met": False, "effective_goal": "0/16", "winning_cases": 0})
        review["errors"].extend(file_audit["errors"] or ["result changed during review"])
        for case in review["cases"]:
            case["gates"]["integrity"] = False
            if case["eligible"]:
                case["verdict"] = "REFUSED"
                case["unmet_gates"] = [gate for gate, passed in case["gates"].items() if not passed]
        review["summary"]["gate_counts"] = {gate: sum(case["gates"][gate] for case in review["cases"])
                                               for gate in ("correctness", "integrity", "schedule", "summary_consistency", "dispersion", "wall", "cpu", "rss")}
        review["summary"]["nonwinning_cases"] = [{"name": case["name"], "verdict": case["verdict"], "unmet_gates": case["unmet_gates"]}
                                                     for case in review["cases"] if case["verdict"] != "WIN"]
    audit_path = output / "file-audit.json"
    audit_path.write_text(json.dumps(file_audit, indent=2, sort_keys=True) + "\n")
    review["file_audit"] = {"status": file_audit["status"], "checked": file_audit["checked"], "identity": short_identity(audit_path)}
    review["input_result"] = initial
    review["reviewer"] = short_identity(__file__)
    review["argv"] = sys.argv
    (output / "independent-review.json").write_text(json.dumps(review, indent=2, sort_keys=True) + "\n")
    (output / "independent-review.md").write_text(markdown_report(review))
    print(json.dumps({"status": review["status"], "summary": review["summary"], "output_dir": str(output)}, indent=2))
    return 1 if review["status"] == "REFUSED" else 0


if __name__ == "__main__":
    sys.exit(main())
