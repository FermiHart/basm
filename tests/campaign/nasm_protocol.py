#!/usr/bin/env python3
"""Fixed N24 sampling schedule; no data-dependent sampling or retry policy."""
import ast
import hashlib
import json
from pathlib import Path

WORKLOADS = ("tiny", "instructions", "instructions-large", "branches", "macros",
             "macros-large", "includes", "relocations", "custom-sections", "flat-bin",
             "incbin", "incbin-large", "labels-10000", "globals-reversed-10000",
             "contextual-expressions", "addressing")
PROTOCOL_FILE = "nasm_n30_protocol.json"


def fixture_generator_hash(source_path):
    source = Path(source_path).read_text()
    function = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == "generate_fixtures")
    return hashlib.sha256(ast.get_source_segment(source, function).encode()).hexdigest()


def load_protocol(directory):
    directory = Path(directory)
    protocol = json.loads((directory / PROTOCOL_FILE).read_text())
    if protocol["workloads"] != list(WORKLOADS):
        raise ValueError("preregistered workload list changed")
    if fixture_generator_hash(directory / "nasm_benchmark.py") != protocol["fixture_generator_sha256"]:
        raise ValueError("original sixteen-fixture generator changed")
    return protocol


def block_schedule(blocks, rounds, warmups):
    if blocks not in (1, 3) or not 5 <= rounds <= 15 or not 1 <= warmups <= 3:
        raise ValueError("blocks must be 1 or 3, rounds 5..15 and warmups 1..3")
    return [{"block": block + 1,
             "pairs": [{"block": block + 1, "round": index,
                        "warmup": index < warmups,
                        "order": list(("nasm", "basm") if (index + block) % 2 == 0 else ("basm", "nasm"))}
                       for index in range(warmups + rounds)]}
            for block in range(blocks)]


def retention_reserve_bytes(blocks, validation_only):
    if validation_only:
        return 192 * 1024 * 1024
    return (2048 if blocks == 3 else 768) * 1024 * 1024
