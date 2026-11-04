<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Assembler modules

`../basm.c` is the production entry point. The implementation remains one C
translation unit and includes these modules in this order:

| Module | Responsibility |
|---|---|
| `01_foundation.inc` | Shared types, state, bounds, symbols and diagnostics |
| `02_encoding.inc` | Instruction dispatch and byte encoding |
| `03_parser.inc` | Assembly syntax, expressions, directives and layout |
| `04_writer.inc` | Flat and ELF64 output |
| `05_preprocessor.inc` | Defines, macros, includes and bounded expansion |
| `06_attestation.inc` | Integrity evidence and proof verification |
| `07_main.inc` | CLI, orchestration and output publication |

Static linkage, shared state and pass ordering are part of this architecture.
A change to those boundaries needs focused behavioral coverage. Instruction
forms and declared effects are maintained in `../isa/`; trace and partial CFG
support are in `../intent/`.

The active language contract is [SUPPORTED-SUBSET.md](../SUPPORTED-SUBSET.md).
Use the [test guide](../docs/TESTING.md) for standalone checks and integration
requirements.

`../quarantine/basm_monolith_legacy.c` is an immutable comparison fixture used
by `../tests/unity_legacy_gate.sh` and `../bench_nasm.sh`. It is not compiled into
the public assembler. That integration gate has its own pinned expectations;
a change here does not automatically qualify the legacy comparison.
