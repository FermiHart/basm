<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Legacy comparison fixture

`basm_monolith_legacy.c` is a frozen reference retained under its original
Unlicense notice. It is used by `tests/unity_legacy_gate.sh` and `bench_nasm.sh`
for explicit compatibility comparisons and is not an active assembler module
or an input to the standalone build.

Preserve its bytes and attribution. The comparison scripts retain Beyond
integration assumptions and pinned expectations; see [the test guide](../docs/TESTING.md)
before running them. Production sources are in `basm.c` and `modules/`.
