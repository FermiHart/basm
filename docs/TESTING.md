<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Testing Basm

## Standalone checks

From the repository root:

```sh
make check
```

This builds the explicit host lane and runs `tools/check_standalone.py` with the
public assembler, compatibility assembler and `elftool`. In addition to the
[build dependencies](BUILD.md), the workflow needs Git and NASM; the executable
example uses a Linux ELF linker and Linux x86-64. No hosted CI service is needed.

The runner records binary hashes, commands, per-suite output and return codes in
`build/host/checks.json` and a fresh evidence directory. Missing or failed required
checks return nonzero. The Linux executable smoke is reported as unrun on other
platforms, without implying those platforms are qualified.

Coverage includes generated-ISA freshness, the language inventory, CLI parsing,
input admission, preprocessor limits, data and sections, 255-byte name boundaries,
ELF output, output publication, trust checks, layout, instruction bytes, traces,
partial CFG, seeded differential assembly, packaging and a small executable.
The public and compatibility binaries are selected explicitly. A compatibility
PASS cannot replace the public binary's required refusal.

To check existing executables without asking Make to rebuild them:

```sh
python3 tools/check_standalone.py \
  --basm /absolute/path/to/basm \
  --compat /absolute/path/to/basm-compat \
  --elftool /absolute/path/to/elftool \
  --output /path/to/new-checks.json
```

This identifies and tests the supplied binaries; it does not establish how they
were compiled. Preserve their build receipts separately when available.

## Focused checks

Select a regression that exercises the changed boundary. For example, after a
host build:

```sh
sh tests/subset_spec_test.sh
python3 tests/standalone/test_cli.py \
  --basm build/host/basm --compat build/host/basm-compat
```

The input, preprocessor, writer, publication and trust tests in `tests/campaign/`
are executable regression suites. Their directory name does not make them a
separate requirement to run every inherited integration test. Some suites use
NASM, host ELF inspectors or a prepared Beyond tree; check their arguments and
input assumptions before selecting them.

Differential cases must distinguish an unsupported input from a crash or a
wrong accepted encoding. Preserve failing sources and exact outputs. A known
limitation needs an explicit classification, not a silently discarded mismatch.

## Sanitizers

ASan and UBSan require a separately instrumented host build. Record the compiler,
flags, runtime options, binary identities and exact cases executed. A clean
instrumented run does not qualify the sovereign binary or unexecuted paths.

Leak detection is a separate capability. If LeakSanitizer cannot operate in the
environment, record it as unavailable; a run with `detect_leaks=0` provides no
leak-check result. Any sanitizer diagnostic in an executed case is a failure.

## Beyond integration and comparison fixtures

Some inherited scripts expect the embedded `toolchain/BearBasm` layout, a
bootstrap assembler, compiler/linker/runtime artifacts or the wider Beyond
source corpus. Their relative paths and old Make targets are not standalone
build interfaces. Run them only in an explicit integration checkout with the
required inputs, and report missing dependencies instead of treating them as PASS.

`tests/unity_legacy_gate.sh` and `bench_nasm.sh` use the immutable source in
`quarantine/` for comparison. The legacy gate also pins a modular-source hash;
those expectations do not automatically track this distribution. Do not refresh
a reference or expected hash merely to turn a failed comparison green.

The [laboratory guide](../lab/README.md) describes its separate identity collector
and timing runner. Laboratory tests are not part of `make check`. Whole-repository
assembly coverage, bootstrap closure, Beyond boot/guest execution and hardware
behavior each require their own evidence.
