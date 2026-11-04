<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Contributing

Build and check the host lane without a full Beyond toolchain:

```sh
make host
make check
```

See [docs/BUILD.md](docs/BUILD.md) for dependencies and the sovereign build,
and [docs/TESTING.md](docs/TESTING.md) for the scope of each test workflow.

## Changing the assembler

Provide a small reproducer and expected bytes, symbols, relocations or a
specific diagnostic. Include an accepted case and a refusal case when changing
a boundary. Where a command can replace files, check that a refusal preserves
the existing output. Preserve the evidence of a failure before changing its
expectation.

Update [SUPPORTED-SUBSET.md](SUPPORTED-SUBSET.md) when language behavior changes.
Instruction forms originate in `isa/forms.tsv`. Regenerate both artifacts,
review their diff and verify freshness:

```sh
perl isa/generate.pl --format header --output isa/intent_forms.h
perl isa/generate.pl --format inventory --output isa/INVENTORY.md
perl isa/generate.pl --check
```

Do not edit a generated artifact to hide disagreement with its source. Keep
syntax, encoding, declared effects and rejection behavior consistent. New
syntax or dependencies need a bounded contract and a compatibility decision.

## Reporting results

Include the revision, platform, build lane, tool versions, exact commands and
relevant output. Distinguish a controlled rejection from a crash. Failed,
unavailable and unrun checks retain those states; host checks do not qualify
Beyond boot, guest execution or physical hardware.

Performance comparisons need a fixed workload, identified executables and
validated output. Report variation and inconclusive results. Instruction
counts, signatures and successful assembly do not prove program correctness.

## Repository contents and licensing

Keep working builds, caches, credentials and private signing keys out of Git.
Reviewed archives under `downloads/0.1.0-dev.1/` are intentional development
deliverables. Synthetic public test seeds must remain clearly labeled fixtures
and must never be reused as release keys. Stage paths explicitly.

Follow the file's existing license and attribution. The primary project license
is BSD-3-Clause; preserve the exceptions and cryptographic credits in
[NOTICE](NOTICE) and `REUSE.toml`.

For a bug report, include minimal source, `basm --version`, the exact command,
expected and actual output, platform and build lane. Send sensitive reports
through the contact listed in [SECURITY.md](SECURITY.md).
