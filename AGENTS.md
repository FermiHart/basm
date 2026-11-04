<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Developing Basm

Preserve the public Linux x86-64 assembler contract, the separate compatibility
binary and the optional nature of inspection, evidence and installation.
The sovereign build uses Bear, BearLinker and blibc. The host diagnostic build
uses an explicitly selected host compiler; never substitute one lane silently
for the other. Keep cryptographic attribution and per-file licenses intact.

Use the current language contract in `SUPPORTED-SUBSET.md` and the build and
test guides in `docs/`. For a behavior change, add focused positive and negative
regressions, including output preservation where applicable. Keep the parser,
encoder and instruction inventory consistent. Do not add a parallel engine for
an existing responsibility.

Stage explicit paths. Keep working build outputs, caches, credentials and
private signing keys out of Git. Reviewed development distributions under
`downloads/0.1.0-dev.1/` are intentional published artifacts; preserve their
manifests and checksums. Clearly labeled synthetic test seeds are fixtures,
never release keys.

Record exact commands, binary identities and results. Failed, unavailable and
unrun checks retain those states. Standalone checks do not qualify Beyond boot,
guest execution or hardware. Integration tests may require an explicit Beyond
checkout; do not alter that checkout as a side effect of this project's work.
