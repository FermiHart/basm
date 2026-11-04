<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Security scope

Basm processes assembly source, includes, binary inclusions and optional
integrity evidence. Invalid input should produce a controlled error before
publishing an output with a different interpretation.

The assembler runs with the caller's filesystem permissions. Source can name
readable include and `incbin` paths. Use external filesystem and resource
restrictions when building untrusted projects; Basm is not a sandbox. The build
and package workflows do not download dependencies automatically.

## Evidence and trust

Attestations bind the assembler's recorded output, source and tool identities.
The v4 format also binds its consumed-input records and expanded-source digest.
Verification reopens the recorded files, so those paths and bytes must remain
available. Review evidence before sharing it: source paths and other recorded
input metadata may be private.

A valid signature establishes integrity under a key. Publisher approval requires
a separately trusted public key, supplied with `--trusted-key`. Requiring a
signature without pinning the key does not establish the signer's identity.
Development archive checksums are unsigned and need a trusted distribution path.
The optional PQC trailer is a placeholder and provides no post-quantum security.

An object attestation does not cover a later linked executable automatically.
It also does not prove instruction semantics, memory safety or safe execution.
Explanation, control-flow and contract tools expose their modeled boundaries;
an unmodeled instruction remains unproven.

Keep private signing keys outside the repository. Demo and test seeds are
public synthetic fixtures, never release credentials. A command that fails
must preserve previous output according to its publication contract.

## Reporting a vulnerability

Send a private report to **contact@fermihart.com**. Include the affected version,
platform and build lane, minimal source or evidence, exact command and observed
result. Remove live credentials and unrelated personal data from the report.
A response SLA and a stable-version support window are not currently specified.

Relevant defects include accepted-but-wrong code within the supported subset,
memory corruption, invalid ELF bounds, unchecked writes, profile bypass,
forged-evidence admission and installation that overwrites unrelated files.
