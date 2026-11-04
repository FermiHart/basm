<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Changelog

## Unreleased

- Publish the existing English presentation and original films through GitHub
  Pages, staging only curated media and notices while checking the reviewed
  development archive checksums without repackaging them.
- Separate the author name and contact address into clearly spaced footer
  blocks; retain the original media, source contracts and per-file licenses.

## 0.1.0-dev.1 — 2026-11-04

Initial standalone development distribution for Linux x86-64. Source-language,
CLI and evidence-format compatibility may evolve during development.

### Assembly and inspection

- A NASM-syntax subset with ELF64 relocatable and flat binary output, explicit
  public and Beyond compatibility profiles, and a bounded preprocessor.
- Instruction and form inventories, structured diagnostics, assembly traces
  and a partial control-flow graph for the modeled forms.
- NASM-compatible data-string padding and supported escapes; explicit refusal
  of conflicting canonical section attributes and writable/executable sections.
- Complete preservation of admitted 255-byte names across symbols, defines,
  macros, structures and relocation-section names.
- Strict singleton CLI options, argument-aware diagnostics selection and
  checked writes for help, version and inventory output.

### Integrity evidence

- Optional object/source attestations, including v4 consumed-input records.
- Ed25519 signatures and verification against an externally supplied public key.
- A separate `elftool` utility for ELF inspection, normalized comparisons and
  attestation verification. Hash and signature checks do not establish program
  semantics, linked-executable provenance or runtime containment.

### Distribution

- Sovereign builds with Bear, BearLinker and blibc, plus an explicit host
  diagnostic lane for contributors.
- Versioned development archives, manifests and checksums; deterministic
  packaging for identical payloads and metadata.
- Optional installation with ownership checks, upgrade recovery and removal
  that preserves unrelated files.
- BSD-3-Clause as the primary license, with the preserved Unlicense,
  TweetNaCl public-domain and external SPL contexts recorded in `NOTICE`
  and the per-file license map.
