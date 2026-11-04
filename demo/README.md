<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# A real Hello. A real object proof.

This demo assembles `hello.basm`, audits the ELF object, links it with GNU ld,
and executes `Hello from BearBasm!` on Linux x86-64. It then signs a v4 proof
of **`hello.o`**, verifies it with an externally provided demo public key,
changes one byte in that same object, observes rejection, restores the exact
original bytes, and verifies again.

The linked `hello` executable is **not** attested by the object proof.

## Reproduce

Run these commands from the repository root on Linux x86-64. The full demo
needs Python 3.10+, Basm, the companion `elftool` and GNU ld. The host build
also needs a C compiler, Make and Perl. Choose an output directory that does
not already exist:

```sh
make host
BASM="$PWD/build/host/basm" \
ELFTOOL="$PWD/build/host/elftool" \
  sh demo/run.sh --output-dir /tmp/basm-demo
```

The binary download provides the assembler; `make host` builds the inspection
companion used here. You can instead supply `BASM` and `ELFTOOL` as explicit
paths to existing executables. When both tools are on `PATH`, omit the two
environment assignments. The script
keeps `events.json`, unmodified stdout/stderr recordings, the source, proof,
linked executable, restored object and original object backup. Its two expected
failures return status 1: a changed object and an untrusted external key.

`demo.pub` and the deterministic seed in `demo.py` are public synthetic fixtures.
They do not establish a publisher identity and must never sign a release. The
public key is supplied before signing; the demo does not extract a trust anchor
from its own proof. The temporary seed file is removed when the run ends.

The capture also includes selected fields from an actual `--explain` JSON file.
It retains modeled/unmodeled coverage and `semantic_verification: unimplemented`.
These are assembly traces, not semantic or memory-safety proofs.

## References

[Build and installation](../docs/BUILD.md) · [Supported subset](../SUPPORTED-SUBSET.md) ·
[Testing](../docs/TESTING.md) · [Security scope](../SECURITY.md) ·
[BSD-3-Clause](../LICENSE).
