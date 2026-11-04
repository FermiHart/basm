<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Basm development downloads

**0.1.0-dev.1** is a development candidate for **Linux x86-64**.

| Package | Download |
|---|---|
| Sovereign public assembler | [Binary archive](https://github.com/FermiHart/basm/raw/refs/heads/main/downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-linux-x86_64.tar.gz) · [SHA-256](https://github.com/FermiHart/basm/raw/refs/heads/main/downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-linux-x86_64.tar.gz.sha256) |
| Source distribution | [Source archive](https://github.com/FermiHart/basm/raw/refs/heads/main/downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-source.tar.gz) |
| Explicit host diagnostic build | [Host archive](https://github.com/FermiHart/basm/raw/refs/heads/main/downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-linux-x86_64-host-diagnostic.tar.gz) |

## Run the assembler directly

Place the binary archive and its checksum in the same directory:

```sh
sha256sum -c bear-basm-0.1.0-dev.1-linux-x86_64.tar.gz.sha256
tar -xzf bear-basm-0.1.0-dev.1-linux-x86_64.tar.gz
cd bear-basm-0.1.0-dev.1-linux-x86_64
./bin/basm --help
./bin/basm -f elf64 -o hello.o examples/hello_linux_x86_64.basm
```

The assembler binary needs no Python, Perl, Make, C compiler or Bear toolchain.
The Linux example can be linked and run with `ld -o hello hello.o` and `./hello`.
Linking needs the corresponding Linux ELF linker.

The extracted archive contains `MANIFEST.json` and `SHA256SUMS`. Run
`sha256sum -c SHA256SUMS` from its root to check the listed files. These hashes
are **unsigned integrity records**; agreement with a supplied checksum does
not authenticate the publisher. These links point to files on the `main`
branch, not to an immutable signed release.

## Optional installation

From the extracted sovereign package, using Python 3.10 or later:

```sh
python3 install.py --prefix "$HOME/.local"
"$HOME/.local/bin/basm" --version
```

The installer preserves unrelated files and does not modify `PATH`. The host
diagnostic archive runs in place; it is not accepted by the sovereign installer.
See [build and installation](../docs/BUILD.md) for staging, upgrades and removal.

## Inspection, demonstration and source builds

From a source checkout or the extracted source archive, `make host` builds
`build/host/basm` and `build/host/elftool`. This needs a C compiler, Make,
Python 3.10+ and Perl. The [full demonstration](../demo/README.md) additionally
uses GNU ld; its inspection and verification steps use the companion `elftool`.
The binary archive itself distributes the assembler.

To create packages from a source checkout, use `make package-source` or
`make package-host`. An official sovereign package uses
`make package BEYOND_ROOT=/path/to/Beyond_BDM` with that existing toolchain.
See the [build guide](../docs/BUILD.md) for the complete prerequisites.

[Supported subset](../SUPPORTED-SUBSET.md) · [Testing](../docs/TESTING.md) ·
[Security](../SECURITY.md) · [BSD-3-Clause](../LICENSE) · [Notices](../NOTICE) ·
[Per-file licensing](../REUSE.toml).
