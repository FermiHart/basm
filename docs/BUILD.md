<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Build, package and install Basm

The binary distribution targets **Linux x86-64**. The public assembler uses a
fixed 64-bit encoding mode and emits ELF64 relocatable objects or flat binaries.
The output format is separate from the operating system hosting the assembler.

## Choose a build lane

| Lane | Command | Dependencies |
|---|---|---|
| Sovereign | `make BEYOND_ROOT=/path/to/Beyond_BDM` | Existing Bear, BearLinker, blibc and bootstrap Basm |
| Host diagnostic | `make host` | Host C compiler, system headers and libc |
| Standalone checks | `make check` | Host lane plus Git, NASM and an ELF linker for the Linux example |

Build orchestration requires Python 3.10 or later, Perl and Make. The assembled
program and the Basm executable do not require those build tools to run.
Dependencies are supplied explicitly; a build performs no automatic download
or privileged installation.

### Sovereign build

```sh
make BEYOND_ROOT=/path/to/Beyond_BDM
build/sovereign/basm --version
build/sovereign/basm --capabilities
```

The selected Beyond checkout must contain executable `toolchain/bear/bear`,
`BearLinker/bear-ld-host`, `toolchain/BearBasm/basm` as a bootstrap seed, and
`surfaces/blibc/build/libblibc.a`. The linker script, runtime startup source,
shim and blibc headers also come from that checkout. Basm's active assembler
and canonical `crypto/ed25519.c/h` sources are local to this repository.

The builder snapshots the selected source/toolchain inputs, checks generated
ISA files, requires fresh nonempty compiler/linker outputs, checks the public
profile and refuses detected input drift. Identities and commands are recorded
in `build/sovereign/build-receipt.json`; attempt logs and snapshots remain under
`build/sovereign/runs/`. Missing sovereign inputs cause an error, with no host
compiler fallback. This operation identifies existing tools; it does not rebuild
the complete compiler bootstrap or qualify Beyond guest execution.

### Host diagnostic and compatibility builds

```sh
make host
# Select a particular host compiler:
make host CC=clang
build/host/basm --version
```

This lane produces the public `basm`, a separate `basm-compat`, `elftool` and
crypto test utilities. Receipts and packages identify the lane as
`host-diagnostic`. System headers and libc are not authenticated by that
receipt. Global flags do not assume SHA-NI or the build machine's native ISA.

To also build a separate compatibility binary with the sovereign toolchain:

```sh
make sovereign-compat BEYOND_ROOT=/path/to/Beyond_BDM
```

`basm-compat` serves existing compatibility and Beyond integration callers. It
does not replace the public `basm` in a binary distribution. See
[TESTING.md](TESTING.md) for the checks and their integration boundaries.

## Development archives

```sh
make package BEYOND_ROOT=/path/to/Beyond_BDM
make package-source
# Optional host diagnostic archive:
make package-host
```

The output directory is `dist/`, configurable with `DIST_DIR=/chosen/path`.
Source archives use allowlisted Git-tracked worktree files; stage intended
files explicitly before packaging. Untracked files are excluded, and the
manifest records tracked changes relative to the Git commit. A binary package
refuses an assembler or source that no longer matches its build receipt.

Published development archives and their checksums are kept under
`downloads/0.1.0-dev.1/`. These reviewed deliverables are distinct from working
build outputs. Packaging excludes the archives themselves from source payloads
to avoid recursively packaging prior distributions.

Each archive contains `MANIFEST.json` and `SHA256SUMS`, with a sibling
`.tar.gz.sha256` file. Tar order, ownership, modes and timestamps are normalized.
Set `SOURCE_DATE_EPOCH` explicitly when desired; the default is zero. Identical
payloads and metadata produce identical archives. That is separate from
reproducibility across independent compiler builds.

These are **unsigned development packages**. Checksums establish byte identity
when obtained through a trusted path; they do not supply a publisher signing
identity or a stable-version guarantee. The binary payload installs `basm`.
Build `elftool` through the host lane for explicit diagnostic use.

## Run without installation

Extract a binary archive, verify its checksums, and run from that directory:

```sh
sha256sum -c SHA256SUMS
./bin/basm --help
./bin/basm -f elf64 -o hello.o examples/hello_linux_x86_64.basm
ld -o hello hello.o
./hello
```

The example uses an ELF64 linker and a Linux x86-64 runtime. Assembly, linking
and execution are separate steps. Use the assembler directly when no system
installation is needed.

## Optional installation

From an extracted sovereign binary archive:

```sh
python3 install.py --prefix "$HOME/.local"
```

From a source checkout:

```sh
make install BEYOND_ROOT=/path/to/Beyond_BDM PREFIX="$HOME/.local"
# Stage files without writing into /usr/local:
make install BEYOND_ROOT=/path/to/Beyond_BDM PREFIX=/usr/local DESTDIR="$PWD/stage"
```

The Python 3.10+ installer accepts the sovereign lane. It installs the executable,
licenses, examples, documentation and an ownership manifest. It refuses symlinks,
unrelated destination files and modified files from a previous installation.
A prefix lock serializes changes. Temporary files, same-directory backup links
and a recovery journal support rollback on ordinary write errors and recovery
of an interrupted upgrade on the next invocation. This is not filesystem-wide
power-loss atomicity. The installer does not change shell startup files or `PATH`.

To remove an installation with its retained installer:

```sh
python3 "$HOME/.local/share/bear-basm/install.py" --uninstall --prefix "$HOME/.local"
```

`make uninstall PREFIX=... DESTDIR=...` is also available from source. Removal
checks owned-file hashes, refuses locally modified replacements and leaves
shared directories intact.

## Other platforms

Linux x86-64 is the current binary lane. Source adaptations for macOS do not
constitute a qualified macOS distribution. Native Windows requires a deliberate
POSIX/runtime port; emitting ELF does not make an executable loadable by Windows.
