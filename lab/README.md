<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Evidence and measurement laboratory

These optional tools inspect supplied executables, artifacts and a pinned
Beyond source corpus. They are separate from `make check` and from the
assembler's attestation verifier.

| Tool | Operation | Result |
|---|---|---|
| `evidence.pl` | Hashes existing inputs without executing tools | `BASM-IC02-EVIDENCE-v1`, identity only |
| `benchmark.pl` | Runs trusted assemblers and host inspectors under bounded deadlines | `BASM-IC02-MEASUREMENT-v1`, measured observations |

The schema names are retained for compatibility. The
[measurement protocol](MEASUREMENT.md) defines the experiment, statistics,
retained executable snapshots and refusal behavior.

## Required integration inputs

`inventory-v1.json` selects three consumers: Bear source NUL scans, Basm name
lookup and software SHA. Its paths, source anchors and corpus hashes belong to
a Beyond checkout. They do not describe a self-contained standalone corpus.
The three assembly fixtures cover the Linux runtime, the Beyond syscall door
and a UEFI ABI bridge; their different execution domains are recorded, and the
laboratory assembles them without running the resulting instructions.

From this standalone repository, always supply `--repo-root /path/to/Beyond_BDM`.
The external tree must contain every selected source-evidence file, including
the documentation anchors listed in the inventory. Default path inference
assumes Basm is embedded in Beyond. Missing inputs or changed pins cause refusal;
never refresh a checksum simply to make a measurement proceed.

The inventory describes caller/provider candidates and build-rule paths. Those
records do not prove that an object exists, was freshly built or resolves to a
particular runtime implementation. Source anchors check textual identity, not
C semantics or dynamic reachability. Its proposed analysis/search budgets are
metadata, not enforced authorization or demonstrated performance.

## Collect identities

With existing nonempty artifacts and a readable executable:

```sh
perl lab/evidence.pl --repo-root /path/to/Beyond_BDM \
  --basm /path/to/basm \
  --artifact runtime-start=/path/to/runtime-start.o \
  --lane bear-blibc > evidence.json
```

`--artifact ID=PATH` and `--tool ID=PATH` are repeatable. Artifact IDs, lane and
build flags are caller declarations. The collector records SHA-256, length and
paths for tools, artifacts, source evidence, corpus, inventory and collector,
plus the Perl/module identities. It launches no subprocess, including version
queries, and performs no timing, signing or candidate execution.

The workload content ID is independent of the checkout location. The full
manifest binds paths as well as bytes and declarations, so relocating inputs
can change that manifest. Missing files, empty artifacts, duplicate IDs,
nonexecutable tools and source/corpus drift fail before JSON is emitted.
Stat/hash checks detect ordinary concurrent changes; they do not establish a
hostile-filesystem snapshot or complete runtime dependency closure.

## Integration tests

`tests/lab_test.sh` and `tests/lab_benchmark_test.sh` retain the embedded Beyond
layout assumption. Run them only in an explicitly prepared integration tree,
from its `toolchain/BearBasm` directory, with the required corpus and tools:

```sh
BASM=/absolute/path/to/basm-compat LAB_KEEP=1 sh tests/lab_test.sh
LAB_KEEP=1 LAB_STUB_ONLY=1 sh tests/lab_benchmark_test.sh
```

The collector test assembles the pinned corpus serially and retains objects,
unsigned proofs, exact commands and diagnostic logs when `LAB_KEEP=1`. It does
not link or execute the emitted objects. Negative cases use private copies.

`LAB_STUB_ONLY=1` exercises measurement helpers and refusal cases without
accessing or executing the current assembler. It still needs the integration
source layout. The full benchmark test runs trusted tools; `LAB_REVIEW=1` also
requires existing objects for linkage inspection. An unavailable dependency
is not a passing test.

## Interpretation limits

An identity receipt is not a performance result. A stable timing distribution
is not a correctness proof, an isolated optimization effect or statistical
significance. The fixed assembly corpus does not measure Bear C preprocessing,
secret equality, a hash kernel or signed-attestation throughput. Boot behavior,
RSS, cold-cache behavior and complete package size require separate evidence.
