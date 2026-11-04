<!-- Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com> -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Measurement protocol

`benchmark.pl` measures existing trusted assemblers on Linux x86-64. It uses
`inventory-v1.json` and produces `BASM-IC02-MEASUREMENT-v1` receipts. The runner
builds no tool, links no object, signs no proof and executes no assembled code.
See [the laboratory guide](README.md) for its required Beyond source tree.

## Run a comparison

Supply explicit executables and a new output directory:

```sh
perl lab/benchmark.pl --repo-root /path/to/Beyond_BDM \
  --baseline /path/to/basm-before --baseline-profile public \
  --candidate /path/to/basm-after --candidate-profile public \
  --baseline-lane bear-blibc --candidate-lane bear-blibc \
  --output-dir /path/to/new-measurement
```

The candidate is optional. Profiles are `compat` (no target selector), `public`
and `beyond`; lane labels are caller declarations. Supply host Perl, `readelf`,
`nm` and `objdump`; inspector paths can be selected explicitly. Do not rebuild
or replace any supplied executable while the run is in progress.

## Fixed experiment

Each of the three pinned assembly fixtures is used in two modes: bare ELF64
assembly and assembly with unsigned `--emit-attestation`. The latter expects
v2 for `compat` and v3 for explicit profiles. It does not measure
`--emit-attestation-v4`, signing or independent cryptographic verification.

By default, each case has three warmup pairs and fifteen measured pairs, with
alternating AB/BA order. Allowed bounds are 1–3 warmups and 5–15 measured rounds.
Warmup observations are retained and excluded from statistics. There is no
automatic retry to obtain a favorable result.

`CLOCK_MONOTONIC` measures fork/exec/wait latency, including process startup,
assembly and output writes. Inspectors, hashes and comparisons run outside the
timed interval. This is a page-cache-warm experiment with fresh processes and
no Basm cache. CPU affinity, frequency and other machine load are not controlled.

Both lanes receive the same absolute source path, including `STT_FILE`, and
stable lane-specific output paths. Every object must be byte-identical across
lanes and across validation, warmups and samples. Outputs are removed before
each invocation so a successful no-op cannot reuse a previous result. `readelf`
checks ELF64/x86-64/REL, expected globals and source-file metadata.

Unsigned proof fields must match the actual tool/source/output hashes, paths,
format, profile where applicable, epoch zero and unsigned state. Proof bytes
must repeat within a lane; they need not match across different executables or
profiles. A comparison between different profiles measures those complete
configurations, not an isolated change.

## Statistics and outcomes

The receipt contains per-lane medians, absolute and relative median absolute
deviation (MAD), and the median of the paired baseline/candidate ratios. This
ratio is not computed by dividing the two independent medians.

`STABLE` requires relative MAD at most 0.25 for each lane and, with a candidate,
for the paired ratios. Otherwise the result is `INCONCLUSIVE`. A single-tool
run has no paired ratio. Stability does not establish statistical significance,
a minimum speedup or suitability for release.

| Exit | Meaning |
|---|---|
| `0` | Stable measurement within the runner's checks |
| `2` | Inconclusive dispersion |
| `1` | Refusal or execution error |

Source, corpus, tool and selected object identities are checked before and
after the run. Drift refuses the result. Once execution has begun, logs and
failure receipts remain in the output directory; preflight errors refuse before
running supplied tools or creating that directory.

## Executable snapshots and replay limits

Before tool execution, the runner copies baseline and optional candidate bytes
to independent owner-read/execute-only files in the output directory. These
copies must match the frozen executable lengths and SHA-256 identities. Copying
is bounded by the frozen size and aggregate deadline, and the copies are
rehashed before acceptance.

The receipt's `executable_snapshots` records each role:

| Field | Meaning |
|---|---|
| `purpose` | `EVIDENCE_ONLY_NOT_EXECUTED` |
| `original` | Frozen original identity, also recorded in `inputs_before` |
| `snapshot_before` | Identity verified before tool execution |
| `snapshot_after` | Identity rechecked before acceptance |
| `status` | `COPIED_SHA256_VERIFIED`, then `UNCHANGED` after the final check |

Measured commands still use the original executable paths. Snapshots retain
bytes; they do not establish dynamic-loader closure, reproduce a source tree
or guarantee the same future timings. Files remain mutable by their owner.
A receipt without `executable_snapshots` makes no retention claim. Replaying
such a result requires independently available bytes matching its recorded
hashes; current binaries cannot stand in for missing originals.

## Optional linkage inspection

`--review-linkage` inspects existing host Bear objects/executable, the selected
Basm objects/executables, `build/bear/sign.o` and the blibc archive in the supplied
Beyond tree. It needs `--baseline-object`, plus `--candidate-object` when a
candidate is present. No compiler or linker is invoked.

The three consumers are Bear NUL scans, Basm name lookup and software SHA.
`nm`, `readelf` and selected `objdump` commands and output are retained. When a
final executable lacks local symbol names, a public anchor locates a candidate
text window. All bytes except supported relocation fields must match before
that window is reported as `RELOCATION_MASKED_TEXT_MATCH`.

That result does not verify relocation values, authenticate the build or trace
dynamic calls. Import sites do not identify a runtime IFUNC implementation.
Unsigned assembly latency does not measure the hash kernel or signing workload.

## Enforced limits and test scope

Each subprocess is limited to at most 10 seconds; the aggregate execution
budget after preflight is at most 60 seconds, including snapshots, validation
and inspection. Six cases with two tools, maximum rounds and warmups produce
228 assembler invocations including validation. These are measurement limits,
not the inventory's proposed analysis/search budgets.

Commands use direct argument vectors and a minimal child environment with
epoch zero. Process-group deadlines handle ordinary descendants. There is no
RSS/address-space enforcement, network restriction or hostile-child containment.
Only run trusted executables. Cold-cache behavior, auxiliary RSS, complete
package size and optimization-search impact remain outside this experiment.

The integration tests in `tests/lab_benchmark_test.sh` cover bounds, literal
paths, child failures/timeouts, stale or changed output, proof-field drift,
snapshot independence and statistics. `LAB_STUB_ONLY=1` skips current-assembler
execution but still needs the Beyond source layout; `LAB_REVIEW=1` requires
existing linkage artifacts. These test modes and their results must be recorded
separately from a measured comparison or Beyond boot test.
