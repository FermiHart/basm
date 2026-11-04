# Output Publication Requalification

The assembler now exclusively creates sibling temporaries and publishes complete
objects with rename. Output is never opened/truncated through a guessed temp name.
This is atomic pathname visibility, not power-loss durability or an atomic
object-plus-proof transaction. See INV-579 and INV-583 in `Docs/INVARIANTS.md`.

## Campaign update: snapshots and explicit diagnostic gates

Dependency snapshots now close each input stream after its bytes are admitted.
The old fixture that expected 31 or 32 retained `incbin` streams to exhaust the
Bear FILE pool is therefore obsolete. The executable gate now requires 31, 32
and 64 **distinct** incbin files to assemble successfully with a child-only
`RLIMIT_NOFILE=16`, for ordinary, cold-cache and warm-cache publication. It checks
every output byte, requires the expected cache hit/miss, and rejects leaked owned
temporaries. This positive test runs on both the explicitly selected host binary
and the existing Bear product gate; `BASM_EXPECT_FILE_POOL` is no longer needed
to select or skip it.

Allocation-failure coverage remains deterministic. The host linker wrappers now
inject `ENOMEM` before `fopen` creates the main output temporary, the cold cache
object temporary, or the cold cache receipt temporary. The gate requires the
specific injection counter, preservation of the previous final object and
cleanup of owned temporaries. The receipt case also exercises cleanup after the
cache object temporary was successfully created. Wrong-output and wrong-cache
controls prove that a missed injection cannot silently pass. These wrappers test
the assembler's publication error paths; they do not qualify blibc's internal
FILE allocator or its ordering relative to `openat`.

The default fault gate still requires the external canonical
`../../crypto/ed25519.c` and header. It fails when these dependencies are absent;
it never substitutes bundled crypto automatically. A standalone diagnostic run
must opt in explicitly:

```sh
BASM=/absolute/path/to/basm-host sh tests/atomic_publish_test.sh
BASM_PUBLICATION_DIAGNOSTIC=1 BASM_PUBLICATION_KEEP=1 \
  sh tests/publication_fault_test.sh
BASM_PUBLICATION_DIAGNOSTIC=1 BASM_PUBLICATION_SANITIZE=1 \
  BASM_PUBLICATION_KEEP=1 sh tests/publication_fault_test.sh
```

The opt-in lane compiles a private source snapshot with the campaign's corrected
bundled Ed25519 implementation. It prints
`HOST_DIAGNOSTIC_CORRECTED_BUNDLED_CRYPTO_NOT_SOVEREIGN` and saves source hashes,
compiler arguments, binary identity, sanitizer configuration and case results in
`results.json` when artifacts are retained. It refuses source drift during the
build. `BASM_PUBLICATION_TMPDIR` optionally selects an existing parent directory;
otherwise normal temporary-directory selection applies. Neither host test hook
nor alternate crypto is added to the shipped product build.

Campaign validation passed all **49 deterministic fault cases** in both ordinary
and ASan+UBSan host builds, and all **eight executable publication methods** on
both the normal and instrumented candidate. The latter includes nine distinct
many-incbin scenarios. ASan and UBSan remain enabled; LeakSanitizer was disabled
because this environment prevents its `/proc` inspection under ptrace. These
results do not requalify the absent canonical crypto, Bear compiler/linker,
external blibc allocator gate, kernel boot, or durability after power loss.

The sections below retain the qualification record supplied with the project;
their binary identity and external build/boot results are historical evidence,
not claims about this standalone campaign.

## Reproduced Defects

- The old one-instruction RLIMIT fixture fit below Bash's 1024-byte `ulimit -f 1`
  but exceeded dash's 512-byte limit. Bash's red result was a test error.
- Pre-existing `.tmp.<pid>` files, symlinks and hardlinks could be truncated,
  renamed or removed without ownership. New CLI tests reproduced seven failures.
- After final rename, cold escrow reopened the shared output path. An interloper
  could replace A with B; a valid authenticated restore of A then returned B.
  A deterministic host fault injector reproduced this for ELF64 and flat bin.
- blibc opened/created a file before obtaining its FILE pool slot. Exhaustion
  could return ENOMEM while leaving a newly created temporary behind.
- The sovereign read/write shim returned raw negative Linux errors without errno,
  unlike the POSIX convention used by assembler retry loops.

## Implementation

`out_tmp_open()` retains the successfully acquired exclusive `w+bex` stream,
tries at most 32 candidate names and never removes unsuccessful candidates.
The main cleanup funnel is armed only after acquisition. Writers flush their
descriptor output; the caller checks close before the final rename. Signals may
leave an owned temporary, but may not expose a partial final object.

Escrow temporaries follow the same acquisition rule. Cold escrow copies from the
assembler's still-open output stream before exposing its shared final name. The
copy uses synchronized descriptor reads, matching the descriptor writer, rather
than depending on buffered reads from its unbuffered update stream. A failed
final rename can leave a valid cache entry: it cannot associate another job's
bytes with this job's key. Cache object and receipt remain separate renames.

blibc now reserves a FILE slot before `openat`, releasing it on syscall failure.
The minimal POSIX shim normalizes only Linux errors in [-4095,-1] to -1/errno;
EOF and successful byte counts do not clear errno. The raw syscall boundary is
unchanged. This does not claim repair of every blibc stdio behavior.

## Historical Gates

```sh
make -C toolchain/BearBasm test-atomic-publish
make -C toolchain/BearBasm test-publication-faults test-publication-faults-sanitize
make -C toolchain/BearBasm test-rel8-escrow test-runtime-io test-function-size
TMPDIR=/tmp/opencode sh tools/blibc-fopen-mode-gate.sh
```

- Eight CLI test methods exercise the actual Bear-linked binary, with a >128 KiB
  payload and a byte-valued 1024-byte limit. Both Bash and sh launchers passed.
- SIGXFSZ default/ignored/blocked, old/absent final, bounded collisions, symlinks,
  hardlinks, unowned cleanup, eight real concurrent writers, cache identity and
  31/32 retained incbin FILE-pool exhaustion are covered.
- The host injector passed 39 cases, including real partial prefixes, EINTR,
  ENOSPC, close/rename errors and the forced A/B replacement. ASan/UBSan passed;
  expected die-path arena leaks are outside that sanitizer check.
- Cache race tests wait for every child separately and verify a warm restore.
- Runtime shim tests passed 24 result cases and six retry loops with host- and
  Bear-compiled wrapper objects. The FILE-pool test requires zero open syscalls
  when capacity is exhausted.
- Function-size/named-relocation gates remain green (12 parity cases, 120
  rejection checks). The Tina hweight differential and kernel-boot gates passed.

## Historical Evidence And Limits

Private build/evidence root: `/tmp/opencode/basm-publication.jPYCTo`.
`before.tar` preserves the previous assembler, compiler and publication sources.
The product was Bear-compiled with the previously pinned compiler and linked
with BearLinker and the rebuilt Linux blibc archive. The archive's existing build
still uses its bootstrap toolchain; this is not full toolchain sovereignty.

The scoped product SHA-256 after the fixes:

```text
e5e679a0b7f005986fe3073f700d062b0fb29142f99c736dfaf312f1f35dc028
```

Full Beyond `make gate` did not complete: one attempt exceeded 720 seconds;
a bounded repeat reached trap-semantics preflight and expired at 180 seconds.
Its output is `full-gate.log` in the evidence directory. No boot-green or full
Beyond qualification is claimed and MAX_FAILS was not raised. The independent
binary-size budget remains red and is not bypassed by these changes.

Out-of-scope: hostile parent-directory replacement / arbitrary same-UID writers,
fsync durability, object/proof pair transactions and guaranteed cleanup after
SIGKILL or other asynchronous process death. No new signal handlers attempt to
undo a completed publication. No commit was created.
