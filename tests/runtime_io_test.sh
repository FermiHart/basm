#!/bin/sh
# INV-579/INV-583: narrow source tests, no libc archive or canonical basm rebuild.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
BL="$ROOT/surfaces/blibc"
CC=${HOST_CC:-cc}
BEAR=${BEAR:-$ROOT/toolchain/bear/bear}
WORK=$(mktemp -d "${TMPDIR:-/tmp/opencode}/basm-runtime-io.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

# Explicit Bear errno header, without replacing the host's other libc headers.
"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$BL" -idirafter "$BL/include" \
    -c "$ROOT/toolchain/BearBasm/tests/runtime_io_test.c" -o "$WORK/test.o"
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -Wno-comment -DBEAR_NOTLS \
    -DBEAR_NO_LOCAL_EXEC_TLS -I"$BL" -idirafter "$BL/include" \
    "$WORK/test.o" \
    "$ROOT/BearLinker/sovereign-shims/posix_minimal.c" \
    "$BL/core/errno/errno.c" -o "$WORK/runtime-io-host"
"$WORK/runtime-io-host"

if [ -x "$BEAR" ]; then
    ulimit -s 65536 2>/dev/null || true
    # Same include roots and BEAR_NOTLS as BearBasm's sovereign shim target.
    for source in BearLinker/sovereign-shims/posix_minimal.c \
                  surfaces/blibc/core/errno/errno.c; do
        obj="$WORK/$(basename "$source" .c).o"
        "$BEAR" -c "$ROOT/$source" -o "$obj" -DBEAR_NOTLS \
            -DBEAR_NO_LOCAL_EXEC_TLS -I"$ROOT/toolchain/BearBasm" \
            -I"$BL/include" -I"$BL" -I"$BL/posix/include" -I"$ROOT"
        test -s "$obj"
    done
    # Only the test runner/printf uses the host runtime; wrappers and errno
    # storage above are freshly Bear-compiled, without any archive dependency.
    "$CC" -no-pie "$WORK/test.o" "$WORK/posix_minimal.o" \
        "$WORK/errno.o" -o "$WORK/runtime-io-bear"
    "$WORK/runtime-io-bear"
else
    printf '%s\n' 'SKIP Bear runtime-io lane: compiler unavailable'
fi
