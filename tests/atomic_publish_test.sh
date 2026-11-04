#!/bin/sh
# INV-579: byte-valued RLIMIT_FSIZE, independent of shell ulimit units.
set -eu
ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
BASM=${BASM:-$ROOT/basm}
[ -x "$BASM" ] || { printf 'FAIL: missing basm: %s\n' "$BASM" >&2; exit 1; }
exec python3 "$ROOT/tests/atomic_publish_test.py" "$BASM"
