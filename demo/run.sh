#!/bin/sh
# Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
# Run from any directory. BASM and ELFTOOL may name explicit executables.
set -eu
demo_source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$demo_source_dir/demo.py" "$@"
