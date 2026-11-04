# Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
# BearBasm standalone front door. Official binaries retain the Bear toolchain.
.DEFAULT_GOAL := sovereign
PYTHON ?= python3
BEYOND_ROOT ?=
CC ?= cc
PREFIX ?= /usr/local
DESTDIR ?=
DIST_DIR ?= dist

.PHONY: all sovereign sovereign-compat host check package package-host package-source install uninstall help
all: sovereign

sovereign:
	$(PYTHON) tools/build.py --lane sovereign --beyond-root "$(BEYOND_ROOT)"

sovereign-compat:
	$(PYTHON) tools/build.py --lane sovereign --beyond-root "$(BEYOND_ROOT)" --compat

host:
	$(PYTHON) tools/build.py --lane host --cc "$(CC)" --compat

check: host
	$(PYTHON) tools/check_standalone.py --basm build/host/basm --compat build/host/basm-compat --elftool build/host/elftool --output build/host/checks.json

package: sovereign
	$(PYTHON) tools/package.py --kind binary --build-dir build/sovereign --out-dir "$(DIST_DIR)"

package-host: host
	$(PYTHON) tools/package.py --kind binary --build-dir build/host --out-dir "$(DIST_DIR)"

package-source:
	$(PYTHON) tools/package.py --kind source --out-dir "$(DIST_DIR)"

install: sovereign
	$(PYTHON) tools/install.py --build-dir build/sovereign --prefix "$(PREFIX)" --destdir "$(DESTDIR)"

uninstall:
	$(PYTHON) tools/install.py --uninstall --prefix "$(PREFIX)" --destdir "$(DESTDIR)"

help:
	@printf '%s\n' \
	  'make BEYOND_ROOT=/path/to/Beyond_BDM  Official Bear/BearLinker/blibc build' \
	  'make host                           Explicit host diagnostic build' \
	  'make check                          Standalone host qualification' \
	  'make package BEYOND_ROOT=...         Linux x86-64 development binary tarball' \
	  'make package-source                 Source tarball from Git-tracked worktree files' \
	  'make install BEYOND_ROOT=... PREFIX="$$HOME/.local" [DESTDIR=...]' \
	  'make uninstall PREFIX="$$HOME/.local" [DESTDIR=...]'
