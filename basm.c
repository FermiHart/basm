/*
 * BearBasm production unity build.
 *
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The assembler remains one translation unit while its implementation is
 * partitioned by responsibility. The parity gate keeps the quarantined source
 * immutable and verifies registered modular deltas against legacy behavior.
 */

#include "modules/01_foundation.inc"
#include "modules/02_encoding.inc"
#include "modules/03_parser.inc"
#include "modules/04_writer.inc"
#include "modules/05_preprocessor.inc"
#include "modules/06_attestation.inc"
#include "modules/07_main.inc"
