#!/usr/bin/env python3
# Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Display selected fields from a real --explain JSON file."""
import json
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text())
print('Assembly trace: selected fields from --explain')
for name in ('schema', 'coverage', 'effect_scope', 'byte_scope', 'semantic_verification'):
    if name in document:
        value = document[name]
        if name == 'coverage':
            print('coverage: ' + str(value['instructions']) + ' instructions')
            for field in ('modeled', 'unmodeled', 'schema_forms'):
                print('  ' + field + ': ' + str(value[field]))
        else:
            print(name + ': ' + (json.dumps(value, separators=(',', ':'))
                                if isinstance(value, (dict, list)) else str(value)))
