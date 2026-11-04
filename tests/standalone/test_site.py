#!/usr/bin/env python3
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause

"""Static presentation checks, not assembler or sovereign-lane qualification."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SiteBuild(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='basm-site-test-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def build(self, target, root=ROOT):
        return subprocess.run([sys.executable, str(root/'tools/site.py'), '--output', str(target)],
                              capture_output=True, text=True, timeout=30)

    def test_public_media_and_licenses_only(self):
        target = self.work/'site'
        result = self.build(target)
        self.assertEqual(result.returncode, 0, result.stderr)
        files = [p for p in target.rglob('*') if p.is_file()]
        self.assertEqual(len(files), 14)
        self.assertEqual((target/'LICENSE').read_bytes(), (ROOT/'LICENSE').read_bytes())
        for path in files:
            if path.name != 'index.html':
                self.assertEqual(path.read_bytes(), (ROOT/path.relative_to(target)).read_bytes())
            self.assertFalse(path.name.endswith(('.tar.gz', '.seed', '.o', '.log', '.json')))

    def test_nonempty_output_is_preserved(self):
        target = self.work/'existing'
        target.mkdir()
        (target/'keep').write_bytes(b'owned by the user')
        result = self.build(target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('existing files are never removed', result.stderr)
        self.assertEqual((target/'keep').read_bytes(), b'owned by the user')
        self.assertEqual(list(target.iterdir()), [target/'keep'])

    def test_doc_links_go_to_source_without_copying_the_repository(self):
        target = self.work/'site'
        result = self.build(target)
        self.assertEqual(result.returncode, 0, result.stderr)
        page = (target/'index.html').read_text()
        self.assertIn('https://github.com/FermiHart/basm/blob/main/docs/BUILD.md', page)
        self.assertNotIn('href="docs/BUILD.md"', page)
        self.assertIn('href="readme/LICENSE.media.txt"', page)
        self.assertFalse((target/'docs').exists())
        self.assertFalse((target/'downloads').exists())

    def test_bad_archive_checksum_is_refused_before_output(self):
        fixture = self.work/'fixture'
        (fixture/'tools').mkdir(parents=True)
        for name in ('site.py', 'package.py'):
            shutil.copy2(ROOT/'tools'/name, fixture/'tools'/name)
        version = (ROOT/'VERSION').read_text().strip()
        (fixture/'VERSION').write_text(version+'\n')
        downloads = fixture/'downloads'/version
        downloads.mkdir(parents=True)
        for suffix in ('linux-x86_64', 'linux-x86_64-host-diagnostic', 'source'):
            path = downloads/f'bear-basm-{version}-{suffix}.tar.gz'
            path.write_bytes(b'checksum-test fixture, not a release archive')
            Path(str(path)+'.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
        path.write_bytes(b'modified fixture')
        target = self.work/'refused'
        result = self.build(target, fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('archive checksum mismatch', result.stderr)
        self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
