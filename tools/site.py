#!/usr/bin/env python3
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause

"""Stage the existing Basm presentation without publishing tools, keys or archives."""
from __future__ import annotations
import argparse
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import runpy
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MEDIA = ('hero-basm.svg', 'hero-basm-mobile.svg', 'hero-basm.png',
         'basm-in-action.gif', 'basm-in-action-mobile.gif',
         'basm-in-action.mp4', 'basm-in-action-mobile.mp4',
         'basm-poster.png', 'basm-poster-mobile.png', 'LICENSE.media.txt')
LEGAL = ('LICENSE', 'NOTICE', 'REUSE.toml')
SOURCE_URL = 'https://github.com/FermiHart/basm/blob/main/'


def package_checks():
    contract = runpy.run_path(str(ROOT/'tools/package.py'))
    read_regular = contract['read_regular']
    version = contract['read_version'](ROOT)
    archives = sorted((ROOT/'downloads'/version).glob('*.tar.gz'))
    expected = {f'bear-basm-{version}-{suffix}.tar.gz' for suffix in
                ('linux-x86_64', 'linux-x86_64-host-diagnostic', 'source')}
    if {path.name for path in archives} != expected:
        raise ValueError('expected the three reviewed development archives')
    for path in archives:
        checksum = read_regular(Path(str(path)+'.sha256')).decode().split()
        if len(checksum) != 2 or checksum[1].lstrip('*') != path.name:
            raise ValueError('invalid archive checksum record: '+path.name)
        if hashlib.sha256(read_regular(path)).hexdigest() != checksum[0]:
            raise ValueError('archive checksum mismatch: '+path.name)
    return read_regular


class Resources(HTMLParser):
    def __init__(self, root: Path):
        super().__init__()
        self.root = root
        self.english = False
        self.videos = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag == 'html':
            self.english = data.get('lang') == 'en'
        if tag == 'video':
            self.videos += 1
            if 'controls' not in data or 'autoplay' in data:
                raise ValueError('the films need user controls and must not autoplay')
        for key in ('href', 'src', 'srcset', 'poster'):
            value = data.get(key, '')
            if not value or value.startswith(('https:', 'mailto:', 'data:', '#')):
                continue
            target = (self.root/urlsplit(value).path).resolve()
            if not target.is_relative_to(self.root) or not target.is_file():
                raise ValueError('missing or out-of-scope local resource: '+value)


def build(output: Path) -> None:
    read_regular = package_checks()
    files = {name: ROOT/name for name in LEGAL}
    files.update({'readme/'+name: ROOT/'readme'/name for name in MEDIA})
    payloads = {name: read_regular(path) for name, path in files.items()}
    original = read_regular(ROOT/'index.html').decode('utf-8')
    # Preserve local media and licensing links; documentation uses GitHub's renderer.
    def hyperlink(match: re.Match) -> str:
        value = match[1]
        if value.startswith(('https:', 'mailto:', 'data:', '#')) or value in files:
            return match[0]
        parsed = urlsplit(value)
        source = (ROOT/parsed.path).resolve()
        if not source.is_relative_to(ROOT) or not source.is_file():
            raise ValueError('unknown presentation link: '+value)
        url = SOURCE_URL+quote(str(source.relative_to(ROOT)))
        if parsed.fragment:
            url += '#'+parsed.fragment
        return 'href="'+url+'"'
    page = re.sub(r'href="([^"]+)"', hyperlink, original)
    output = output.expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('output directory must be new or empty; existing files are never removed')
    output.mkdir(parents=True, exist_ok=True)
    for name, data in payloads.items():
        destination = output/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o644)
    (output/'index.html').write_text(page, encoding='utf-8')
    (output/'index.html').chmod(0o644)
    checker = Resources(output)
    checker.feed(page)
    if not checker.english or checker.videos != 2:
        raise ValueError('expected the English presentation and both controlled films')
    actual = {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
    if actual != set(files)|{'index.html'}:
        raise ValueError('unexpected static artifact members')
    size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
    if size > 8*1024*1024:
        raise ValueError('unexpected site payload size')
    print(f'PASS: {len(actual)} public site files, {size:,} bytes; reviewed archive hashes match.')
    print('Media and archives are unchanged; archives, tools and private inputs are not copied into the site.')
    print('Static site:', output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.output)
    except (ValueError, OSError) as error:
        parser.exit(1, f'site build refused: {error}\n')


if __name__ == '__main__':
    main()
