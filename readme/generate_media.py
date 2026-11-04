#!/usr/bin/env python3
# Copyright (c) 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Render the Basm product film from captured command output.

Dependencies: Python 3, Pillow, FFmpeg (including libx264), DejaVu Sans Mono.
No network, generated log lines, or third-party rendering scripts are used.

The native basm-presentation-capture-v1 schema (demo.py's events.json) is
accepted and validated against its base64 stdout/stderr and single-byte checks.
A normalized capture may also use this format:
  {"scenes": [{"id": "build|verify|tamper|restore", "events": [
    {"command": "exact command", "stdout": "...", "stderr": "...",
     "exit_code": 0}
  ]}]}

The four scenes must contain real, ordered events. stdout/stderr are rendered
verbatim with visual line wrapping. Shell prompts, labels, chapter headings,
and exit badges are editorial UI; they are never inserted into captured logs.
Timing is deliberately edited. A non-zero event is required in the tamper
scene, and every other event must succeed. The capture producer remains
responsible for proving the one-byte change and restore operation.

Example from the presentation directory:
  python3 readme/generate_media.py --capture demo/media-session.json --out readme

Output: 1280x960 desktop and 720x900 mobile video, GIF, and poster PNG.
Both MP4s are silent H.264/yuv420p with faststart. The mobile MP4 reuses the
lossless portrait frames at 8 fps. Each GIF is constrained to 8 MiB; its
palette is reduced if necessary.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageFilter, ImageFont

COLORS = {
    'bg': '#070a12', 'surface': '#0d1220', 'ivory': '#f5f1df',
    'teal': '#65fbd2', 'gold': '#ffcc66', 'violet': '#a4afff',
    'muted': '#8794b8', 'line': '#27334b', 'red': '#ff7e8d',
}
BRAND = 'FermiHart / Basm'
CAPTION = 'Real command output. Timing edited for readability.'
CLAIM = 'Synthetic demo key · object evidence · no runtime-safety claim'
FPS = 24
DURATION = 46.0
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def rgb(value):
    return tuple(int(value[i:i + 2], 16) for i in (1, 3, 5))


def mix(a, b, t):
    return tuple(round(x + (y - x) * max(0.0, min(1.0, t))) for x, y in zip(rgb(a) if isinstance(a, str) else a, rgb(b) if isinstance(b, str) else b))


def smooth(t):
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)


def clean(text):
    """Interpret ANSI color as presentation, preserving printable capture text."""
    if not isinstance(text, str):
        raise ValueError('Capture stdout, stderr, and commands must be strings')
    text = ANSI.sub('', text).replace('\r\n', '\n')
    if any(ord(c) < 32 and c not in '\n\t' for c in text):
        raise ValueError('Unsupported terminal control character in capture')
    return text


@dataclass
class Event:
    command: str
    stdout: str
    stderr: str
    exit_code: int

    @classmethod
    def read(cls, raw):
        required = {'command', 'stdout', 'stderr', 'exit_code'}
        if not required.issubset(raw):
            raise ValueError(f'Missing event fields: {sorted(required - raw.keys())}')
        if isinstance(raw['exit_code'], bool) or not isinstance(raw['exit_code'], int):
            raise ValueError('exit_code must be an integer')
        command = clean(raw['command'])
        if not command.strip():
            raise ValueError('Empty captured command')
        return cls(command, clean(raw['stdout']), clean(raw['stderr']), raw['exit_code'])


SCENE_META = [
    ('build', 3.0, 14.0, '01', 'BUILD / RUN', 'Small source.', 'Real machine code.', 'teal'),
    ('verify', 14.0, 25.0, '02', 'SIGN / VERIFY', 'Attach evidence.', 'Verify the object.', 'violet'),
    ('tamper', 25.0, 35.5, '03', 'CHANGE ONE BYTE', 'One byte.', 'A different verdict.', 'gold'),
    ('restore', 35.5, 42.5, '04', 'RESTORE / VERIFY', 'Restore the bytes.', 'Verify again.', 'teal'),
]


def load_capture(path):
    raw = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(raw, dict):
        raise ValueError('Capture must be a JSON object')
    if raw.get('schema') == 'basm-presentation-capture-v1':
        if raw.get('status') != 'COMPLETE':
            raise ValueError('Capture is not complete')
        checks = raw['checks']
        mutation = checks['tampering']
        if mutation['changed_bytes'] != 1 or not mutation['same_inode']:
            raise ValueError('Capture does not prove a single-byte change in the same object')
        if not checks['restored_exact_bytes_same_inode'] or not checks['proof_output_path_is_object']:
            raise ValueError('Capture does not prove object restoration and evidence scope')
        records = {event['id']: event for event in raw['events']}
        groups = {
            'build': ['version', 'assemble', 'audit-object', 'link', 'run-hello'],
            'verify': ['sign-object', 'verify-original'],
            'tamper': ['flip-one-byte', 'verify-modified'],
            'restore': ['restore-original', 'verify-restored'],
        }
        scenes = {}
        for name, ids in groups.items():
            scenes[name] = []
            for identity in ids:
                event = records[identity]
                if event['returncode'] != event['expected_returncode']:
                    raise ValueError('Unexpected captured return code: ' + identity)
                for stream in ('stdout', 'stderr'):
                    original = base64.b64decode(event[stream + '_base64'], validate=True)
                    if original != event[stream].encode('utf-8'):
                        raise ValueError('Captured text differs from original bytes: ' + identity)
                    raw_file = path.parent / event[stream + '_file']
                    if raw_file.is_file() and raw_file.read_bytes() != original:
                        raise ValueError('Raw capture file differs: ' + identity)
                scenes[name].append(Event.read({
                    'command': event['display_command'], 'stdout': event['stdout'],
                    'stderr': event['stderr'], 'exit_code': event['returncode'],
                }))
    else:
        if not isinstance(raw.get('scenes'), list):
            raise ValueError('Capture must contain a scenes array')
        scenes = {}
        for item in raw['scenes']:
            identity = item['id']
            if identity in scenes:
                raise ValueError('Duplicate captured scene: ' + identity)
            events = [Event.read(event) for event in item['events']]
            if not events:
                raise ValueError('Empty captured scene: ' + identity)
            scenes[identity] = events
    if set(scenes) != {'build', 'verify', 'tamper', 'restore'}:
        raise ValueError('Capture must contain build, verify, tamper, restore exactly')
    if not any(event.exit_code != 0 for event in scenes['tamper']):
        raise ValueError('Tamper scene has no captured rejection')
    for name in ('build', 'verify', 'restore'):
        if any(event.exit_code != 0 for event in scenes[name]):
            raise ValueError('Unexpected command failure in ' + name)
    return scenes


class Renderer:
    def __init__(self, width, height, scenes, font_dir):
        self.width, self.height, self.scenes = width, height, scenes
        self.portrait = width < height
        self.font_dir = font_dir
        self.fonts = {}
        self.frames = {}
        self.margin = 32 if self.portrait else 68
        self.background = self.make_background()
        self.body_size = 18 if self.portrait else 24
        self.body_line = 26 if self.portrait else 32
        self.columns = 52 if self.portrait else 69
        self.terminal_top = 282 if self.portrait else 300
        self.terminal_height = 444 if self.portrait else 458
        mutation_text = '\n'.join(e.stdout for e in scenes['tamper'])
        match = re.search(r'hello\.o: byte (\d+) changed (0x[0-9a-f]+) -> (0x[0-9a-f]+)', mutation_text)
        if not match:
            raise ValueError('No captured byte-change detail for the editorial marker')
        self.mutation = match.groups()
        self.timeline = self.make_timeline()

    def font(self, size, bold=False):
        key = size, bold
        if key not in self.fonts:
            path = self.font_dir / ('DejaVuSansMono-Bold.ttf' if bold else 'DejaVuSansMono.ttf')
            self.fonts[key] = ImageFont.truetype(str(path), size)
        return self.fonts[key]

    def make_background(self):
        image = Image.new('RGB', (self.width, self.height), COLORS['bg'])
        pixels = ImageDraw.Draw(image)
        for y in range(self.height):
            strength = 0.15 * (1 - abs(y - self.height * .36) / self.height)
            pixels.line((0, y, self.width, y), fill=mix(COLORS['bg'], COLORS['surface'], strength))
        glow = Image.new('RGBA', image.size, (0, 0, 0, 0))
        d = ImageDraw.Draw(glow)
        for radius in range(350, 0, -6):
            opacity = int(8 * (1 - radius / 350))
            d.ellipse((-140 - radius, 100 - radius, -140 + radius, 100 + radius), fill=(*rgb(COLORS['teal']), opacity))
            d.ellipse((self.width - 40 - radius, self.height * .72 - radius,
                       self.width - 40 + radius, self.height * .72 + radius), fill=(*rgb(COLORS['violet']), opacity))
        image = Image.alpha_composite(image.convert('RGBA'), glow.filter(ImageFilter.GaussianBlur(30))).convert('RGB')
        d = ImageDraw.Draw(image)
        for x in range(32, self.width, 32):
            for y in range(32, self.height, 32):
                d.point((x, y), fill='#151b2b')
        return image

    def make_timeline(self):
        result = {}
        for identity, begin, end, *_ in SCENE_META:
            events = self.scenes[identity]
            available = end - begin - .6
            weights = [max(2.5, min(7, len(e.command) / 30 + len((e.stdout + e.stderr).splitlines()) * .23 + 1.5)) for e in events]
            total = sum(weights)
            slots = []
            cursor = .30
            for event, weight in zip(events, weights):
                span = available * weight / total
                type_time = min(span * .44, max(.38, len(event.command) / 42))
                lines = max(1, len((event.stdout + event.stderr).splitlines()))
                reveal_time = min(span * .18, max(.18, lines * .09))
                slots.append((event, cursor, span, type_time, reveal_time))
                cursor += span
            result[identity] = slots
        return result

    def text(self, image, xy, value, size, color='ivory', bold=False, anchor=None):
        ImageDraw.Draw(image).text(xy, value, font=self.font(size, bold), fill=COLORS.get(color, color), anchor=anchor, stroke_width=0)

    def width_of(self, value, size, bold=False):
        return self.font(size, bold).getlength(value)

    def rounded(self, image, box, fill, outline=None, radius=12, width=1):
        ImageDraw.Draw(image).rounded_rectangle(box, radius=radius, fill=COLORS.get(fill, fill), outline=COLORS.get(outline, outline), width=width)

    def header(self, image, selected=None):
        d = ImageDraw.Draw(image)
        m = self.margin
        y = 42 if self.portrait else 44
        d.rectangle((m, y + 5, m + 8, y + 23), fill=COLORS['teal'])
        self.text(image, (m + 21, y), BRAND, 17 if self.portrait else 20, bold=True)
        self.text(image, (self.width - m, y + 4), 'OBJECT / EVIDENCE', 11 if self.portrait else 13, 'muted', anchor='ra')
        d.line((m, 88, self.width - m, 88), fill=COLORS['line'])
        if selected is not None:
            tab_w = (self.width - 2 * m) / 4
            for index, title in enumerate(['BUILD', 'VERIFY', 'ALTER', 'RESTORE']):
                active = index == selected
                accent = SCENE_META[index][-1]
                tx = m + index * tab_w
                self.text(image, (tx, 109), f'0{index + 1}  {title}', 12 if self.portrait else 15, accent if active else 'muted', active)
                if active:
                    d.line((tx, 137, tx + tab_w - 18, 137), fill=COLORS[accent], width=2)

    def footer(self, image, time, scene=None):
        m, h = self.margin, self.height
        y = h - 79
        d = ImageDraw.Draw(image)
        d.line((m, y - 18, self.width - m, y - 18), fill=COLORS['line'])
        self.text(image, (m, y), CAPTION, 11 if self.portrait else 15, 'muted')
        self.text(image, (m, y + 24), 'Basm · Linux x86-64 · object attestation', 10 if self.portrait else 12, 'muted')
        d.line((m, h - 22, self.width - m, h - 22), fill=COLORS['line'], width=2)
        d.line((m, h - 22, m + (self.width - 2 * m) * min(1, time / DURATION), h - 22), fill=COLORS[scene or 'teal'], width=2)

    def icon(self, image, x, y, label, accent, active=True):
        w = 144 if self.portrait else 202
        h = 82 if self.portrait else 100
        self.rounded(image, (x, y, x + w, y + h), 'surface', accent if active else 'line', radius=10)
        self.text(image, (x + 20, y + 17), {'SOURCE': '01', 'OBJECT': '02', 'EVIDENCE': '03'}[label], 12, accent)
        self.text(image, (x + 20, y + 41), label, 14 if self.portrait else 18, 'ivory', True)
        return w

    def object_symbol(self, image, cx, cy, radius, local_time):
        d = ImageDraw.Draw(image)
        points = [(cx, cy - radius), (cx + radius * .86, cy - radius * .5),
                  (cx + radius * .86, cy + radius * .5), (cx, cy + radius),
                  (cx - radius * .86, cy + radius * .5), (cx - radius * .86, cy - radius * .5)]
        center = (cx, cy)
        for multiplier, color in ((1.7, 'line'), (1.9, 'line'), (2.1, 'line')):
            d.ellipse((cx - radius * multiplier, cy - radius * multiplier * .54,
                       cx + radius * multiplier, cy + radius * multiplier * .54), outline=COLORS[color])
        d.polygon([points[0], points[1], center, points[5]], fill='#0c2229')
        d.polygon([points[5], center, points[3], points[4]], fill='#0b1b24')
        d.polygon([center, points[1], points[2], points[3]], fill='#161b32')
        d.line(points + [points[0]], fill=COLORS['teal'], width=2)
        for target in (points[1], points[3], points[5]):
            d.line([center, target], fill=COLORS['violet'], width=2)
        for scale in (.52, .28):
            ring = [(cx, cy - radius * scale), (cx + radius * .86 * scale, cy - radius * .5 * scale),
                    (cx, cy), (cx - radius * .86 * scale, cy - radius * .5 * scale)]
            d.line(ring + [ring[0]], fill='#2c6770', width=1)
        theta = local_time * .32
        px, py = cx + math.cos(theta) * radius * 1.9, cy + math.sin(theta) * radius * 1.03
        d.ellipse((px - 4, py - 4, px + 4, py + 4), fill=COLORS['gold'])
        d.ellipse((px - 10, py - 10, px + 10, py + 10), outline='#57462b')
        for x, y in points:
            d.ellipse((x - 2, y - 2, x + 2, y + 2), fill=COLORS['ivory'])

    def title_card(self, time, end=False):
        image = self.background.copy()
        self.header(image)
        w, h, m = self.width, self.height, self.margin
        title_y = 208 if self.portrait else 204
        self.text(image, (m, title_y - 54), 'SMALL TOOL. LASTING TRACE.', 13 if self.portrait else 17, 'teal', True)
        self.text(image, (m - 5, title_y), 'Basm.', 114 if self.portrait else 166, 'ivory', True)
        sub_y = title_y + (158 if self.portrait else 209)
        self.text(image, (m, sub_y), 'Every build deserves a witness.', 20 if self.portrait else 32, 'ivory', True)
        self.text(image, (m, sub_y + 47), 'Assemble. Inspect. Attest.', 17 if self.portrait else 25, 'muted')
        if not self.portrait:
            self.object_symbol(image, 988, 285, 94, local_time=time)
        row_y = sub_y + 117
        available = w - 2 * m
        icon_w = 144 if self.portrait else 202
        gap = (available - icon_w * 3) / 2
        d = ImageDraw.Draw(image)
        for idx, (label, accent) in enumerate([('SOURCE', 'teal'), ('OBJECT', 'gold'), ('EVIDENCE', 'violet')]):
            xx = m + idx * (icon_w + gap)
            self.icon(image, xx, row_y, label, accent)
            if idx < 2:
                yy = row_y + (41 if self.portrait else 50)
                x1, x2 = xx + icon_w + 12, xx + icon_w + gap - 12
                d.line((x1, yy, x2, yy), fill=COLORS['line'], width=2)
                d.line((x2 - 5, yy - 4, x2, yy), fill=COLORS['muted'], width=1)
                d.line((x2 - 5, yy + 4, x2, yy), fill=COLORS['muted'], width=1)
        self.text(image, (m, row_y + (119 if self.portrait else 145)), 'One changed byte. Watch the verdict change.', 13 if self.portrait else 20, 'gold')
        if end:
            self.text(image, (m, row_y + (153 if self.portrait else 182)), 'Synthetic demo key · object evidence', 11 if self.portrait else 13, 'muted')
        self.footer(image, time)
        local = time - 42.5 if end else time
        alpha = smooth(local / .55)
        if alpha < 1:
            image = Image.blend(self.background, image, alpha)
        return image

    def wrap(self, text):
        # A visual wrap only; no strip, truncation, abbreviation, or replacement.
        output = []
        for line in text.expandtabs(4).split('\n'):
            if not line:
                output.append('')
            else:
                while len(line) > self.columns:
                    cut = line.rfind(' ', 0, self.columns + 1)
                    cut = self.columns if cut < self.columns // 3 else cut + 1
                    output.append(line[:cut])
                    line = line[cut:]
                if line:
                    output.append(line)
        return output

    def rows(self, identity, local):
        rows, current, completed, typing = [], None, False, False
        for event, begin, span, type_time, reveal_time in self.timeline[identity]:
            if local < begin:
                break
            elapsed = local - begin
            current = event
            typed = event.command[:max(0, min(len(event.command), math.ceil(len(event.command) * elapsed / type_time)))]
            parts = self.wrap(typed)
            rows.extend((part, 'command', idx == 0) for idx, part in enumerate(parts))
            typing = elapsed < type_time
            if typing:
                completed = False
                break
            output = []
            for value, stream in ((event.stdout, 'stdout'), (event.stderr, 'stderr')):
                if value:
                    raw_lines = self.wrap(value[:-1] if value.endswith('\n') else value)
                    output.extend((line, stream, False) for line in raw_lines)
            count = min(len(output), max(0, math.ceil(len(output) * (elapsed - type_time - .12) / reveal_time)))
            rows.extend(output[:count])
            completed = elapsed > type_time + .12 + reveal_time
            if elapsed < span:
                break
            rows.append(('', 'space', False))
        return rows, current, completed, typing

    def terminal(self, image, identity, local, accent):
        m, top, width, height = self.margin, self.terminal_top, self.width - 2 * self.margin, self.terminal_height
        d = ImageDraw.Draw(image)
        # Modest static shadow and a solid surface, preserving GIF efficiency.
        self.rounded(image, (m + 5, top + 10, m + width + 5, top + height + 10), '#03050a', radius=14)
        self.rounded(image, (m, top, m + width, top + height), 'surface', 'line', radius=14)
        d.line((m + 1, top + 49, m + width - 1, top + 49), fill=COLORS['line'])
        for idx, color in enumerate(['#3b465f', '#3b465f', COLORS[accent]]):
            d.ellipse((m + 19 + idx * 15, top + 21, m + 25 + idx * 15, top + 27), fill=color)
        self.text(image, (m + 82, top + 16), 'captured session', 12 if self.portrait else 15, 'muted')
        self.text(image, (m + width - 18, top + 18), 'LINUX / x86-64', 10 if self.portrait else 12, accent, anchor='ra')
        rows, current, completed, typing = self.rows(identity, local)
        max_rows = int((height - 74) / self.body_line)
        hidden = max(0, len(rows) - max_rows)
        shown = rows[hidden:]
        body_y = top + 66
        for index, (value, stream, first) in enumerate(shown):
            y = body_y + index * self.body_line
            if stream == 'command':
                if first:
                    self.text(image, (m + 19, y), '$', self.body_size, 'teal', True)
                color = 'ivory'
            elif stream == 'stderr':
                color = 'red' if current and current.exit_code else 'muted'
            else:
                color = 'ivory'
            emphasized = False
            if stream != 'command':
                if value.startswith('ATTEST FAIL') or value.startswith('ATTEST RESULT: FAIL'):
                    color, emphasized = 'red', True
                elif value.startswith(('ATTEST OK', 'ATTEST RESULT: PASS', 'Hello from BearBasm!')):
                    color, emphasized = 'teal', True
                elif value.startswith('hello.o: byte'):
                    color, emphasized = 'gold', True
                elif value.startswith('hello.o: original'):
                    color, emphasized = 'teal', True
                elif value.startswith('ATTEST SIGNER') or (value and all(c in '0123456789abcdef' for c in value.split(' ')[0])):
                    color = 'muted'
            self.text(image, (m + (43 if self.portrait else 54), y), value, self.body_size, color, emphasized)
        if typing and shown:
            last = shown[-1][0]
            cursor_x = m + (43 if self.portrait else 54) + self.width_of(last, self.body_size)
            cursor_y = body_y + (len(shown) - 1) * self.body_line + 3
            d.rectangle((cursor_x + 2, cursor_y, cursor_x + 9, cursor_y + self.body_size - 1), fill=COLORS[accent])
        if hidden:
            self.text(image, (m + width - 17, top + height - 19), '↑ earlier output', 9 if self.portrait else 11, 'muted', anchor='ra')
        badge_y = top + height + 28
        if current is None or not completed:
            label = 'CAPTURED COMMAND'
            color = 'muted'
        elif current.exit_code:
            label = f'EXIT {current.exit_code}  /  REJECTED'
            color = 'red'
        else:
            label = 'EXIT 0  /  COMPLETE'
            color = accent
        d.rectangle((m, badge_y + 4, m + 4, badge_y + 23), fill=COLORS[color])
        self.text(image, (m + 15, badge_y), label, 12 if self.portrait else 16, color, True)
        note = 'Output is real. Playback is edited.' if self.portrait else 'Real output · editorial pacing · no speed benchmark'
        self.text(image, (self.width - m, badge_y + 2), note, 10 if self.portrait else 12, 'muted', anchor='ra')

    def chapter(self, time, meta, index):
        identity, begin, end, number, label, title1, title2, accent = meta
        image = self.background.copy()
        self.header(image, index)
        m = self.margin
        self.text(image, (m, 158), label, 12 if self.portrait else 15, accent, True)
        if self.portrait:
            self.text(image, (m - 1, 184), title1, 31, 'ivory', True)
            self.text(image, (m - 1, 222), title2, 31, 'ivory', True)
        else:
            self.text(image, (m - 1, 189), title1, 43, 'ivory', True)
            self.text(image, (m - 1, 241), title2, 28, 'muted')
        if not self.portrait:
            tags = {
                'build': ('SOURCE → ELF64', 'assemble · link · execute'),
                'verify': ('SIGNED v4 OBJECT', 'external public key'),
                'tamper': (f'{self.mutation[1]} → {self.mutation[2]}', f'byte {self.mutation[0]} · same object'),
                'restore': ('ORIGINAL BYTES', 'restored · verified'),
            }
            headline, detail = tags[identity]
            self.text(image, (self.width - m, 210), headline, 24, accent, True, anchor='ra')
            self.text(image, (self.width - m, 250), detail, 14, 'muted', anchor='ra')
        self.terminal(image, identity, time - begin, accent)
        self.footer(image, time, accent)
        return image

    def frame(self, time):
        if time < 3:
            return self.title_card(time)
        if time >= 42.5:
            return self.title_card(time, end=True)
        for index, meta in enumerate(SCENE_META):
            if meta[1] <= time < meta[2]:
                image = self.chapter(time, meta, index)
                # A brief dip between chapters is an editorial cut, not runtime.
                edge = min((time - meta[1]) / .22, (meta[2] - time) / .20)
                if edge < 1:
                    image = Image.blend(self.background, image, .45 + .55 * smooth(edge))
                return image
        raise ValueError('Frame outside timeline')


def locate_font_dir(argument):
    options = [Path(argument)] if argument else [
        Path('/usr/share/fonts/truetype/dejavu'),
        Path('/usr/local/share/fonts'),
        Path.home() / '.fonts',
    ]
    for option in options:
        if (option / 'DejaVuSansMono.ttf').is_file() and (option / 'DejaVuSansMono-Bold.ttf').is_file():
            return option
    raise SystemExit('DejaVu Sans Mono regular and bold fonts required; use --font-dir')


def render_mp4(renderer, path, fps=FPS):
    cmd = [
        'ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
        '-f', 'rawvideo', '-pixel_format', 'rgb24', '-video_size', f'{renderer.width}x{renderer.height}',
        '-framerate', str(fps), '-i', 'pipe:0', '-an', '-c:v', 'libx264',
        '-preset', 'medium', '-crf', '19', '-pix_fmt', 'yuv420p',
        '-movflags', '+faststart', '-threads', '2', str(path),
    ]
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    try:
        for index in range(round(DURATION * fps)):
            process.stdin.write(renderer.frame(index / fps).tobytes())
            if index % (fps * 10) == 0:
                print(f'Rendered {index / fps:.0f}/{DURATION:.0f}s: {path.name}', flush=True)
        process.stdin.close()
        code = process.wait()
        if code:
            raise RuntimeError(f'FFmpeg failed with exit {code}')
    except BaseException:
        process.kill()
        process.wait()
        raise


def render_gif(renderer, path, scratch, fps=8):
    # The lossless intermediate avoids MP4 ringing and keeps terminal text crisp.
    intermediate = scratch / (path.stem + '-lossless.mkv')
    process = subprocess.Popen([
        'ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-f', 'rawvideo',
        '-pixel_format', 'rgb24', '-video_size', f'{renderer.width}x{renderer.height}',
        '-framerate', str(fps), '-i', 'pipe:0', '-an', '-c:v', 'ffv1',
        '-threads', '2', str(intermediate),
    ], stdin=subprocess.PIPE)
    try:
        for index in range(round(DURATION * fps)):
            process.stdin.write(renderer.frame(index / fps).tobytes())
        process.stdin.close()
        if process.wait():
            raise RuntimeError('FFmpeg failed to render GIF intermediate')
    except BaseException:
        process.kill()
        process.wait()
        raise
    for colors in (128, 96, 64, 48):
        palette = scratch / (path.stem + '-palette.png')
        subprocess.run([
            'ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-i', str(intermediate),
            '-vf', f'palettegen=max_colors={colors}:stats_mode=diff', '-frames:v', '1',
            '-update', '1', '-threads', '1', str(palette),
        ], check=True)
        subprocess.run([
            'ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-i', str(intermediate),
            '-i', str(palette), '-lavfi', 'paletteuse=dither=none:diff_mode=rectangle',
            '-loop', '0', '-gifflags', '+transdiff', '-threads', '1', str(path),
        ], check=True)
        if path.stat().st_size <= 8 * 1024 * 1024:
            return {'colors': colors, 'fps': fps, 'bytes': path.stat().st_size,
                    'dimensions': [renderer.width, renderer.height]}
    raise RuntimeError('GIF exceeds 8 MiB after palette reduction')


def encode_mobile_mp4(intermediate, path):
    # Reuse the exact lossless portrait frames also used by the mobile GIF.
    subprocess.run([
        'ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-i', str(intermediate),
        '-an', '-c:v', 'libx264', '-preset', 'medium', '-crf', '19',
        '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-threads', '2', str(path),
    ], check=True)


def ffprobe(path):
    result = subprocess.run([
        'ffprobe', '-v', 'error', '-show_entries',
        'format=duration,size:stream=codec_name,pix_fmt,width,height,r_frame_rate,codec_type',
        '-of', 'json', str(path),
    ], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--font-dir')
    parser.add_argument('--stills-only', action='store_true')
    args = parser.parse_args()
    for command in ('ffmpeg', 'ffprobe'):
        if shutil.which(command) is None:
            raise SystemExit(f'{command} is required')
    scenes = load_capture(args.capture)
    fonts = locate_font_dir(args.font_dir)
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='basm-media-') as temporary:
        work = args.work or Path(temporary)
        work.mkdir(parents=True, exist_ok=True)
        landscape = Renderer(1280, 960, scenes, fonts)
        portrait = Renderer(720, 900, scenes, fonts)
        landscape.frame(33.4).save(args.out / 'basm-poster.png')
        portrait.frame(33.4).save(args.out / 'basm-poster-mobile.png')
        for moment in (1.5, 12.6, 23.8, 33.4, 41.4, 44.4):
            landscape.frame(moment).save(work / f'frame-{moment:04.1f}.png')
            portrait.frame(moment).save(work / f'portrait-{moment:04.1f}.png')
        if args.stills_only:
            print(json.dumps({'stills': str(work), 'poster': str(args.out / 'basm-poster.png')}))
            return
        render_mp4(landscape, args.out / 'basm-in-action.mp4')
        print('Rendering desktop GIF', flush=True)
        gif = render_gif(landscape, args.out / 'basm-in-action.gif', work)
        print('Rendering mobile GIF', flush=True)
        mobile_gif = render_gif(portrait, args.out / 'basm-in-action-mobile.gif', work)
        print('Encoding mobile MP4 from the same portrait frames', flush=True)
        encode_mobile_mp4(work / 'basm-in-action-mobile-lossless.mkv',
                          args.out / 'basm-in-action-mobile.mp4')
        report = {
            'capture_sha256': hashlib.sha256(args.capture.read_bytes()).hexdigest(),
            'brand': BRAND, 'caption': CAPTION, 'scope': CLAIM,
            'gif': gif, 'mobile_gif': mobile_gif,
            'artifacts': {},
        }
        for filename in ('basm-in-action.mp4', 'basm-in-action.gif',
                         'basm-in-action-mobile.gif', 'basm-in-action-mobile.mp4',
                         'basm-poster.png', 'basm-poster-mobile.png'):
            path = args.out / filename
            info = {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            if path.suffix in ('.mp4', '.gif'):
                info['probe'] = ffprobe(path)
            else:
                info['dimensions'] = list(Image.open(path).size)
            report['artifacts'][filename] = info
        (work / 'media-build.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
