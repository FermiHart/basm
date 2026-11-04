#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
# SPDX-License-Identifier: BSD-3-Clause
"""Failure-path tests for builds, deterministic packages and owned installation."""
from __future__ import annotations

import contextlib
import errno
import hashlib
from html.parser import HTMLParser
import importlib.util
import io
import json
import os
from pathlib import Path
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location("basm_" + name, ROOT / "tools" / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


builder = module("build")
packager = module("package")
installer = module("install")


class HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if not value:
                continue
            if name in ("href", "src", "poster"):
                self.links.append(value)
            elif name == "srcset" and not value.lstrip().startswith("data:"):
                self.links.extend(part.strip().split()[0] for part in value.split(",") if part.strip())


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="bear-basm-package-test-")
        self.root = Path(self.work.name)

    def tearDown(self):
        self.work.cleanup()

    def sample_payload(self):
        return {"bin/basm": (b"test binary\n", 0o755),
                "share/doc/bear-basm/LICENSE": (b"license\n", 0o644),
                installer.INSTALLER: (b"# retained installer\n", 0o644)}

    def install_sample(self, target):
        with contextlib.redirect_stdout(io.StringIO()):
            installer.install(target, self.sample_payload(), "0.1.0-test")

    def source_fixture(self, extra_files=None):
        source = self.root / "git-source"
        source.mkdir()
        required = ["Makefile", "VERSION", "version.h", "README.md", "LICENSE", "NOTICE", "REUSE.toml",
                    "LICENSES/BSD-3-Clause.txt", "LICENSES/LicenseRef-SPL-1.0.txt", "LICENSES/Unlicense.txt",
                    "LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt", "basm.c",
                    "tools/build.py", "tools/package.py", "tools/install.py"]
        files = {name: b"fixture\n" for name in required}
        files.update(extra_files or {})
        for name, content in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        subprocess.run(["git", "init", "-q", str(source)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "add", "--", *files], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Basm packaging test",
                        "-c", "user.email=basm-test@example.invalid", "commit", "-qm", "fixture"],
                       check=True, capture_output=True)
        return source, set(files)

    def binary_fixture(self):
        source, build = self.root / "source", self.root / "build"
        source.mkdir()
        build.mkdir()
        for name, content in {
            "VERSION": b"0.1.0-test\n", "README.md": b"readme\n", "LICENSE": b"license\n",
            "NOTICE": b"notice\n", "SUPPORTED-SUBSET.md": b"subset\n", "POLITICA-BASM.md": b"policy\n",
            "docs/BUILD.md": b"build\n", "tools/install.py": b"# installer\n", "basm.c": b"int x;\n",
            "REUSE.toml": b"version = 1\n", "LICENSES/BSD-3-Clause.txt": b"BSD-3-Clause\n",
            "LICENSES/LicenseRef-SPL-1.0.txt": b"SPL\n", "LICENSES/Unlicense.txt": b"Unlicense\n",
            "LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt": b"TweetNaCl public domain\n",
            "examples/hello_linux_x86_64.basm": b"nop\n", "examples/bytes.basm": b"db 1\n",
            "CONTRIBUTING.md": b"contributing\n", "SECURITY.md": b"security\n", "CHANGELOG.md": b"changelog\n",
            "docs/TESTING.md": b"testing\n", "provenance/UPSTREAM.json": b"{}\n",
            "lab/README.md": b"lab guide\n", "lab/MEASUREMENT.md": b"measurement guide\n",
            "index.html": b"public page\n", "downloads/README.md": b"download instructions\n",
            "readme/LICENSE.media.txt": b"media license\n", "readme/hero-basm.svg": b"desktop hero\n",
            "readme/hero-basm-mobile.svg": b"mobile hero\n", "readme/basm-in-action.gif": b"desktop GIF\n",
            "readme/basm-in-action-mobile.gif": b"mobile GIF\n", "readme/basm-in-action.mp4": b"film\n",
            "readme/basm-in-action-mobile.mp4": b"mobile film\n", "readme/basm-poster.png": b"poster\n",
            "readme/basm-poster-mobile.png": b"mobile poster\n",
            "demo/README.md": b"demo\n", "demo/demo.py": b"# demo helper\n",
            "demo/demo.pub": b"synthetic public key\n", "demo/other-demo.pub": b"other synthetic public key\n",
            "demo/explain_summary.py": b"# trace summary\n", "demo/hello.basm": b"nop\n",
            "demo/object_edit.py": b"# object edit helper\n", "demo/run.sh": b"# demo runner\n",
        }.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        binary = b"fixture binary\n"
        (build / "basm").write_bytes(binary)
        identity = lambda data: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        receipt = {"schema": "bear-basm-build-v1", "status": "BUILT", "version": "0.1.0-test",
                   "lane": "sovereign", "target": "linux-x86_64", "qualification": "test fixture only",
                   "artifacts": {"basm": identity(binary)}, "source_inputs": {"basm.c": identity(b"int x;\n")}}
        (build / "build-receipt.json").write_text(json.dumps(receipt))
        return source, build

    def test_missing_beyond_never_falls_back_to_host(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/build.py"), "--lane", "sovereign",
                                 "--beyond-root", "", "--output-dir", str(self.root / "output")],
                                capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BEYOND_ROOT", result.stderr)
        self.assertFalse((self.root / "output").exists())

    def test_failed_compiler_preserves_previous_published_binary(self):
        output = self.root / "output"
        output.mkdir()
        (output / "basm").write_bytes(b"previous binary\n")
        (output / "build-receipt.json").write_bytes(b"previous receipt\n")
        compiler = self.root / "fail-compiler"
        compiler.write_text('#!/bin/sh\nif [ "$1" = --version ]; then printf "deliberate test compiler\\n"; exit 0; fi\nexit 1\n')
        compiler.chmod(0o755)
        result = subprocess.run([sys.executable, str(ROOT / "tools/build.py"), "--lane", "host",
                                 "--cc", str(compiler), "--output-dir", str(output)],
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((output / "basm").read_bytes(), b"previous binary\n")
        self.assertEqual((output / "build-receipt.json").read_bytes(), b"previous receipt\n")
        receipts = list((output / "runs").glob("*/build-receipt.json"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(json.loads(receipts[0].read_text())["status"], "FAILED")

    def test_success_exit_without_output_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "without a nonempty regular output"):
            builder.atomic_command([sys.executable, "-c", "pass"], self.root / "missing.o",
                                   cwd=self.root, log=self.root / "command.log")

    def test_stale_intermediate_is_not_accepted(self):
        stale = self.root / "stale.o"
        stale.write_bytes(b"old object")
        with self.assertRaisesRegex(ValueError, "already exists"):
            builder.atomic_command([sys.executable, "-c", "raise SystemExit(1)"], stale,
                                   cwd=self.root, log=self.root / "command.log")
        self.assertEqual(stale.read_bytes(), b"old object")

    def test_version_header_must_match_distribution_version(self):
        (self.root / "version.h").write_text('#define BASM_VERSION "0.1.0-old"\n')
        with self.assertRaisesRegex(ValueError, "same single BASM_VERSION"):
            builder.validate_version_header(self.root, "0.1.0-new")

    def test_tar_is_byte_reproducible_and_contains_verified_inventory(self):
        entries = packager.complete_entries({"bin/basm": (b"binary", 0o755), "LICENSE": (b"license", 0o644)},
                                            {"version": "0.1.0-test", "kind": "binary"})
        a, b = self.root / "a.tar.gz", self.root / "b.tar.gz"
        packager.write_archive(a, "bear-basm-test", entries, 1234567890)
        packager.write_archive(b, "bear-basm-test", entries, 1234567890)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with tarfile.open(a) as archive:
            for member in archive:
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 1234567890))
                self.assertFalse(member.name.startswith("/"))
            manifest = json.load(archive.extractfile("bear-basm-test/MANIFEST.json"))
            for record in manifest["files"]:
                data = archive.extractfile("bear-basm-test/" + record["path"]).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])

    def test_archive_traversal_is_refused(self):
        with self.assertRaises(ValueError):
            packager.complete_entries({"../outside": (b"x", 0o644)}, {})
        with self.assertRaises(ValueError):
            packager.write_archive(self.root / "bad.tar.gz", "../bad", {}, 0)

    def test_binary_package_refuses_changed_binary(self):
        source, build = self.binary_fixture()
        packager.binary_entries(source, build)
        (build / "basm").write_bytes(b"replacement")
        with self.assertRaisesRegex(ValueError, "does not match"):
            packager.binary_entries(source, build)

    def test_binary_package_refuses_source_drift(self):
        source, build = self.binary_fixture()
        (source / "basm.c").write_bytes(b"changed source")
        with self.assertRaisesRegex(ValueError, "source changed"):
            packager.binary_entries(source, build)

    def test_binary_docs_do_not_sweep_untracked_license_or_example_files(self):
        source, build = self.binary_fixture()
        (source / "LICENSES/local-private-key.pem").write_text("sentinel\n")
        (source / "examples/private-experiment.basm").write_text("sentinel\n")
        (source / "readme/private.mp4").write_bytes(b"sentinel\n")
        (source / "demo/private.seed").write_bytes(b"sentinel\n")
        entries, _ = packager.binary_entries(source, build)
        self.assertNotIn("LICENSES/local-private-key.pem", entries)
        self.assertNotIn("examples/private-experiment.basm", entries)
        self.assertNotIn("readme/private.mp4", entries)
        self.assertNotIn("demo/private.seed", entries)

    def test_binary_docs_refuse_symlink_ancestor(self):
        source, build = self.binary_fixture()
        outside = self.root / "outside-licenses"
        (source / "LICENSES").rename(outside)
        (source / "LICENSES").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            packager.binary_entries(source, build)

    def test_readme_links_resolve_in_distributed_documentation(self):
        entries = packager.documentation_entries(ROOT)
        all_local_links = []
        for page in ("README.md", "index.html", "downloads/README.md", "demo/README.md",
                     "docs/BUILD.md", "docs/TESTING.md", "lab/README.md", "lab/MEASUREMENT.md"):
            with self.subTest(page=page):
                text = entries[page][0].decode("utf-8")
                # Check Markdown and HTML media links, not shell examples or code paths.
                text = re.sub(r"(?ms)^```[^\n]*\n.*?^```[^\n]*$", "", text)
                text = re.sub(r"`[^`\n]*`", "", text)
                inline = re.findall(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", text)
                referenced = re.findall(r"(?m)^\s*\[[^\]\n]+\]:\s*(\S+)", text)
                html = HTMLLinks()
                html.feed(text)
                local_links = []
                for target in inline + referenced + html.links:
                    url = urlsplit(target.strip().split()[0].strip("<>"))
                    if url.scheme or url.netloc or not url.path:
                        continue
                    local_links.append(posixpath.normpath(posixpath.join(posixpath.dirname(page), unquote(url.path))))
                all_local_links.extend(local_links)
                missing = sorted(set(local_links) - entries.keys())
                self.assertEqual(missing, [], "presentation links must work inside the extracted binary package")
        self.assertIn("readme/hero-basm.svg", all_local_links)
        self.assertIn("readme/basm-in-action-mobile.gif", all_local_links)
        self.assertIn("readme/basm-poster-mobile.png", all_local_links)

    def test_source_install_preserves_the_packaged_documentation_set(self):
        source, build = self.binary_fixture()
        documents = packager.documentation_entries(source)
        payload, _ = installer.payload_from_source(source, build)
        prefix = "share/doc/bear-basm/"
        installed = {name[len(prefix):] for name in payload if name.startswith(prefix)}
        installed.discard("build-receipt.json")
        self.assertEqual(set(documents), installed)
        notices = {"LICENSE", "NOTICE", "REUSE.toml", "LICENSES/BSD-3-Clause.txt",
                   "LICENSES/LicenseRef-SPL-1.0.txt", "LICENSES/Unlicense.txt",
                   "LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt"}
        entries, _ = packager.binary_entries(source, build)
        self.assertTrue(notices <= entries.keys())
        for name in notices:
            original = (source / name).read_bytes()
            self.assertEqual(entries[name][0], original)
            self.assertEqual(payload[prefix + name][0], original)

    def test_source_distribution_never_sweeps_untracked_files(self):
        source, required = self.source_fixture()
        (source / "local-secret.txt").write_text("untracked sentinel\n")
        entries, _ = packager.source_entries(source)
        self.assertNotIn("local-secret.txt", entries)
        self.assertEqual(set(entries), set(required))
        subprocess.run(["git", "-C", str(source), "rm", "--cached", "--", "REUSE.toml"],
                       check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "requires explicitly Git-staged files: REUSE.toml"):
            packager.source_entries(source)

    def test_source_distribution_excludes_only_declared_downloads(self):
        assets = {"index.html": b"public page\n", "downloads/README.md": b"download instructions\n",
                  "readme/hero-basm.svg": b"hero\n", "readme/hero-basm-mobile.svg": b"mobile hero\n",
                  "readme/basm-in-action.gif": b"GIF\n", "readme/basm-in-action.mp4": b"film\n",
                  "readme/basm-poster.png": b"poster\n", "readme/generate_media.py": b"# renderer\n",
                  "demo/demo.py": b"# demo\n", "demo/demo.pub": b"synthetic key\n",
                  "demo/other-demo.pub": b"other synthetic key\n", "demo/run.sh": b"# runner\n"}
        downloads = {}
        for lane in ("source", "linux-x86_64", "linux-x86_64-host-diagnostic"):
            name = "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-" + lane + ".tar.gz"
            downloads[name] = b"published archive\n"
            downloads[name + ".sha256"] = b"published archive checksum\n"
        source, tracked = self.source_fixture({**assets, **downloads})
        entries, metadata = packager.source_entries(source)
        self.assertEqual(set(entries), tracked - downloads.keys())
        self.assertEqual(metadata["excluded_published_artifacts"], sorted(downloads))
        for name, data in assets.items():
            self.assertEqual(entries[name][0], data)

    def test_source_distribution_rejects_undeclared_media_keys_and_downloads(self):
        source, _ = self.source_fixture()
        unexpected = ["downloads/0.1.0-dev.1/other.tar.gz", "downloads/0.1.0-dev.1/private.seed",
                      "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-source.tar.gz.backup",
                      "downloads/0.2.0/bear-basm-0.2.0-source.tar.gz",
                      "demo/private.pub", "readme/private.mp4", "readme/private.svg"]
        for name in unexpected:
            with self.subTest(path=name):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"unexpected input\n")
                subprocess.run(["git", "-C", str(source), "add", "--", name], check=True, capture_output=True)
                with self.assertRaisesRegex(ValueError, "has no source-distribution policy") as error:
                    packager.source_entries(source)
                self.assertIn(name, str(error.exception))
                subprocess.run(["git", "-C", str(source), "rm", "--cached", "--", name],
                               check=True, capture_output=True)
                path.unlink()

    def test_declared_download_symlink_is_rejected(self):
        name = "downloads/0.1.0-dev.1/bear-basm-0.1.0-dev.1-source.tar.gz"
        source, _ = self.source_fixture({name: b"archive\n"})
        outside = self.root / "outside-download"
        outside.write_bytes(b"outside sentinel\n")
        (source / name).unlink()
        (source / name).symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            packager.source_entries(source)

    def test_install_collision_refuses_before_any_write(self):
        target = self.root / "prefix"
        (target / "bin").mkdir(parents=True)
        (target / "bin/basm").write_bytes(b"someone else's command\n")
        with self.assertRaisesRegex(ValueError, "unrelated"):
            self.install_sample(target)
        self.assertEqual((target / "bin/basm").read_bytes(), b"someone else's command\n")
        self.assertFalse((target / "share").exists())

    def test_prefix_destdir_spaces_roundtrip(self):
        target = installer.destination_root("/opt/bear tools", str(self.root / "stage directory"))
        self.install_sample(target)
        self.assertEqual((target / "bin/basm").stat().st_mode & 0o777, 0o755)
        self.install_sample(target)  # Reinstall owned, unchanged files.
        unrelated = target / "bin/other-tool"
        unrelated.write_bytes(b"keep")
        with contextlib.redirect_stdout(io.StringIO()):
            installer.uninstall(target)
        self.assertFalse((target / "bin/basm").exists())
        self.assertEqual(unrelated.read_bytes(), b"keep")

    def test_uninstall_refuses_changed_file_before_deleting_anything(self):
        target = self.root / "prefix"
        self.install_sample(target)
        changed = target / "share/doc/bear-basm/LICENSE"
        changed.write_bytes(b"local modification")
        with self.assertRaisesRegex(ValueError, "modified"):
            installer.uninstall(target)
        self.assertTrue((target / "bin/basm").exists())
        self.assertEqual(changed.read_bytes(), b"local modification")

    def test_upgrade_enospc_rolls_back_all_previous_bytes(self):
        target = self.root / "prefix"
        self.install_sample(target)
        originals = {name: (target / name).read_bytes() for name in self.sample_payload()}
        original_manifest = (target / installer.INSTALL_MANIFEST).read_bytes()
        replacement = {name: (data + b"new-version\n", mode) for name, (data, mode) in self.sample_payload().items()}
        real_write = installer.atomic_write

        def fault(path, data, mode):
            if path == target / "bin/basm":
                raise OSError(errno.ENOSPC, "injected full disk")
            return real_write(path, data, mode)

        with mock.patch.object(installer, "atomic_write", side_effect=fault):
            with self.assertRaises(OSError):
                installer.install(target, replacement, "0.2.0-test")
        for name, data in originals.items():
            self.assertEqual((target / name).read_bytes(), data)
        self.assertEqual((target / installer.INSTALL_MANIFEST).read_bytes(), original_manifest)
        self.assertFalse((target / installer.JOURNAL).exists())
        self.assertFalse(list(target.rglob(".bear-basm-backup-*")))
        self.install_sample(target)  # The previous release remains maintainable.
        with contextlib.redirect_stdout(io.StringIO()):
            installer.uninstall(target)

    def test_interrupted_upgrade_recovers_before_next_operation(self):
        target = self.root / "prefix"
        self.install_sample(target)
        changed_name = "share/doc/bear-basm/LICENSE"
        with installer.prefix_lock(target):
            installer.prepare_transaction(target, {changed_name: (b"interrupted upgrade\n", 0o644)})
            installer.atomic_write(target / changed_name, b"interrupted upgrade\n", 0o644)
        self.assertTrue((target / installer.JOURNAL).exists())
        self.install_sample(target)
        self.assertEqual((target / changed_name).read_bytes(), b"license\n")
        self.assertFalse((target / installer.JOURNAL).exists())

    def test_second_writer_cannot_enter_same_prefix(self):
        target = self.root / "prefix"
        self.install_sample(target)
        with installer.prefix_lock(target):
            with self.assertRaisesRegex(ValueError, "another installation"):
                installer.install(target, self.sample_payload(), "0.1.0-test")

    def test_symlink_destination_is_refused(self):
        target = self.root / "prefix"
        outside = self.root / "outside"
        target.mkdir()
        outside.mkdir()
        (target / "bin").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.install_sample(target)
        self.assertFalse(list(outside.iterdir()))

    def test_uninstall_manifest_cannot_escape_prefix(self):
        target = self.root / "prefix"
        path = target / installer.INSTALL_MANIFEST
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"schema": installer.SCHEMA, "files": {
            "../../outside": {"sha256": "0" * 64}}}))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            installer.uninstall(target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
