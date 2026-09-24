"""Host-only tests: malformed archives never reach a Docker extraction command."""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import tarfile
import tempfile
from collections import namedtuple
import unittest
from pathlib import Path
from unittest import mock

from autofv import dependency_cache, worker_runtime


def _archive(*entries: tuple[str, str, str]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for root in ("packages", "toolchain", "mathlib-cache"):
            member = tarfile.TarInfo(root)
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        for name, kind, target in entries:
            member = tarfile.TarInfo(name)
            if kind == "link":
                member.type = tarfile.SYMTYPE
                member.linkname = target
            elif kind == "special":
                member.type = tarfile.CHRTYPE
            else:
                member.size = len(target.encode())
            archive.addfile(member, io.BytesIO(target.encode()) if kind == "file" else None)
    return stream.getvalue()


class DependencyCacheTests(unittest.TestCase):
    def test_valid_internal_symlink_and_file(self):
        raw = _archive(("packages/aeneas/lib", "file", "data"),
                       ("packages/aeneas/ref", "link", "lib"))
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r|") as archive:
            dependency_cache._validate_members(archive)

    def test_rejects_traversal_duplicate_symlink_escape_nested_and_special(self):
        cases = (
            (("../outside", "file", "x"),),
            (("packages/../../outside", "file", "x"),),
            (("packages/dir", "file", "x"), ("packages/dir", "file", "y")),
            (("packages/ref", "link", "../../outside"),),
            (("packages/ref", "link", "/outside"),),
            (("packages/ref", "link", "inside"), ("packages/ref/new", "file", "x")),
            (("packages/device", "special", ""),),
            (("unknown/data", "file", "x"),),
        )
        for entries in cases:
            with self.subTest(entries=entries), tarfile.open(
                fileobj=io.BytesIO(_archive(*entries)), mode="r|"
            ) as archive, self.assertRaises(dependency_cache.CacheError):
                dependency_cache._validate_members(archive)

    def test_rejects_unrecognized_pax_metadata(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as writer:
            for root in ("packages", "toolchain", "mathlib-cache"):
                member = tarfile.TarInfo(root)
                member.type = tarfile.DIRTYPE
                writer.addfile(member)
            member = tarfile.TarInfo("packages/strange")
            member.pax_headers = {"GNU.sparse.name": "outside"}
            writer.addfile(member)
        with tarfile.open(fileobj=io.BytesIO(raw.getvalue()), mode="r|") as archive:
            with self.assertRaises((dependency_cache.CacheError, tarfile.TarError)):
                dependency_cache._validate_members(archive)

    @unittest.skipUnless(shutil.which("zstd"), "zstd is needed for archive intake")
    def test_validation_stages_exact_bytes_and_blocks_tampering(self):
        raw = _archive(("packages/example", "file", "ok"))
        compressed = subprocess.run(
            ("zstd", "-q", "-T1", "-c"), input=raw, capture_output=True,
            check=True,
        ).stdout
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.tar.zst"
            path.write_bytes(compressed)
            digest = hashlib.sha256(compressed).hexdigest()
            with dependency_cache.validated_archive(path, digest, len(compressed)) as staged:
                self.assertNotEqual(staged, path)
                self.assertEqual(staged.read_bytes(), compressed)
                path.write_bytes(b"corrupted outside staged input")
                self.assertEqual(staged.read_bytes(), compressed)
            self.assertFalse(staged.exists())
            with self.assertRaises(dependency_cache.CacheError):
                with dependency_cache.validated_archive(path, digest):
                    self.fail("an invalid cache must not enter the guest")
            path.unlink()
            path.symlink_to(Path(tmp) / "other")
            with self.assertRaises(dependency_cache.CacheError):
                with dependency_cache.validated_archive(path, digest):
                    self.fail("a symlinked cache must not enter the guest")

    def test_low_disk_space_blocks_before_archive_read_or_guest_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "cache.tar.zst"
            source.write_bytes(b"not an archive")
            usage = namedtuple("usage", "total used free")(100, 99, 1)
            with mock.patch.object(dependency_cache.shutil, "disk_usage", return_value=usage):
                with self.assertRaisesRegex(dependency_cache.CacheError, "insufficient space"):
                    with dependency_cache.validated_archive(
                        source, hashlib.sha256(source.read_bytes()).hexdigest()
                    ):
                        self.fail("low disk space must block staging")

    @unittest.skipUnless(shutil.which("zstd"), "zstd is needed for archive intake")
    def test_invalid_archive_cannot_reach_worker_extraction(self):
        raw = _archive(("packages/../outside", "file", "bad"))
        compressed = subprocess.run(
            ("zstd", "-q", "-T1", "-c"), input=raw, capture_output=True,
            check=True,
        ).stdout
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.tar.zst"
            path.write_bytes(compressed)
            with mock.patch.object(worker_runtime, "_docker") as docker, mock.patch.object(
                worker_runtime, "_lima_stream_file"
            ) as streamed, self.assertRaises(worker_runtime.WorkerError):
                worker_runtime.seed_dependency_cache(
                    {"volume": "unused"}, path, hashlib.sha256(compressed).hexdigest()
                )
            docker.assert_not_called()
            streamed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
