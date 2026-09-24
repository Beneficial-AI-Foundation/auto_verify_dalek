"""Validate a private, hash-bound dependency archive before any guest extraction."""

from __future__ import annotations

import hashlib
import os
import posixpath
import shutil
import stat
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


_ALLOWED_ROOTS = {"packages", "toolchain", "mathlib-cache"}
_ALLOWED_PAX = {
    "hdrcharset", "mtime", "path", "LIBARCHIVE.xattr.com.apple.provenance",
    "SCHILY.xattr.com.apple.provenance",
}
_MAX_ENTRIES = 125_000
_MAX_EXPANDED = 8 * 1024**3
_MAX_MEMBER = 512 * 1024**2
_MAX_ARCHIVE = 3 * 1024**3
_MIN_FREE_AFTER_STAGE = 10 * 1024**3


class CacheError(ValueError):
    pass


def _identity(status: os.stat_result) -> tuple[int, ...]:
    # Reading a file can update atime; only mutations and inode replacement matter.
    return (status.st_dev, status.st_ino, status.st_mode, status.st_size,
            status.st_mtime_ns, status.st_ctime_ns)


def _validate_members(archive: tarfile.TarFile) -> None:
    seen: set[str] = set()
    links: set[str] = set()
    expanded = 0
    for member in archive:
        name = member.name.rstrip("/") if member.isdir() else member.name
        parts = name.split("/")
        if (
            len(seen) >= _MAX_ENTRIES
            or name in seen
            or parts[0] not in _ALLOWED_ROOTS
            or any(part in {"", ".", ".."} for part in parts)
            or name.startswith("/")
            or "\\" in name
            or not (member.isdir() or member.isfile() or member.issym())
            or member.sparse is not None
            or not set(member.pax_headers) <= _ALLOWED_PAX
        ):
            raise CacheError("dependency archive contains an unsafe member")
        seen.add(name)
        if member.isfile():
            expanded += member.size
            if member.size > _MAX_MEMBER or expanded > _MAX_EXPANDED:
                raise CacheError("dependency archive expands beyond its limit")
        elif member.issym():
            target = member.linkname
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            if (
                not target or target.startswith("/") or "\\" in target
                or resolved.split("/")[0] != parts[0]
                or resolved in {".", ".."}
                or resolved.startswith("../")
            ):
                raise CacheError("dependency archive symlink escapes its root")
            links.add(name)
    if not _ALLOWED_ROOTS <= seen:
        raise CacheError("dependency archive is incomplete")
    if any(any(path.startswith(link + "/") for link in links) for path in seen):
        raise CacheError("dependency archive contains paths beneath a symlink")


@contextmanager
def validated_archive(
    source: str | Path, expected_sha256: str, expected_size: int | None = None
) -> Iterator[Path]:
    """Yield the *same* private compressed bytes that passed identity and tar checks."""
    with tempfile.TemporaryDirectory(prefix="autofv-dependencies-") as directory:
        staged = Path(directory) / "dependency-cache.tar.zst"
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as original, staged.open("xb") as copy:
                before = os.fstat(original.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_ARCHIVE:
                    raise CacheError("dependency archive identity is invalid")
                if shutil.disk_usage(directory).free < before.st_size + _MIN_FREE_AFTER_STAGE:
                    raise CacheError("insufficient space to stage dependency archive")
                digest = hashlib.sha256()
                while chunk := original.read(8 * 1024 * 1024):
                    copy.write(chunk)
                    digest.update(chunk)
                copy.flush()
                after = os.fstat(original.fileno())
                if (
                    _identity(before) != _identity(after)
                    or digest.hexdigest() != expected_sha256
                    or (expected_size is not None and before.st_size != expected_size)
                    or staged.stat().st_size != before.st_size
                ):
                    raise CacheError("dependency archive identity changed")
            proc = subprocess.Popen(
                ("zstd", "-dc", "-T1", str(staged)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                assert proc.stdout is not None
                with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
                    _validate_members(archive)
                if proc.wait(timeout=60):
                    raise CacheError("dependency archive decompression failed")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()
        except (OSError, tarfile.TarError, subprocess.TimeoutExpired) as exc:
            raise CacheError("dependency archive could not be validated") from exc
        yield staged
