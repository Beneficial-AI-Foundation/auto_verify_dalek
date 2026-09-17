"""Authenticated durable snapshots for private candidate lanes."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import worker_runtime as _runtime
from .candidate_lane import _local_lane_file, _sealed_lane_exec, _sealed_lane_root
from .worker_runtime import WorkerError


_LANE_FIELDS = frozenset(
    {
        "schema",
        "lane_id",
        "request_id",
        "node",
        "base_commit",
        "assigned_path",
        "worktree_path",
        "cache_path",
        "result_path",
    }
)
_SOURCE_SKIP_PARTS = frozenset({".git", ".lake", "target", "__pycache__"})
_MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
_MAX_SNAPSHOT_RECORD_BYTES = 4 * 1024 * 1024


def _lane_descriptor(run: dict[str, Any], lane: dict[str, Any]) -> dict[str, Any]:
    """Validate and copy the complete immutable lane identity."""
    if set(lane) - {"status", "requeueable"} != _LANE_FIELDS:
        raise WorkerError("lane snapshot descriptor is invalid")
    body = {field: lane[field] for field in sorted(_LANE_FIELDS)}
    lane_id = body["lane_id"]
    assigned = body["assigned_path"]
    pure = PurePosixPath(assigned) if isinstance(assigned, str) else None
    if (
        body["schema"] != "autofv-proof-lane/v1"
        or not isinstance(lane_id, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", lane_id) is None
        or not isinstance(body["base_commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", body["base_commit"]) is None
        or pure is None
        or pure.is_absolute()
        or pure.as_posix() != assigned
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise WorkerError("lane snapshot descriptor is invalid")
    if run.get("execution_tier") == "simulation":
        run_root = run.get("run_root")
        if not isinstance(run_root, str):
            raise WorkerError("lane snapshot run root is unavailable")
        root = Path(run_root)
        expected = root / "lanes" / lane_id
        paths = {
            "worktree_path": expected / "work",
            "cache_path": expected / "cache",
            "result_path": expected / "result" / "candidate.json",
        }
        if any(Path(body[field]) != value for field, value in paths.items()):
            raise WorkerError("lane snapshot path escapes the run")
    else:
        expected = f"/volume/lanes/{lane_id}"
        if (
            body["worktree_path"] != f"{expected}/work"
            or body["cache_path"] != f"{expected}/cache"
            or body["result_path"] != f"{expected}/result/candidate.json"
        ):
            raise WorkerError("lane snapshot path escapes the managed volume")
    return body


def _snapshot_directory(run: dict[str, Any], *, create: bool) -> Path:
    root_text = run.get("run_root")
    if not isinstance(root_text, str):
        raise WorkerError("lane snapshot run root is unavailable")
    root = Path(root_text)
    try:
        if root.resolve(strict=True) != root or not root.is_dir():
            raise WorkerError("lane snapshot run root is not canonical")
    except OSError as exc:
        raise WorkerError("lane snapshot run root is unavailable") from exc
    directory = root / "lane-snapshots"
    if os.path.lexists(directory):
        status = directory.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise WorkerError("lane snapshot directory is invalid")
    elif create:
        directory.mkdir(mode=0o700)
    else:
        raise WorkerError("lane snapshot is missing")
    return directory


def _snapshot_key(directory: Path, *, create: bool) -> bytes:
    path = directory / ".key"
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if not create:
            raise WorkerError("lane snapshot authentication key is missing")
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            raise WorkerError("lane snapshot authentication key is unavailable") from exc
        key = secrets.token_bytes(32)
        with os.fdopen(descriptor, "wb") as output:
            output.write(key)
            output.flush()
            os.fsync(output.fileno())
        return key
    except OSError as exc:
        raise WorkerError("lane snapshot authentication key is unavailable") from exc
    with os.fdopen(descriptor, "rb") as source:
        key = source.read(33)
    if len(key) != 32:
        raise WorkerError("lane snapshot authentication key is invalid")
    return key


def _source_member(relative: PurePosixPath) -> bool:
    return not any(part in _SOURCE_SKIP_PARTS for part in relative.parts)


def _stable_file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Describe source identity without access time, which reads may update."""
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _archive_manifest(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > _MAX_SNAPSHOT_BYTES:
        raise WorkerError("lane snapshot exceeds its size bound")
    entries: list[dict[str, Any]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    not member.isfile()
                    or path.is_absolute()
                    or path.as_posix() != member.name
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not _source_member(path)
                ):
                    raise WorkerError("lane snapshot archive member is invalid")
                source = archive.extractfile(member)
                if source is None:
                    raise WorkerError("lane snapshot archive member is missing")
                data = source.read(_MAX_SNAPSHOT_BYTES + 1)
                entries.append(
                    {
                        "path": member.name,
                        "mode": member.mode & 0o777,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
    except (tarfile.TarError, OSError) as exc:
        raise WorkerError("lane snapshot archive is invalid") from exc
    if entries != sorted(entries, key=lambda item: item["path"]):
        raise WorkerError("lane snapshot archive is not canonical")
    if len({item["path"] for item in entries}) != len(entries):
        raise WorkerError("lane snapshot archive contains duplicate paths")
    return entries


def _local_source_archive(run: dict[str, Any], lane: dict[str, Any]) -> bytes:
    root = _local_lane_file(run, lane, lane["assigned_path"]).parents[
        len(PurePosixPath(lane["assigned_path"]).parts) - 1
    ]
    files: list[tuple[str, bytes, int]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if not _source_member(relative):
            continue
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise WorkerError("lane snapshot source contains a symlink")
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode):
            raise WorkerError("lane snapshot source contains a special file")
        data = path.read_bytes()
        if _stable_file_identity(path.lstat()) != _stable_file_identity(status):
            raise WorkerError("lane snapshot source changed while being read")
        files.append((relative.as_posix(), data, stat.S_IMODE(status.st_mode)))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data, mode in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid = info.gid = info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


_SEALED_SOURCE_ARCHIVE = r'''
import hashlib, io, os, stat, sys, tarfile
from pathlib import Path
schema = "autofv-resume-source/v1"
root = Path(sys.argv[1])
skip = {".git", ".lake", "target", "__pycache__"}
def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)
files = []
for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
    relative = path.relative_to(root)
    if any(part in skip for part in relative.parts):
        continue
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not (stat.S_ISDIR(status.st_mode) or stat.S_ISREG(status.st_mode)):
        raise RuntimeError("invalid lane source member")
    if stat.S_ISDIR(status.st_mode):
        continue
    data = path.read_bytes()
    if identity(path.lstat()) != identity(status):
        raise RuntimeError("lane source changed")
    files.append((relative.as_posix(), data, stat.S_IMODE(status.st_mode)))
stream = io.BytesIO()
with tarfile.open(fileobj=stream, mode="w") as archive:
    for name, data, mode in files:
        info = tarfile.TarInfo(name)
        info.size = len(data); info.mode = mode
        info.uid = info.gid = info.mtime = 0
        archive.addfile(info, io.BytesIO(data))
sys.stdout.buffer.write(stream.getvalue())
'''.strip()


def _capture_sealed_source_root(
    run: dict[str, Any], root: str
) -> tuple[bytes, str]:
    """Capture one sealed source root as inert, canonical archive data."""
    path = PurePosixPath(root)
    if (
        not path.is_absolute()
        or path.as_posix() != root
        or any(part in {"", ".", ".."} for part in path.parts)
        or root != "/volume/work/project"
        and not root.startswith("/volume/lanes/")
    ):
        raise WorkerError("sealed source root is invalid")
    raw = _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            _SEALED_SOURCE_ARCHIVE,
            root,
        )
    ).stdout
    manifest = _archive_manifest(raw)
    if not manifest:
        raise WorkerError("sealed source snapshot is empty")
    return raw, manifest[0]["path"]


def _capture_lane_source(run: dict[str, Any], lane: dict[str, Any]) -> bytes:
    _lane_descriptor(run, lane)
    if run.get("execution_tier") == "simulation":
        raw = _local_source_archive(run, lane)
    else:
        root = _sealed_lane_root(lane)
        _runtime._docker(
            *_runtime._runtime_argv(
                run["lock"],
                run["volume"],
                *_sealed_lane_exec(root, lane["assigned_path"], "true"),
            )
        )
        raw = _runtime._docker(
            *_runtime._runtime_argv(
                run["lock"], run["volume"], "python", "-c", _SEALED_SOURCE_ARCHIVE, root
            )
        ).stdout
    _archive_manifest(raw)
    return raw


def _atomic_snapshot_write(path: Path, raw: bytes) -> None:
    _runtime._atomic_write(path, raw)
    path.chmod(0o600)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _snapshot_file_present(path: Path) -> bool:
    try:
        status = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise WorkerError("lane snapshot is unavailable") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise WorkerError("lane snapshot file is invalid")
    return True


def _read_snapshot_file(directory: Path, name: str, limit: int) -> bytes:
    directory_fd = -1
    file_fd = -1
    try:
        directory_fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        status = os.fstat(file_fd)
        if not stat.S_ISREG(status.st_mode) or status.st_size > limit:
            raise WorkerError("lane snapshot file is invalid")
        with os.fdopen(file_fd, "rb", closefd=False) as source:
            raw = source.read(limit + 1)
        if len(raw) > limit:
            raise WorkerError("lane snapshot file is invalid")
        return raw
    except FileNotFoundError as exc:
        raise WorkerError("lane snapshot is missing") from exc
    except OSError as exc:
        raise WorkerError("lane snapshot is unavailable") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0:
            os.close(directory_fd)


def _save_lane_snapshot(
    run: dict[str, Any], lane: dict[str, Any], archive: bytes, *, initial: bool = False
) -> dict[str, Any]:
    descriptor = _lane_descriptor(run, lane)
    manifest = _archive_manifest(archive)
    directory = _snapshot_directory(run, create=True)
    key = _snapshot_key(directory, create=True)
    stem = descriptor["lane_id"]
    record_path = directory / f"{stem}.json"
    archive_path = directory / f"{stem}.tar"
    record_exists = _snapshot_file_present(record_path)
    archive_exists = _snapshot_file_present(archive_path)
    if record_exists != archive_exists:
        raise WorkerError("lane snapshot is incomplete")
    if record_exists:
        prior, _prior_archive = _load_lane_snapshot(run, lane)
        if initial:
            if prior["sequence"] != 1 or archive != _prior_archive:
                raise WorkerError("initial lane snapshot differs from its immutable base")
            return prior
        sequence = prior["sequence"] + 1
    else:
        sequence = 1
    body = {
        "schema": "autofv-lane-snapshot/v1",
        "run_id": run.get("run_id"),
        "sequence": sequence,
        "lane": descriptor,
        "base_commit": descriptor["base_commit"],
        "assigned_path": descriptor["assigned_path"],
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "archive_size": len(archive),
        "files": manifest,
    }
    receipt = {
        **body,
        "snapshot_sha256": hashlib.sha256(_runtime._canonical_bytes(body)).hexdigest(),
    }
    record = {
        "body": receipt,
        "auth": hmac.new(
            key, _runtime._canonical_bytes(receipt), hashlib.sha256
        ).hexdigest(),
    }
    _atomic_snapshot_write(archive_path, archive)
    _atomic_snapshot_write(
        record_path, _runtime._canonical_bytes(record) + b"\n"
    )
    return receipt


def _load_lane_snapshot(
    run: dict[str, Any], lane: dict[str, Any]
) -> tuple[dict[str, Any], bytes]:
    descriptor = _lane_descriptor(run, lane)
    directory = _snapshot_directory(run, create=False)
    key = _snapshot_key(directory, create=False)
    record_path = directory / f"{descriptor['lane_id']}.json"
    archive_path = directory / f"{descriptor['lane_id']}.tar"
    if not _snapshot_file_present(record_path) or not _snapshot_file_present(archive_path):
        raise WorkerError("lane snapshot is missing")
    try:
        raw_record = _read_snapshot_file(
            directory, record_path.name, _MAX_SNAPSHOT_RECORD_BYTES
        )
        record = json.loads(raw_record)
        receipt = record["body"]
        auth = record["auth"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise WorkerError("lane snapshot authentication failed") from exc
    expected_auth = hmac.new(
        key, _runtime._canonical_bytes(receipt), hashlib.sha256
    ).hexdigest()
    if not isinstance(auth, str) or not hmac.compare_digest(auth, expected_auth):
        raise WorkerError("lane snapshot authentication failed")
    body = {key: value for key, value in receipt.items() if key != "snapshot_sha256"}
    if (
        set(receipt) != {
            "schema", "run_id", "sequence", "lane", "base_commit", "assigned_path",
            "archive_sha256", "archive_size", "files", "snapshot_sha256",
        }
        or receipt.get("schema") != "autofv-lane-snapshot/v1"
        or receipt.get("run_id") != run.get("run_id")
        or type(receipt.get("sequence")) is not int
        or receipt["sequence"] < 1
        or receipt.get("lane") != descriptor
        or receipt.get("base_commit") != descriptor["base_commit"]
        or receipt.get("assigned_path") != descriptor["assigned_path"]
        or receipt.get("snapshot_sha256")
        != hashlib.sha256(_runtime._canonical_bytes(body)).hexdigest()
    ):
        raise WorkerError("lane snapshot identity mismatch")
    try:
        archive = _read_snapshot_file(
            directory, archive_path.name, _MAX_SNAPSHOT_BYTES
        )
    except OSError as exc:
        raise WorkerError("lane snapshot is missing") from exc
    if (
        len(archive) != receipt.get("archive_size")
        or hashlib.sha256(archive).hexdigest() != receipt.get("archive_sha256")
        or _archive_manifest(archive) != receipt.get("files")
    ):
        raise WorkerError("lane snapshot authentication failed")
    return receipt, archive


def _archive_contents(raw: bytes) -> dict[str, tuple[bytes, int]]:
    _archive_manifest(raw)
    files: dict[str, tuple[bytes, int]] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive.getmembers():
            source = archive.extractfile(member)
            if source is None:
                raise WorkerError("lane snapshot archive member is missing")
            files[member.name] = (source.read(), member.mode & 0o777)
    return files


def _restore_local_source(
    run: dict[str, Any], lane: dict[str, Any], archive: bytes
) -> None:
    _local_lane_file(run, lane, lane["assigned_path"])
    root = Path(lane["worktree_path"])
    files = _archive_contents(archive)
    if lane["assigned_path"] not in files:
        raise WorkerError("lane snapshot assigned source is missing")
    existing: list[Path] = []
    directories: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if not _source_member(relative):
            continue
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise WorkerError("lane restore source contains a symlink")
        if stat.S_ISDIR(status.st_mode):
            directories.append(path)
        elif stat.S_ISREG(status.st_mode):
            existing.append(path)
        else:
            raise WorkerError("lane restore source contains a special file")
    for path in existing:
        path.unlink()
    for name, (data, mode) in files.items():
        destination = root.joinpath(*PurePosixPath(name).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        current = root
        for part in PurePosixPath(name).parts[:-1]:
            current /= part
            status = current.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise WorkerError("lane restore path is invalid")
        _runtime._atomic_write(destination, data)
        destination.chmod(mode)
    expected_directories = {
        root.joinpath(*PurePosixPath(name).parts[:index])
        for name in files
        for index in range(1, len(PurePosixPath(name).parts))
    }
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        if directory not in expected_directories:
            try:
                directory.rmdir()
            except OSError:
                pass


_SEALED_SOURCE_RESTORE = r'''
import io, os, stat, sys, tarfile
from pathlib import PurePosixPath
skip = {".git", ".lake", "target", "__pycache__"}
limit = 128 * 1024 * 1024
raw = sys.stdin.buffer.read(limit + 1)
if len(raw) > limit:
    raise RuntimeError("snapshot too large")
files = {}
with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if (not member.isfile() or path.is_absolute() or path.as_posix() != member.name
                or any(part in {"", ".", ".."} or part in skip for part in path.parts)
                or member.name in files):
            raise RuntimeError("invalid snapshot member")
        source = archive.extractfile(member)
        if source is None:
            raise RuntimeError("missing snapshot member")
        files[member.name] = (source.read(), member.mode & 0o777)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
descriptor = os.open("/", flags)
try:
    for part in sys.argv[1].split("/")[1:]:
        if not part or part in {".", ".."}:
            raise RuntimeError("invalid lane root")
        next_descriptor = os.open(part, flags, dir_fd=descriptor)
        os.close(descriptor); descriptor = next_descriptor
    for directory, names, file_names, directory_fd in os.fwalk(
            ".", topdown=True, follow_symlinks=False, dir_fd=descriptor):
        names[:] = [name for name in names if name not in skip]
        for name in names:
            status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise RuntimeError("invalid lane directory")
        for name in file_names:
            relative = str(PurePosixPath(directory) / name).removeprefix("./")
            if any(part in skip for part in PurePosixPath(relative).parts):
                continue
            status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
                raise RuntimeError("invalid lane file")
            os.unlink(name, dir_fd=directory_fd)
    for name, (data, mode) in sorted(files.items()):
        parts = PurePosixPath(name).parts
        parent = os.dup(descriptor)
        try:
            for part in parts[:-1]:
                try:
                    child = os.open(part, flags, dir_fd=parent)
                except FileNotFoundError:
                    os.mkdir(part, 0o755, dir_fd=parent)
                    child = os.open(part, flags, dir_fd=parent)
                os.close(parent); parent = child
            temporary = ".autofv-restore.tmp"
            output = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode,
                dir_fd=parent,
            )
            try:
                with os.fdopen(output, "wb", closefd=False) as destination:
                    destination.write(data); destination.flush(); os.fsync(output)
                os.fchmod(output, mode)
            finally:
                os.close(output)
            os.rename(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            os.close(parent)
finally:
    os.close(descriptor)
'''.strip()


def _restore_sealed_source_root(
    run: dict[str, Any], root: str, archive: bytes
) -> None:
    """Restore inert source bytes only into one controller-created private lane."""
    path = PurePosixPath(root)
    if (
        not path.is_absolute()
        or path.as_posix() != root
        or len(path.parts) != 5
        or path.parts[:3] != ("/", "volume", "lanes")
        or re.fullmatch(r"resume-[a-z0-9-]{1,120}", path.parts[3]) is None
        or path.parts[4] != "work"
    ):
        raise WorkerError("resume source root is invalid")
    _archive_manifest(archive)
    _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            _SEALED_SOURCE_RESTORE,
            root,
        ),
        input_bytes=archive,
    )


def _restore_lane_source(
    run: dict[str, Any], lane: dict[str, Any], archive: bytes
) -> None:
    _lane_descriptor(run, lane)
    manifest = _archive_manifest(archive)
    if lane["assigned_path"] not in {item["path"] for item in manifest}:
        raise WorkerError("lane snapshot assigned source is missing")
    if run.get("execution_tier") == "simulation":
        _restore_local_source(run, lane, archive)
    else:
        root = _sealed_lane_root(lane)
        _runtime._docker(
            *_runtime._runtime_argv(
                run["lock"],
                run["volume"],
                "python",
                "-c",
                _SEALED_SOURCE_RESTORE,
                root,
            ),
            input_bytes=archive,
        )


def save_lane_snapshot(
    run: dict[str, Any], lane: dict[str, Any], *, initial: bool = False
) -> dict[str, Any]:
    """Persist an authenticated full source view outside candidate mounts."""
    archive = _capture_lane_source(run, lane)
    return _save_lane_snapshot(run, lane, archive, initial=initial)


def restore_lane_snapshot(
    run: dict[str, Any],
    lane: dict[str, Any],
    *,
    expected_receipt: dict[str, Any] | None = None,
    _prepare_lanes: Any,
) -> dict[str, Any]:
    """Authenticate, recreate if needed, and exactly restore one private lane."""
    receipt, archive = _load_lane_snapshot(run, lane)
    if expected_receipt is not None and receipt != expected_receipt:
        raise WorkerError("lane snapshot does not match its durable receipt")
    root = lane["worktree_path"]
    if run.get("execution_tier") == "simulation":
        exists = os.path.lexists(root)
    else:
        exists = (
            _runtime._docker(
                *_runtime._runtime_argv(
                    run["lock"], run["volume"], "test", "-d", root
                ),
                check=False,
            ).returncode
            == 0
        )
    if not exists:
        _prepare_lanes(run, [lane])
    if run.get("execution_tier") == "simulation":
        for directory in (
            Path(lane["cache_path"]),
            Path(lane["result_path"]).parent,
        ):
            if os.path.lexists(directory) and directory.is_symlink():
                raise WorkerError("lane snapshot metadata path contains a symlink")
            directory.mkdir(parents=True, exist_ok=True)
    else:
        _runtime._docker(
            *_runtime._runtime_argv(
                run["lock"],
                run["volume"],
                "mkdir",
                "-p",
                lane["cache_path"],
                str(PurePosixPath(lane["result_path"]).parent),
            )
        )
    _restore_lane_source(run, lane, archive)
    return receipt
