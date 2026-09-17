"""Candidate no-follow path guards and reversible Git mutations."""

from __future__ import annotations

import os
import re
import secrets
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from . import worker_runtime as _runtime
from .worker_runtime import WorkerError


_CANDIDATE_SOURCE_DIGEST = r'''
import hashlib, json, stat, sys
from pathlib import Path
root = Path(sys.argv[1])
skip = {".git", ".lake", "target", "__pycache__"}
def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)
entries = []
for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
    relative = path.relative_to(root)
    if any(part in skip for part in relative.parts):
        continue
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not (stat.S_ISDIR(status.st_mode) or stat.S_ISREG(status.st_mode)):
        raise RuntimeError("invalid candidate source member")
    if stat.S_ISDIR(status.st_mode):
        continue
    data = path.read_bytes()
    if identity(path.lstat()) != identity(status):
        raise RuntimeError("candidate source changed")
    entries.append({"path": relative.as_posix(), "mode": stat.S_IMODE(status.st_mode),
                    "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
body = {"schema": "autofv-candidate-source/v1", "files": entries}
raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
sys.stdout.write(hashlib.sha256(raw).hexdigest() + "\n")
'''.strip()


def _sealed_source_digest(
    run: dict[str, Any], root: str, assigned_path: str
) -> str:
    _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            *_sealed_lane_exec(root, assigned_path, "true"),
        )
    )
    raw = _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            _CANDIDATE_SOURCE_DIGEST,
            root,
        )
    ).stdout.decode("ascii", "strict").strip()
    if re.fullmatch(r"[0-9a-f]{64}", raw) is None:
        raise WorkerError("candidate source digest is invalid")
    return raw


def _sealed_source_file(
    run: dict[str, Any], root: str, relative: str
) -> bytes:
    return _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            *_sealed_lane_exec(root, relative, "cat", "--", relative),
        )
    ).stdout

def _sealed_lane_root(lane: dict[str, Any]) -> str:
    """Bind a sealed lane to its one controller-assigned volume subpath."""
    lane_id = lane.get("lane_id")
    root = lane.get("worktree_path")
    safe = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    if (
        not isinstance(lane_id, str)
        or not lane_id
        or lane_id[0] not in safe[:36]
        or len(lane_id) > 128
        or any(character not in safe for character in lane_id)
        or root != f"/volume/lanes/{lane_id}/work"
    ):
        raise WorkerError("lane root escapes the managed volume")
    return root


_SEALED_LANE_EXEC_SOURCE = """
import os
import stat
import sys


def open_root(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if path == ".":
        return os.open(".", flags)
    if not path.startswith("/"):
        raise RuntimeError("lane root is not absolute")
    descriptor = os.open("/", flags)
    try:
        for part in path.split("/")[1:]:
            if not part or part in {".", ".."}:
                raise RuntimeError("lane root is invalid")
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_file(root_descriptor, relative):
    parts = relative.split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise RuntimeError("lane path is invalid")
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor
        )
        try:
            if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
                raise RuntimeError("lane path is not a regular file")
        finally:
            os.close(file_descriptor)
    finally:
        os.close(descriptor)


root = open_root(sys.argv[1])
try:
    validate_file(root, sys.argv[2])
    if sys.argv[3] == "1":
        try:
            git_status = os.stat(".git", dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(git_status.st_mode):
                raise RuntimeError("lane git authority is not a regular file")
            os.unlink(".git", dir_fd=root)
    os.fchdir(root)
    os.execvp(sys.argv[4], sys.argv[4:])
finally:
    os.close(root)
""".strip()


def _sealed_lane_exec(
    root: str,
    relative: str,
    *command: str,
    detach_git: bool = False,
) -> tuple[str, ...]:
    """Validate a sealed lane without following links, then execute in its fd."""
    if not command:
        raise WorkerError("lane command is unavailable")
    return (
        "python",
        "-c",
        _SEALED_LANE_EXEC_SOURCE,
        root,
        relative,
        "1" if detach_git else "0",
        *command,
    )


def _local_lane_file(
    run: dict[str, Any], lane: dict[str, Any], relative: str
) -> Path:
    """Resolve one simulation-lane file while rejecting every symlink hop."""
    root_text = lane.get("worktree_path")
    lane_id = lane.get("lane_id")
    if not isinstance(root_text, str) or not isinstance(lane_id, str):
        raise WorkerError("lane root is unavailable")
    if not Path(root_text).is_absolute() or ".." in Path(root_text).parts:
        raise WorkerError("lane root escapes the run")
    root = Path(os.path.abspath(root_text))
    run_root = run.get("run_root")
    if isinstance(run_root, str):
        boundary = Path(os.path.abspath(run_root))
        expected = boundary / "lanes" / lane_id / "work"
        if root != expected:
            raise WorkerError("lane root escapes the run")
    else:
        boundary = root
    if not root.is_relative_to(boundary):
        raise WorkerError("lane root escapes the run")
    current = boundary
    root_parts = root.relative_to(boundary).parts
    try:
        for part in (None, *root_parts):
            if part is not None:
                current /= part
            status = current.lstat()
            if stat.S_ISLNK(status.st_mode):
                raise WorkerError("lane root must not contain a symlink")
            if not stat.S_ISDIR(status.st_mode):
                raise WorkerError("lane root is unavailable")
    except OSError as exc:
        raise WorkerError("lane root is unavailable") from exc
    relative_parts = PurePosixPath(relative).parts
    try:
        path = root
        for index, part in enumerate(relative_parts):
            path /= part
            status = path.lstat()
            if stat.S_ISLNK(status.st_mode):
                raise WorkerError("lane path must not contain a symlink")
            if index < len(relative_parts) - 1 and not stat.S_ISDIR(status.st_mode):
                raise WorkerError("lane path is unavailable")
    except OSError as exc:
        raise WorkerError("lane path is unavailable") from exc
    if not stat.S_ISREG(path.lstat().st_mode):
        raise WorkerError("lane path escapes its root or is not a file")
    return path


def _simulation_git_snapshot(project: Path, relative: str) -> dict[str, Any]:
    """Capture the exact mutable Git state touched by candidate acceptance."""
    head_result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=project,
        capture_output=True,
        text=True,
    )
    if head_result.returncode:
        raise WorkerError("simulation Git HEAD is unavailable")
    index_result = subprocess.run(
        ("git", "rev-parse", "--git-path", "index"),
        cwd=project,
        capture_output=True,
        text=True,
    )
    if index_result.returncode:
        raise WorkerError("simulation Git index is unavailable")
    index_path = Path(index_result.stdout.strip())
    if not index_path.is_absolute():
        index_path = project / index_path
    try:
        index_status = index_path.lstat()
    except OSError as exc:
        raise WorkerError("simulation Git index is unavailable") from exc
    if stat.S_ISLNK(index_status.st_mode) or not stat.S_ISREG(index_status.st_mode):
        raise WorkerError("simulation Git index is invalid")

    target = project
    parts = PurePosixPath(relative).parts
    try:
        for index, part in enumerate(parts):
            target /= part
            status = target.lstat()
            if stat.S_ISLNK(status.st_mode):
                raise WorkerError("simulation candidate path contains a symlink")
            expected_kind = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
            if not expected_kind(status.st_mode):
                raise WorkerError("simulation candidate path is invalid")
    except OSError as exc:
        raise WorkerError("simulation candidate path is unavailable") from exc
    return {
        "project": project,
        "head": head_result.stdout.strip(),
        "index_path": index_path,
        "index_bytes": index_path.read_bytes(),
        "index_mode": stat.S_IMODE(index_status.st_mode),
        "target_path": target,
        "target_bytes": target.read_bytes(),
        "target_mode": stat.S_IMODE(target.lstat().st_mode),
    }


def _restore_simulation_git_snapshot(snapshot: dict[str, Any]) -> None:
    """Restore candidate-touched index and worktree bytes without Git resets."""
    current_result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=snapshot["project"],
        capture_output=True,
        text=True,
    )
    if current_result.returncode:
        raise WorkerError("simulation Git HEAD rollback is unavailable")
    current = current_result.stdout.strip()
    if current != snapshot["head"]:
        restored = subprocess.run(
            ("git", "update-ref", "HEAD", snapshot["head"], current),
            cwd=snapshot["project"],
            capture_output=True,
        )
        if restored.returncode:
            raise WorkerError("simulation Git HEAD rollback failed")

    target = snapshot["target_path"]
    try:
        status = target.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            target.unlink()
    _runtime._atomic_write(target, snapshot["target_bytes"])
    target.chmod(snapshot["target_mode"])

    index_path = snapshot["index_path"]
    _runtime._atomic_write(index_path, snapshot["index_bytes"])
    index_path.chmod(snapshot["index_mode"])


_EXPECTED_CANDIDATE_TREE = r'''
set -eu
project="$1"
patch_file=/tmp/autofv-candidate.patch
index_file=/tmp/autofv-candidate.index
trap 'rm -f "$patch_file" "$index_file"' EXIT
cat > "$patch_file"
rm -f "$index_file"
GIT_INDEX_FILE="$index_file" git -C "$project" read-tree HEAD
GIT_INDEX_FILE="$index_file" git -C "$project" apply --cached --check "$patch_file"
GIT_INDEX_FILE="$index_file" git -C "$project" apply --cached "$patch_file"
# AUTOFV_EXPECTED_TREE: independently construct the exact post-patch tree.
GIT_INDEX_FILE="$index_file" git -C "$project" write-tree
'''.strip()


def _prepare_acceptance_snapshot(
    run: dict[str, Any], path: str, raw_patch: bytes
) -> tuple[str, str, bytes, str]:
    """Create and verify a disposable source snapshot outside canonical state."""
    lane_id = f"accept-{_runtime._sha256(raw_patch)[:16]}-{secrets.token_hex(8)}"
    root = f"/volume/lanes/{lane_id}/work"
    baseline = _runtime._git(run, "archive", "--format=tar", "HEAD")
    _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            "sh",
            "-eu",
            "-c",
            'test ! -e "$1"; mkdir -p "${1%/*}"; mkdir "$1"; tar -xf - -C "$1"',
            "sh",
            root,
        ),
        input_bytes=baseline,
    )
    for check in (True, False):
        command = ["git", "apply"]
        if check:
            command.append("--check")
        command.append("-")
        _runtime._docker(
            *_runtime._runtime_argv(
                run["lock"],
                run["volume"],
                *_sealed_lane_exec(root, path, *command),
            ),
            input_bytes=raw_patch,
        )
    before = _sealed_source_digest(run, root, path)
    expected_tree = _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            "sh",
            "-eu",
            "-c",
            _EXPECTED_CANDIDATE_TREE,
            "sh",
            "/volume/work/project",
        ),
        input_bytes=raw_patch,
    ).stdout.decode("ascii", "strict").strip()
    if len(expected_tree) != 40 or any(
        character not in "0123456789abcdef" for character in expected_tree
    ):
        raise WorkerError("candidate expected tree identity is invalid")
    return lane_id, before, _sealed_source_file(run, root, path), expected_tree


def _rollback_sealed_candidate(run: dict[str, Any], previous_head: str) -> None:
    """Return the disposable canonical repository to its pre-import commit."""
    current = _runtime._git(run, "rev-parse", "HEAD").decode().strip()
    if current != previous_head:
        _runtime._git(run, "update-ref", "HEAD", previous_head, current)
    _runtime._git(run, "reset", "--hard", previous_head)


def accept_sealed_candidate(
    run: dict[str, Any], candidate: dict[str, Any], manifest: dict[str, Any],
    path: str, raw_patch: bytes,
) -> dict[str, Any]:
    """Compile without canonical authority, then import exactly the validated tree."""
    verify = manifest.get("verify")
    if (
        not isinstance(verify, list)
        or not verify
        or any(not isinstance(item, str) or not item for item in verify)
    ):
        raise WorkerError("candidate verification command is unavailable")
    previous_head = _runtime._git(run, "rev-parse", "HEAD").decode().strip()
    lane_id, source_digest, assigned_bytes, expected_tree = (
        _prepare_acceptance_snapshot(run, path, raw_patch)
    )
    root = f"/volume/lanes/{lane_id}/work"
    _runtime._docker(
        *_runtime._candidate_runtime_argv(
            run["lock"],
            run["volume"],
            lane_id,
            *_sealed_lane_exec(".", path, *verify, detach_git=True),
        )
    )
    if _sealed_source_digest(run, root, path) != source_digest:
        raise WorkerError("candidate verification modified authoritative source")
    if _sealed_source_file(run, root, path) != assigned_bytes:
        raise WorkerError("candidate assigned source changed during verification")
    canonical_mutated = False
    try:
        _runtime._git(run, "apply", "--check", "-", input_bytes=raw_patch)
        _runtime._git(run, "apply", "-", input_bytes=raw_patch)
        canonical_mutated = True
        _runtime._git(run, "add", "--", path)
        changed = _runtime._git(
            run, "diff", "--cached", "--name-only", "-z"
        ).decode("utf-8", "strict")
        if changed != f"{path}\0":
            raise WorkerError("candidate canonical import changed unexpected paths")
        observed_tree = _runtime._git(run, "write-tree").decode().strip()
        if observed_tree != expected_tree:
            raise WorkerError("candidate canonical import tree mismatch")
        if _runtime._git(run, "show", f":{path}") != assigned_bytes:
            raise WorkerError("candidate canonical import bytes mismatch")
        _runtime._docker(
            *_runtime._runtime_argv(
                run["lock"],
                run["volume"],
                "git",
                "-C",
                "/volume/work/project",
                "-c",
                "user.name=AutoFV",
                "-c",
                "user.email=autofv@invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                candidate["request_id"],
            )
        )
        commit = _runtime._git(run, "rev-parse", "HEAD").decode().strip()
        tree = _runtime._git(run, "archive", "--format=tar", "HEAD")
    except BaseException as exc:
        if canonical_mutated:
            try:
                _rollback_sealed_candidate(run, previous_head)
            except BaseException as rollback_exc:
                raise WorkerError(
                    f"{exc}; sealed candidate rollback failed: {rollback_exc}"
                ) from exc
        raise
    run["events"].append(f"accepted:{path}")
    return {
        "accepted_commit": commit,
        "accepted_tree_sha256": _runtime._sha256(tree),
        "checks": [
            "assigned_path_scope",
            "base_commit",
            "patch_sha256",
            "patch_applies",
            "forbidden_source_markers",
            "isolated_candidate_snapshot",
            "source_immutable_during_build",
            "exact_canonical_tree_import",
            "configured_build",
        ],
    }
