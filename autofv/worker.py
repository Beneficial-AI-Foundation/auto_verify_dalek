"""Trusted Docker/runsc launcher for the V1 sealed experiment."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
AGENT_VM = "autofv-agent"
AGENT_UID = "65532:65532"
SKIP_PARTS = frozenset({".git", ".lake", "target", "__pycache__"})
SKIP_NAMES = frozenset({"Cargo.lock", "functions.json"})
FIXTURE_RUN_ID = "fixture-diamond-run-0001"


class WorkerError(RuntimeError):
    """The trusted worker could not preserve its launch contract."""

    def __init__(self, message: str, *, run: dict[str, Any] | None = None):
        super().__init__(message)
        self.run = run


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _tree_files(root: Path) -> Iterable[tuple[str, bytes, int]]:
    root = root.resolve(strict=True)
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative.parts) or path.name in SKIP_NAMES:
            continue
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise WorkerError(f"symlink is forbidden in sealed input: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(status.st_mode):
            raise WorkerError(f"special file is forbidden in sealed input: {relative}")
        data = path.read_bytes()
        if path.lstat() != status:
            raise WorkerError(f"input changed while being copied: {relative}")
        yield relative.as_posix(), data, stat.S_IMODE(status.st_mode)


def _tree_hash(files: Iterable[tuple[str, bytes, int]]) -> str:
    entries = [
        {"path": name, "sha256": _sha256(data), "size": len(data)}
        for name, data, _ in files
    ]
    return _sha256(_canonical_bytes(entries))


def hash_tree(root: str | Path) -> str:
    """Hash the canonical regular-file view used for the sealed snapshot."""
    return _tree_hash(_tree_files(Path(root)))


def _control_manifest(lock: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, bytes, int]]]:
    contract = lock["controller_delivery"]
    members = contract["allowed_members"]
    if not isinstance(members, list) or len(members) != len(set(members)):
        raise WorkerError("control bundle allowlist is invalid")
    files: list[tuple[str, bytes, int]] = []
    entries: list[dict[str, Any]] = []
    for member in sorted(members):
        path = PurePosixPath(member)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise WorkerError("control bundle member path is invalid")
        source = ROOT.joinpath(*path.parts)
        status = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(status.st_mode):
            raise WorkerError(f"control bundle member is not a regular file: {member}")
        data = source.read_bytes()
        entries.append({"path": member, "sha256": _sha256(data), "size": len(data)})
        files.append((member, data, 0o444))
    body = {
        "schema": contract["manifest"]["schema"],
        "entries": entries,
        "modes": contract["modes"],
    }
    return {**body, "bundle_sha256": _sha256(_canonical_bytes(body))}, files


def _add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def _seed_archive(
    target: Path, lock: dict[str, Any]
) -> tuple[bytes, dict[str, Any], str]:
    manifest, control_files = _control_manifest(lock)
    project_files = list(_tree_files(target))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data, mode in project_files:
            _add_bytes(archive, f"work/project/{name}", data, mode & 0o755)
        for name, data, mode in control_files:
            _add_bytes(archive, f"autofv-control/{name}", data, mode)
        _add_bytes(
            archive,
            "autofv-control/manifest.json",
            _canonical_bytes(manifest) + b"\n",
            0o444,
        )
    return stream.getvalue(), manifest, _tree_hash(project_files)


def _lima(*argv: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ("limactl", "shell", AGENT_VM, "--", *argv),
            input=input_bytes,
            capture_output=True,
        )
    except OSError as exc:
        raise WorkerError(f"agent worker launcher failed: {exc}") from exc
    if completed.returncode:
        detail = "\n".join(
            part
            for part in (
                completed.stdout.decode("utf-8", "replace").strip(),
                completed.stderr.decode("utf-8", "replace").strip(),
            )
            if part
        )[-4000:]
        raise WorkerError(f"agent worker command failed: {detail or argv[0]}")
    return completed


def _docker(*argv: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return _lima("sudo", "docker", *argv, input_bytes=input_bytes)


def _runtime_argv(lock: dict[str, Any], volume: str, *command: str) -> tuple[str, ...]:
    return (
        "run",
        "--rm",
        "-i",
        "--pull",
        "never",
        "--runtime",
        lock["tools"]["runsc"]["runtime_name"],
        "--read-only",
        "--network",
        "none",
        "--user",
        AGENT_UID,
        "--workdir",
        "/volume/work/project",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--cpus",
        "2",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--tmpfs",
        "/home/autofv/.cache:rw,noexec,nosuid,nodev,size=64m",
        "--mount",
        f"type=volume,src={volume},dst=/volume,volume-nocopy",
        lock["image"]["image_digest"],
        *command,
    )


def _git(run: dict[str, Any], *argv: str, input_bytes: bytes | None = None) -> bytes:
    completed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "git",
            "-C",
            "/volume/work/project",
            *argv,
        ),
        input_bytes=input_bytes,
    )
    return completed.stdout


def prepare_run(target: Path, manifest: dict[str, Any], lock: dict[str, Any]) -> dict[str, Any]:
    """Copy target/control bytes into a fresh named volume without a bind mount."""
    archive, control_manifest, snapshot_sha256 = _seed_archive(target, lock)
    run_id = FIXTURE_RUN_ID
    volume = f"autofv-{secrets.token_hex(8)}"
    run_root = Path(tempfile.mkdtemp(prefix=f"{run_id}-"))
    run = {
        "run_id": run_id,
        "run_root": str(run_root),
        "project_dir": "/volume/work/project",
        "evidence_dir": str(run_root / "evidence"),
        "volume": volume,
        "agent_worker_id": f"lima:{AGENT_VM}",
        "execution_tier": "sealed_runsc",
        "cost_classification": lock["fixed_proxy"]["cost_classification"],
        "snapshot_sha256": snapshot_sha256,
        "manifest_sha256": _sha256(_canonical_bytes(manifest)),
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": control_manifest["bundle_sha256"],
        "events": ["validated"],
        "lock": lock,
    }
    seed = (
        "mkdir -p /volume/work/project /volume/evidence /volume/accepted "
        "/volume/logs /volume/lanes /volume/autofv-control && "
        "tar -xf - -C /volume && "
        "chown -R 65532:65532 /volume/work /volume/evidence /volume/accepted "
        "/volume/logs /volume/lanes && "
        "chmod -R a-w /volume/autofv-control && chmod 0555 /volume/autofv-control"
    )
    git_env = (
        "-e",
        "GIT_AUTHOR_NAME=AutoFV Fixture",
        "-e",
        "GIT_AUTHOR_EMAIL=fixture@autofv.invalid",
        "-e",
        "GIT_AUTHOR_DATE=2000-01-01T00:00:00+00:00",
        "-e",
        "GIT_COMMITTER_NAME=AutoFV Fixture",
        "-e",
        "GIT_COMMITTER_EMAIL=fixture@autofv.invalid",
        "-e",
        "GIT_COMMITTER_DATE=2000-01-01T00:00:00+00:00",
    )
    try:
        _lima("true")
        _docker("volume", "create", volume)
        _docker(
            "run",
            "--rm",
            "-i",
            "--pull",
            "never",
            "--network",
            "none",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,src={volume},dst=/volume,volume-nocopy",
            lock["image"]["image_digest"],
            "sh",
            "-eu",
            "-c",
            seed,
            input_bytes=archive,
        )
        run["events"].extend(("target_copied", "control_bundle_verified"))
        for command in (
            ("git", "-C", "/volume/work/project", "init", "-q", "--object-format=sha1"),
            ("git", "-C", "/volume/work/project", "config", "core.autocrlf", "false"),
            ("git", "-C", "/volume/work/project", "config", "core.filemode", "false"),
            ("git", "-C", "/volume/work/project", "add", "--all"),
        ):
            _docker(*_runtime_argv(lock, volume, *command))
            if "runsc_started" not in run["events"]:
                run["events"].append("runsc_started")
        _docker(
            "run",
            "--rm",
            "--pull",
            "never",
            *git_env,
            "--runtime",
            lock["tools"]["runsc"]["runtime_name"],
            "--read-only",
            "--network",
            "none",
            "--user",
            AGENT_UID,
            "--security-opt",
            "no-new-privileges",
            "--mount",
            f"type=volume,src={volume},dst=/volume,volume-nocopy",
            lock["image"]["image_digest"],
            "git",
            "-C",
            "/volume/work/project",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "Freeze the prepared diamond baseline",
        )
        run["base_commit"] = _git(run, "rev-parse", "HEAD").decode().strip()
        run["accepted"] = {
            "accepted_commit": run["base_commit"],
            "accepted_tree_sha256": _sha256(
                _git(run, "archive", "--format=tar", "HEAD")
            ),
            "checks": ["sealed_baseline"],
        }
    except WorkerError as exc:
        exc.run = run
        raise
    return run


def _bridge(rust_raw: bytes, manifest: dict[str, Any]) -> bytes:
    rust = json.loads(rust_raw)
    namespace = manifest["targets"][0]["spec"].rsplit(".", 1)[0]
    records = []
    for atom in rust["data"].values():
        if atom.get("language") != "rust" or not atom.get("rust-qualified-name"):
            continue
        lines = atom["code-text"]
        records.append(
            {
                "lean_name": f"{namespace}.{atom['display-name']}",
                "rust_name": atom["rust-qualified-name"],
                "source": atom["code-path"],
                "lines": f"L{lines['lines-start']}-L{lines['lines-end']}",
                "is_hidden": False,
                "is_extraction_artifact": False,
            }
        )
    return _canonical_bytes({"functions": sorted(records, key=lambda item: item["lean_name"])}) + b"\n"


def prepare_lanes(run: dict[str, Any], lanes: list[dict[str, Any]]) -> None:
    """Create private worktrees and mutable paths serially from one base."""
    if not lanes:
        raise WorkerError("proof lane list is empty")
    keys = {
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
    bases = {lane.get("base_commit") for lane in lanes}
    if len(bases) != 1:
        raise WorkerError("proof lanes must share one accepted base")
    mutable = [
        lane[field]
        for lane in lanes
        for field in ("worktree_path", "cache_path", "result_path")
    ]
    if len(mutable) != len(set(mutable)):
        raise WorkerError("proof lanes share mutable state")

    project = Path(run["project_dir"])
    local = project.is_dir()
    local_root = (Path(run["run_root"]) / "lanes").resolve() if local else None
    for lane in lanes:
        if set(lane) != keys or lane["schema"] != "autofv-proof-lane/v1":
            raise WorkerError("proof lane descriptor is invalid")
        worktree = lane["worktree_path"]
        cache = lane["cache_path"]
        result_parent = str(PurePosixPath(lane["result_path"]).parent)
        if local:
            paths = [Path(worktree), Path(cache), Path(lane["result_path"])]
            if any(not path.resolve().is_relative_to(local_root) for path in paths):
                raise WorkerError("proof lane path escapes the run")
            Path(cache).mkdir(parents=True)
            Path(lane["result_path"]).parent.mkdir(parents=True)
            completed = subprocess.run(
                ("git", "worktree", "add", "--detach", worktree, lane["base_commit"]),
                cwd=project,
                capture_output=True,
                text=True,
            )
            if completed.returncode:
                raise WorkerError(
                    f"proof lane worktree failed: {(completed.stdout + completed.stderr)[-2000:]}"
                )
        else:
            prefix = f"/volume/lanes/{lane['lane_id']}/"
            if not all(
                value.startswith(prefix)
                for value in (worktree, cache, lane["result_path"])
            ):
                raise WorkerError("proof lane path escapes the managed volume")
            _docker(
                *_runtime_argv(
                    run["lock"], run["volume"], "mkdir", "-p", cache, result_parent
                )
            )
            _git(run, "worktree", "add", "--detach", worktree, lane["base_commit"])
    run["events"].append("proof_lanes:prepared")


def persist_lane_result(
    run: dict[str, Any], lane: dict[str, Any], result: dict[str, Any]
) -> None:
    """Write one hash-only lane result without exposing its candidate patch."""
    raw = _canonical_bytes(result) + b"\n"
    path = lane["result_path"]
    project = Path(run["project_dir"])
    if project.is_dir():
        destination = Path(path)
        root = (Path(run["run_root"]) / "lanes" / lane["lane_id"]).resolve()
        if not destination.resolve().is_relative_to(root):
            raise WorkerError("proof lane result path escapes the run")
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(raw)
        os.replace(temporary, destination)
        return
    if not path.startswith(f"/volume/lanes/{lane['lane_id']}/"):
        raise WorkerError("proof lane result path escapes the managed volume")
    _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "sh",
            "-eu",
            "-c",
            'temporary="$1.tmp"; cat > "$temporary"; mv "$temporary" "$1"',
            "sh",
            path,
        ),
        input_bytes=raw,
    )


def run_probes(run: dict[str, Any]) -> tuple[bytes, bytes]:
    """Run both probes in runsc and export only their raw evidence bytes."""
    lock = run["lock"]
    rust_output = "/volume/evidence/probe-rust.json"
    aeneas_output = "/volume/evidence/probe-aeneas.json"
    _docker(
        *_runtime_argv(
            lock,
            run["volume"],
            "probe-rust",
            "extract",
            "/volume/work/project",
            "--with-locations",
            "--with-public-api",
            "--auto-install",
            "-o",
            rust_output,
        )
    )
    rust_raw = _docker(
        *_runtime_argv(lock, run["volume"], "cat", rust_output)
    ).stdout
    manifest = json.loads(
        _docker(
            *_runtime_argv(lock, run["volume"], "cat", "/volume/work/project/autofv.json")
        ).stdout
    )
    bridge = _bridge(rust_raw, manifest)
    _docker(
        *_runtime_argv(
            lock,
            run["volume"],
            "sh",
            "-c",
            "umask 077; cat > /volume/work/project/functions.json",
        ),
        input_bytes=bridge,
    )
    _docker(
        *_runtime_argv(
            lock,
            run["volume"],
            "probe-aeneas",
            "extract",
            "/volume/work/project",
            "--with-public-api",
            "-o",
            aeneas_output,
        )
    )
    aeneas_raw = _docker(
        *_runtime_argv(lock, run["volume"], "cat", aeneas_output)
    ).stdout
    evidence = Path(run["evidence_dir"])
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "probe-rust.json").write_bytes(rust_raw)
    (evidence / "probe-aeneas.json").write_bytes(aeneas_raw)
    run["events"].extend(("probe_rust", "probe_aeneas"))
    return rust_raw, aeneas_raw


def proxy_round(run: dict[str, Any], request: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Call only the launcher-selected fixed route from the runsc worker."""
    base = os.environ.get("AUTOFV_PROXY_BASE")
    token = os.environ.get("AUTOFV_RUN_TOKEN")
    if not base or not token:
        raise WorkerError("trusted proxy identity is not configured")
    route = run["lock"]["fixed_proxy"]
    url = base.rstrip("/") + route["path"]
    outbound = urllib.request.Request(
        url,
        data=_canonical_bytes(request),
        method=route["method"],
        headers={"Content-Type": "application/json", "X-AutoFV-Run-Token": token},
    )
    try:
        with urllib.request.urlopen(outbound, timeout=30) as reply:
            body = json.load(reply)
    except Exception as exc:
        raise WorkerError("fixed proxy request failed") from exc
    if not isinstance(body, dict) or set(body) != {"response", "receipt"}:
        raise WorkerError("fixed proxy returned an invalid envelope")
    return body["response"], body["receipt"]


def check_contract_feasibility(
    run: dict[str, Any], statements: list[str]
) -> dict[str, Any]:
    """Try the V1 diamond consumer proof against provisional statements."""
    source = (
        "import Diamond.Top\n\n"
        + "\n".join(f"{statement} := by sorry" for statement in statements)
        + "\n\nexample (input : Nat) : Diamond.top input = input * 3 + 1 := by\n"
        "  rw [Diamond.top, Diamond.left_spec, Diamond.right_spec]\n"
        "  simp [Nat.succ_eq_add_one, Nat.mul_succ, Nat.add_assoc, "
        "Nat.add_comm, Nat.add_left_comm]\n"
    )
    completed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "sh",
            "-c",
            "lake env lean --stdin 2>&1; code=$?; "
            "printf '\\nAUTOFV_FEASIBILITY_EXIT=%s\\n' \"$code\"",
        ),
        input_bytes=source.encode("utf-8"),
    )
    marker = b"\nAUTOFV_FEASIBILITY_EXIT="
    if marker not in completed.stdout:
        raise WorkerError("provisional consumer check returned no exit marker")
    diagnostic, raw_status = completed.stdout.rsplit(marker, 1)
    try:
        exit_code = int(raw_status.strip())
    except ValueError as exc:
        raise WorkerError("provisional consumer check returned an invalid status") from exc
    text = diagnostic.decode("utf-8", "replace")[-4000:]
    return {
        "status": "passed" if exit_code == 0 else "failed",
        "reason": None if exit_code == 0 else "consumer_proof_failed",
        "diagnostic_sha256": _sha256(diagnostic),
        "diagnostic": text,
    }


def accept_candidate(
    run: dict[str, Any], candidate: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Apply one one-file candidate and advance canonical state only after gates."""
    payload = candidate["payload"]
    path = payload["assigned_path"]
    patch = payload["patch"]
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or candidate["assigned_path"] != path:
        raise WorkerError("candidate scope is invalid")
    header = f"diff --git a/{path} b/{path}\n"
    if not patch.startswith(header) or patch.count("diff --git ") != 1:
        raise WorkerError("candidate must modify exactly its assigned file")
    if payload["base_commit"] != run["base_commit"]:
        raise WorkerError("candidate base commit mismatch")
    if _sha256(patch.encode("utf-8")) != payload["patch_sha256"]:
        raise WorkerError("candidate patch hash mismatch")
    if any(marker in patch for marker in ("\n+axiom ", "\n+sorry", "\n+unsafe ")):
        raise WorkerError("candidate violates the trust gate")
    raw_patch = patch.encode()
    _git(run, "apply", "--check", "-", input_bytes=raw_patch)
    _git(run, "apply", "-", input_bytes=raw_patch)
    _git(run, "add", "--", path)
    try:
        verify = manifest["verify"]
        _docker(*_runtime_argv(run["lock"], run["volume"], *verify))
        _docker(
            *_runtime_argv(
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
    except WorkerError:
        _git(run, "apply", "--reverse", "-", input_bytes=raw_patch)
        _git(run, "add", "--", path)
        raise
    commit = _git(run, "rev-parse", "HEAD").decode().strip()
    tree = _git(run, "archive", "--format=tar", "HEAD")
    run["events"].append(f"accepted:{path}")
    return {
        "accepted_commit": commit,
        "accepted_tree_sha256": _sha256(tree),
        "checks": [
            "assigned_path_scope",
            "base_commit",
            "patch_sha256",
            "patch_applies",
            "forbidden_source_markers",
            "configured_build",
        ],
    }


def persist_result(run: dict[str, Any], result: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Atomically persist the public result and initial L0 receipt."""
    root = Path(run["run_root"])
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    for path, value in ((root / "result.json", result), (evidence / "l0.json", receipt)):
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(_canonical_bytes(value) + b"\n")
        os.replace(temporary, path)


def export_accepted(run: dict[str, Any]) -> bytes:
    """Return the exact accepted Git tree, without worker caches or metadata."""
    return _git(run, "archive", "--format=tar", "HEAD")


def inspect_resume_state(
    run: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Verify the managed Git HEAD before the controller trusts resumed state."""
    try:
        status = _git(run, "status", "--porcelain").decode().strip()
        if status:
            return {"valid": False, "dirty": True, "reason": "working tree changed"}
        _docker(*_runtime_argv(run["lock"], run["volume"], *manifest["verify"]))
        commit = _git(run, "rev-parse", "HEAD").decode().strip()
        tree = _git(run, "archive", "--format=tar", "HEAD")
    except WorkerError as exc:
        return {"valid": False, "dirty": None, "reason": str(exc)[:1000]}
    return {
        "valid": True,
        "dirty": False,
        "accepted_commit": commit,
        "accepted_tree_sha256": _sha256(tree),
    }


def restore_accepted(
    run: dict[str, Any], accepted: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Restore only the disposable managed project to an exact accepted commit."""
    commit = accepted.get("accepted_commit")
    tree_sha256 = accepted.get("accepted_tree_sha256")
    if (
        not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or not isinstance(tree_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", tree_sha256) is None
    ):
        raise WorkerError("accepted checkpoint identity is invalid")
    _git(run, "reset", "--hard", commit)
    _git(run, "clean", "-ffd")
    return inspect_resume_state(run, manifest)


def read_project_file(run: dict[str, Any], relative_path: str) -> bytes:
    """Read one selected source file from either a test seam or the managed volume."""
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts:
        raise WorkerError("selected source path is unsafe")
    project = Path(run["project_dir"])
    if project.is_dir():
        resolved = (project / relative_path).resolve(strict=True)
        if not resolved.is_relative_to(project.resolve(strict=True)) or not resolved.is_file():
            raise WorkerError("selected source path escapes the project")
        return resolved.read_bytes()
    return _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "cat",
            f"/volume/work/project/{path.as_posix()}",
        )
    ).stdout
