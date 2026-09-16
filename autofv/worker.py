"""Stable worker operations for sealed experiments."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import worker_runtime as _runtime
from .worker_artifacts import (
    dispose_run,
    export_accepted,
    export_run,
    inspect_resume_state,
    read_project_file,
    restore_accepted,
    scan_artifacts,
    scan_retained_state,
)
from .worker_proxy import (
    proxy_round,
    run_egress_matrix,
    run_proxy_policy_matrix,
    verify_egress,
)


AGENT_TEMPLATE_VM = _runtime.AGENT_TEMPLATE_VM
AGENT_UID = _runtime.AGENT_UID
AGENT_VM = _runtime.AGENT_VM
SKIP_NAMES = _runtime.SKIP_NAMES
SKIP_PARTS = _runtime.SKIP_PARTS
WorkerError = _runtime.WorkerError
claim_worker = _runtime.claim_worker
hash_tree = _runtime.hash_tree
inspect_lima_instance = _runtime.inspect_lima_instance
inspect_scored_container = _runtime.inspect_scored_container
inspect_worker = _runtime.inspect_worker
lima_host_address = _runtime.lima_host_address


def control_manifest(
    lock: dict[str, Any],
) -> tuple[dict[str, Any], list[tuple[str, bytes, int]]]:
    """Build the exact controller bundle manifest and file list."""
    return _runtime._control_manifest(lock)


def force_destroy_worker(run: dict[str, Any]) -> None:
    """Delete the run-owned disposable worker after normal disposal fails."""
    _runtime._destroy_worker(run)


def verification_repository(
    run: dict[str, Any], expected_commit: str
) -> bytes | None:
    """Export the repository only when HEAD is the accepted commit."""
    head = _runtime._git(run, "rev-parse", "HEAD").decode().strip()
    if head != expected_commit:
        return None
    return _runtime._git(run, "bundle", "create", "-", "HEAD")


def prepare_run(
    target: Path, manifest: dict[str, Any], lock: dict[str, Any]
) -> dict[str, Any]:
    """Copy target/control bytes into a fresh named volume without a bind mount."""
    archive, control_manifest, snapshot_sha256 = _runtime._seed_archive(target, lock)
    run_id = _runtime._new_run_id()
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
        "manifest_sha256": _runtime._sha256(_runtime._canonical_bytes(manifest)),
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": control_manifest["bundle_sha256"],
        "native_decide_policy": lock["native_decide_policy"]["selection"],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "fixed_proxy_sha256": _runtime._sha256(
            _runtime._canonical_bytes(lock["fixed_proxy"])
        ),
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
    worker_created = False
    try:
        _runtime._create_worker(run)
        worker_created = True
        inventory = _runtime.inspect_worker(lock, run_id=run_id)
        run["worker_inventory"] = inventory
        run["worker_inventory_sha256"] = inventory["inventory_sha256"]
        run["agent_worker_id"] = f"lima:{AGENT_VM}:{inventory['machine_id']}"
        evidence = Path(run["evidence_dir"])
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "worker-inventory.json").write_bytes(
            _runtime._canonical_bytes(inventory) + b"\n"
        )
        _runtime.claim_worker(run)
        if _runtime._docker("volume", "inspect", volume, check=False).returncode == 0:
            raise WorkerError("run volume identity already exists")
        _runtime._docker("volume", "create", *_runtime._labels(run, "volume"), volume)
        if not _runtime._resource_matches("volume", volume, run):
            raise WorkerError("run volume claim mismatch")
        _runtime._docker(
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
            _runtime._docker(*_runtime._runtime_argv(lock, volume, *command))
            if "runsc_started" not in run["events"]:
                run["events"].append("runsc_started")
        _runtime._docker(
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
        run["base_commit"] = _runtime._git(run, "rev-parse", "HEAD").decode().strip()
        run["accepted"] = {
            "accepted_commit": run["base_commit"],
            "accepted_tree_sha256": _runtime._sha256(
                _runtime._git(run, "archive", "--format=tar", "HEAD")
            ),
            "checks": ["sealed_baseline"],
        }
        run["scored_container_receipt"] = _runtime.inspect_scored_container(run)
    except BaseException as exc:
        if worker_created:
            try:
                _runtime._destroy_worker(run)
            except WorkerError as cleanup_exc:
                raise WorkerError(
                    f"{exc}; preparation cleanup failed: {cleanup_exc}", run=run
                ) from exc
        if isinstance(exc, WorkerError):
            exc.run = run
        if isinstance(exc, KeyboardInterrupt):
            run["preparation_interrupted"] = True
            raise WorkerError(
                "controller interrupted during worker preparation", run=run
            ) from exc
        raise
    return run


def probe_bridge(rust_raw: bytes, manifest: dict[str, Any]) -> bytes:
    """Map fresh Rust atoms to the Lean names consumed by probe-aeneas."""
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
    return (
        _runtime._canonical_bytes(
            {"functions": sorted(records, key=lambda item: item["lean_name"])}
        )
        + b"\n"
    )


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
                detail = (completed.stdout + completed.stderr)[-2000:]
                raise WorkerError(f"proof lane worktree failed: {detail}")
        else:
            prefix = f"/volume/lanes/{lane['lane_id']}/"
            if not all(
                value.startswith(prefix)
                for value in (worktree, cache, lane["result_path"])
            ):
                raise WorkerError("proof lane path escapes the managed volume")
            _runtime._docker(
                *_runtime._runtime_argv(
                    run["lock"], run["volume"], "mkdir", "-p", cache, result_parent
                )
            )
            _runtime._git(
                run, "worktree", "add", "--detach", worktree, lane["base_commit"]
            )
    run["events"].append("proof_lanes:prepared")


def persist_lane_result(
    run: dict[str, Any], lane: dict[str, Any], result: dict[str, Any]
) -> None:
    """Write one hash-only lane result without exposing its candidate patch."""
    raw = _runtime._canonical_bytes(result) + b"\n"
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
    _runtime._docker(
        *_runtime._runtime_argv(
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


def _lane_path(lane: dict[str, Any], relative: str, allowed: set[str]) -> tuple[str, str]:
    """Validate a worker-owned lane path without consulting a host mount."""
    pure = PurePosixPath(relative) if isinstance(relative, str) else None
    root = lane.get("worktree_path")
    if (
        pure is None
        or pure.is_absolute()
        or pure.as_posix() != relative
        or any(part in {"", ".", ".."} for part in pure.parts)
        or relative not in allowed
        or not isinstance(root, str)
    ):
        raise WorkerError("lane path is outside its allowlist")
    return root, f"{root}/{relative}"


def _local_lane_file(root_text: str, relative: str) -> Path:
    """Resolve one simulation-lane file while rejecting every symlink hop."""
    root = Path(root_text)
    if root.is_symlink():
        raise WorkerError("lane root must not be a symlink")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise WorkerError("lane root is unavailable") from exc
    current = resolved_root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            raise WorkerError("lane path must not contain a symlink")
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise WorkerError("lane path is unavailable") from exc
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise WorkerError("lane path escapes its root or is not a file")
    return resolved


def read_lane_file(
    run: dict[str, Any], lane: dict[str, Any], relative: str, allowed_paths: list[str]
) -> str:
    """Read one allowlisted private-lane file through the worker boundary."""
    root, sealed_path = _lane_path(lane, relative, set(allowed_paths))
    if run.get("execution_tier") == "simulation":
        return _local_lane_file(root, relative).read_text(encoding="utf-8")
    if not root.startswith(f"/volume/lanes/{lane.get('lane_id')}/"):
        raise WorkerError("lane root escapes the managed volume")
    completed = _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            (
                "import os,sys; root=os.path.realpath(sys.argv[1]); "
                "path=os.path.realpath(os.path.join(root,sys.argv[2])); "
                "assert os.path.commonpath((root,path))==root; "
                "assert not any(os.path.islink(os.path.join(root,*sys.argv[2].split('/')[:i])) "
                "for i in range(1,len(sys.argv[2].split('/'))+1)); "
                "sys.stdout.buffer.write(open(path,'rb').read())"
            ),
            root,
            relative,
        )
    )
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkerError("lane file is not UTF-8") from exc


def search_lane_files(
    run: dict[str, Any], lane: dict[str, Any], query: str, allowed_paths: list[str]
) -> str:
    """Search only allowlisted lane sources using worker-owned reads."""
    matches: list[str] = []
    for relative in sorted(set(allowed_paths)):
        text = read_lane_file(run, lane, relative, allowed_paths)
        for number, line in enumerate(text.splitlines(), 1):
            if query in line:
                matches.append(f"{relative}:{number}:{line}")
    return "\n".join(matches)


def edit_lane_file(
    run: dict[str, Any], lane: dict[str, Any], patch: str
) -> str:
    """Apply a validated one-file patch only inside its private lane."""
    validate_assigned_patch(lane["assigned_path"], patch)
    raw = patch.encode("utf-8")
    root = lane["worktree_path"]
    if run.get("execution_tier") == "simulation":
        _local_lane_file(root, lane["assigned_path"])
        for check in (True, False):
            command = ["git", "apply"]
            if check:
                command.append("--check")
            command.append("-")
            completed = subprocess.run(
                command, cwd=root, input=raw, capture_output=True
            )
            if completed.returncode:
                raise WorkerError(
                    "private lane patch failed: "
                    + (completed.stdout + completed.stderr).decode("utf-8", "replace")[-2000:]
                )
    else:
        if not root.startswith(f"/volume/lanes/{lane.get('lane_id')}/"):
            raise WorkerError("lane root escapes the managed volume")
        for check in (True, False):
            argv = ["git", "-C", root, "apply"]
            if check:
                argv.append("--check")
            argv.append("-")
            _runtime._docker(
                *_runtime._runtime_argv(run["lock"], run["volume"], *argv),
                input_bytes=raw,
            )
    return f"applied:{_runtime._sha256(raw)}"


def check_lane(
    run: dict[str, Any], lane: dict[str, Any], manifest: dict[str, Any]
) -> str:
    """Return an actual worker diagnostic, honestly classified by execution tier."""
    root = lane["worktree_path"]
    if run.get("execution_tier") == "simulation":
        completed = subprocess.run(
            ("git", "diff", "--check"), cwd=root, capture_output=True, text=True
        )
        diagnostic = (completed.stdout + completed.stderr)[-4000:]
        return (
            f"simulation_static:exit={completed.returncode}:"
            f"diagnostic_sha256={_runtime._sha256(diagnostic.encode())}"
        )
    if not root.startswith(f"/volume/lanes/{lane.get('lane_id')}/"):
        raise WorkerError("lane root escapes the managed volume")
    verify = manifest.get("verify")
    if not isinstance(verify, list) or not verify:
        raise WorkerError("lane diagnostic command is unavailable")
    completed = _runtime._docker(
        *_runtime._runtime_argv(
            run["lock"],
            run["volume"],
            "sh",
            "-eu",
            "-c",
            'cd "$1"; shift; "$@"',
            "sh",
            root,
            *verify,
        ),
        check=False,
    )
    diagnostic = (completed.stdout + completed.stderr)[-4000:]
    return (
        f"sealed_runtime:exit={completed.returncode}:"
        f"diagnostic_sha256={_runtime._sha256(diagnostic)}:"
        + diagnostic.decode("utf-8", "replace")
    )


def run_probes(run: dict[str, Any]) -> tuple[bytes, bytes]:
    """Run both probes in runsc and export only their raw evidence bytes."""
    lock = run["lock"]
    rust_output = "/volume/evidence/probe-rust.json"
    aeneas_output = "/volume/evidence/probe-aeneas.json"
    _runtime._docker(
        *_runtime._runtime_argv(
            lock,
            run["volume"],
            "probe-rust",
            "extract",
            "/volume/work/project",
            "--with-locations",
            "--with-public-api",
            "-o",
            rust_output,
        )
    )
    rust_raw = _runtime._docker(
        *_runtime._runtime_argv(lock, run["volume"], "cat", rust_output)
    ).stdout
    manifest = json.loads(
        _runtime._docker(
            *_runtime._runtime_argv(
                lock, run["volume"], "cat", "/volume/work/project/autofv.json"
            )
        ).stdout
    )
    bridge = probe_bridge(rust_raw, manifest)
    _runtime._docker(
        *_runtime._runtime_argv(
            lock,
            run["volume"],
            "sh",
            "-c",
            "umask 077; cat > /volume/work/project/functions.json",
        ),
        input_bytes=bridge,
    )
    _runtime._docker(
        *_runtime._runtime_argv(
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
    aeneas_raw = _runtime._docker(
        *_runtime._runtime_argv(lock, run["volume"], "cat", aeneas_output)
    ).stdout
    evidence = Path(run["evidence_dir"])
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "probe-rust.json").write_bytes(rust_raw)
    (evidence / "probe-aeneas.json").write_bytes(aeneas_raw)
    run["events"].extend(("probe_rust", "probe_aeneas"))
    return rust_raw, aeneas_raw
def contract_feasibility_request(
    graph: dict[str, Any], records_by_node: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Bind provisional statements to their real graph consumers and modules."""
    selected = graph.get("selected_nodes")
    if not isinstance(selected, list) or set(records_by_node) != set(selected):
        raise WorkerError("contract feasibility nodes mismatch")
    modules = sorted(
        {
            str(PurePosixPath(path).with_suffix("")).replace("/", ".")
            for path in graph.get("source_paths", {}).values()
            if isinstance(path, str) and path.endswith(".lean")
        }
    )
    obligations = []
    for node in selected:
        record = records_by_node[node]
        consumers = sorted(
            consumer
            for consumer, dependency in graph.get("term_dependencies", [])
            if dependency == node
        )
        obligations.append(
            {
                "node": node,
                "declaration": record.get("declaration"),
                "canon": record.get("canon"),
                "model_fingerprint": record.get("model_fingerprint"),
                "immediate_consumers": [
                    {
                        "node": consumer,
                        "declaration": records_by_node[consumer].get("declaration"),
                        "canon": records_by_node[consumer].get("canon"),
                        "model_fingerprint": records_by_node[consumer].get(
                            "model_fingerprint"
                        ),
                    }
                    for consumer in consumers
                ],
            }
        )
    body = {
        "schema": "autofv-contract-feasibility/v1",
        "graph_sha256": graph.get("graph_sha256"),
        "modules": modules,
        "obligations": obligations,
    }
    return {**body, "request_sha256": _runtime._sha256(_runtime._canonical_bytes(body))}


def check_contract_feasibility(
    run: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    """Compile graph-derived provisional statements in the managed worker."""
    if not isinstance(request, dict) or request.get("schema") != "autofv-contract-feasibility/v1":
        raise WorkerError("contract feasibility request is invalid")
    body = {key: value for key, value in request.items() if key != "request_sha256"}
    if request.get("request_sha256") != _runtime._sha256(_runtime._canonical_bytes(body)):
        raise WorkerError("contract feasibility request hash mismatch")
    modules = request.get("modules")
    obligations = request.get("obligations")
    if (
        not isinstance(modules, list)
        or not modules
        or any(not isinstance(module, str) or not module for module in modules)
        or not isinstance(obligations, list)
        or not obligations
    ):
        raise WorkerError("contract feasibility request is incomplete")
    statements = []
    for item in obligations:
        if not isinstance(item, dict) or not isinstance(item.get("canon"), str):
            raise WorkerError("contract feasibility obligation is invalid")
        # A supplied declaration already exists in its imported source. Only
        # provisional helper statements are restated in this isolated check.
        if item.get("immediate_consumers"):
            statements.append(item["canon"])
    source = (
        "\n".join(f"import {module}" for module in modules)
        + "\n\n"
        + "\n".join(f"{statement} := by sorry" for statement in statements)
        + "\n"
    )
    completed = _runtime._docker(
        *_runtime._runtime_argv(
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
        raise WorkerError(
            "provisional consumer check returned an invalid status"
        ) from exc
    text = diagnostic.decode("utf-8", "replace")[-4000:]
    return {
        "status": "passed" if exit_code == 0 else "failed",
        "reason": None if exit_code == 0 else "consumer_proof_failed",
        "diagnostic_sha256": _runtime._sha256(diagnostic),
        "diagnostic": text,
        "request_sha256": request["request_sha256"],
    }


def validate_assigned_patch(assigned_path: str, patch: str) -> None:
    """Reject a patch unless it names exactly one safe assigned file."""
    if not isinstance(assigned_path, str) or not isinstance(patch, str):
        raise WorkerError("candidate scope is invalid")
    pure = PurePosixPath(assigned_path)
    if (
        not assigned_path
        or pure.is_absolute()
        or "\\" in assigned_path
        or pure.as_posix() != assigned_path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise WorkerError("candidate scope is invalid")
    header = f"diff --git a/{assigned_path} b/{assigned_path}\n"
    if not patch.startswith(header) or patch.count("diff --git ") != 1:
        raise WorkerError("candidate must modify exactly its assigned file")
    lines = patch.splitlines()
    if any(
        line.startswith("--- ") and line != f"--- a/{assigned_path}"
        or line.startswith("+++ ") and line != f"+++ b/{assigned_path}"
        or line.startswith(("rename from ", "rename to ", "copy from ", "copy to "))
        for line in lines
    ):
        raise WorkerError("candidate must modify exactly its assigned file")


def accept_candidate(
    run: dict[str, Any], candidate: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Apply one one-file candidate and advance canonical state only after gates."""
    payload = candidate["payload"]
    path = payload["assigned_path"]
    patch = payload["patch"]
    if candidate["assigned_path"] != path:
        raise WorkerError("candidate scope is invalid")
    validate_assigned_patch(path, patch)
    if payload["base_commit"] != run["base_commit"]:
        raise WorkerError("candidate base commit mismatch")
    if _runtime._sha256(patch.encode("utf-8")) != payload["patch_sha256"]:
        raise WorkerError("candidate patch hash mismatch")
    if any(marker in patch for marker in ("\n+axiom ", "\n+sorry", "\n+unsafe ")):
        raise WorkerError("candidate violates the trust gate")
    raw_patch = patch.encode()
    if run.get("execution_tier") == "simulation":
        project = Path(run["project_dir"])
        for check in (True, False):
            command = ["git", "apply"]
            if check:
                command.append("--check")
            command.append("-")
            completed = subprocess.run(
                command, cwd=project, input=raw_patch, capture_output=True
            )
            if completed.returncode:
                raise WorkerError(
                    "simulation candidate patch failed: "
                    + (completed.stdout + completed.stderr).decode(
                        "utf-8", "replace"
                    )[-2000:]
                )
        subprocess.run(("git", "add", "--", path), cwd=project, check=True)
        structural = subprocess.run(
            ("git", "diff", "--cached", "--check"),
            cwd=project,
            capture_output=True,
        )
        if structural.returncode:
            subprocess.run(
                ("git", "apply", "--reverse", "-"),
                cwd=project,
                input=raw_patch,
                check=True,
            )
            raise WorkerError("simulation static candidate check failed")
        committed = subprocess.run(
            (
                "git",
                "-c",
                "user.name=AutoFV",
                "-c",
                "user.email=autofv@invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                candidate["request_id"],
            ),
            cwd=project,
            capture_output=True,
        )
        if committed.returncode:
            raise WorkerError(
                "simulation candidate commit failed: "
                + (committed.stdout + committed.stderr).decode("utf-8", "replace")[-2000:]
            )
        commit = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=project,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tree = subprocess.run(
            ("git", "archive", "--format=tar", "HEAD"),
            cwd=project,
            check=True,
            capture_output=True,
        ).stdout
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
                "simulation_static_diff_check",
            ],
            "evidence_classification": "simulation_static",
        }
    _runtime._git(run, "apply", "--check", "-", input_bytes=raw_patch)
    _runtime._git(run, "apply", "-", input_bytes=raw_patch)
    _runtime._git(run, "add", "--", path)
    try:
        verify = manifest["verify"]
        _runtime._docker(*_runtime._runtime_argv(run["lock"], run["volume"], *verify))
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
    except BaseException:
        _runtime._git(run, "apply", "--reverse", "-", input_bytes=raw_patch)
        _runtime._git(run, "add", "--", path)
        raise
    commit = _runtime._git(run, "rev-parse", "HEAD").decode().strip()
    tree = _runtime._git(run, "archive", "--format=tar", "HEAD")
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
            "configured_build",
        ],
    }
