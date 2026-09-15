"""Retained-state scanning, export, disposal, and restart recovery."""

from __future__ import annotations

import io
import hashlib
import json
import os
import re
import secrets
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .worker_runtime import (
    AGENT_VM,
    CLAIM_CONTAINER,
    SKIP_NAMES,
    SKIP_PARTS,
    WorkerError,
    _add_bytes,
    _atomic_write,
    _canonical_bytes,
    _control_manifest,
    _create_worker,
    _destroy_worker,
    _docker,
    _git,
    _json_output,
    _labels,
    _lima,
    _owned_worker,
    _runtime_argv,
    _sha256,
    claim_worker,
    inspect_lima_instance,
    inspect_scored_container,
    inspect_worker,
)


SHA256 = re.compile(r"[0-9a-f]{64}")
SCANNED_SURFACES = (
    "environment",
    "filesystem",
    "log",
    "transcript",
    "state",
    "result",
    "export",
)

_VOLUME_SCAN_PROGRAM = r"""
import hashlib
import json
import os
import stat
import sys

request = json.load(sys.stdin)
markers = [bytes.fromhex(value) for value in request["markers"]]
overlap = max(map(len, markers), default=1) - 1
roots = (
    ("/volume/work", "filesystem"),
    ("/volume/accepted", "filesystem"),
    ("/volume/autofv-control", "filesystem"),
    ("/volume/logs", "log"),
    ("/volume/evidence", "transcript"),
    ("/volume/lanes", "state"),
)
hits = set()
receipts = []

def failed(error):
    raise error

for root, surface in roots:
    manifest = hashlib.sha256()
    entries = []
    file_count = byte_count = 0
    for current, directories, names in os.walk(root, topdown=True, onerror=failed):
        directories.sort()
        names.sort()
        for name in directories:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root)
            encoded_path = relative.encode("utf-8", "surrogateescape")
            if any(marker in encoded_path for marker in markers):
                hits.add(surface)
            status = os.lstat(path)
            kind = "directory" if stat.S_ISDIR(status.st_mode) else "non-regular"
            entry = json.dumps([relative, kind], ensure_ascii=True)
            entries.append(entry.encode())
        for name in names:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root)
            encoded_path = relative.encode("utf-8", "surrogateescape")
            if any(marker in encoded_path for marker in markers):
                hits.add(surface)
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode):
                entry = json.dumps([relative, "non-regular"], ensure_ascii=True)
                entries.append(entry.encode())
                continue
            digest = hashlib.sha256()
            tail = b""
            size = 0
            with open(path, "rb") as source:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    digest.update(chunk)
                    sample = tail + chunk
                    if any(marker in sample for marker in markers):
                        hits.add(surface)
                    tail = sample[-overlap:] if overlap else b""
            after = os.lstat(path)
            identity = ("st_mode", "st_ino", "st_size", "st_mtime_ns")
            if any(getattr(before, field) != getattr(after, field) for field in identity):
                raise RuntimeError("worker file changed during retained-state scan")
            file_count += 1
            byte_count += size
            entry = json.dumps([relative, size, digest.hexdigest()], ensure_ascii=True)
            entries.append(entry.encode())
    for entry in sorted(entries):
        manifest.update(entry + b"\n")
    receipts.append(
        {
            "root": root,
            "surface": surface,
            "files": file_count,
            "bytes": byte_count,
            "manifest_sha256": manifest.hexdigest(),
        }
    )
print(
    json.dumps(
        {
            "schema": "autofv-worker-filesystem-scan/v1",
            "roots": receipts,
            "hit_surfaces": sorted(hits),
            "clean": not hits,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""
_VOLUME_ROOTS = (
    ("work", "filesystem"),
    ("accepted", "filesystem"),
    ("autofv-control", "filesystem"),
    ("logs", "log"),
    ("evidence", "transcript"),
    ("lanes", "state"),
)


def _safe_tar(
    raw: bytes,
    label: str,
    *,
    forbidden: tuple[bytes, ...] = (),
) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            seen = set()
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if forbidden and _marker_hits({member.name: b""}, forbidden):
                    raise WorkerError(
                        "forbidden material found in trusted worker-volume scan"
                    )
                if (
                    member.name in seen
                    or path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not (member.isfile() or member.isdir())
                ):
                    raise WorkerError(f"{label} contains an unsafe member")
                seen.add(member.name)
    except tarfile.TarError as exc:
        raise WorkerError(f"{label} is not a valid archive") from exc


def _forbidden_markers(markers: Iterable[bytes | str]) -> tuple[bytes, ...]:
    forbidden = [
        b"tests/fixtures/model-proxy/diamond-responses.json",
        b"diamond-responses.json",
        b"diamond-reference",
        b"tests/fixtures/diamond-reference",
    ]
    for marker in markers:
        if isinstance(marker, str):
            raw = marker.encode("utf-8")
        elif isinstance(marker, bytes):
            raw = marker
        else:
            raise WorkerError("artifact scan marker must be bytes or text")
        if not raw:
            raise WorkerError("artifact scan marker must not be empty")
        forbidden.append(raw)
    return tuple(dict.fromkeys(forbidden))


def _marker_hits(
    artifacts: dict[str, bytes], forbidden: tuple[bytes, ...]
) -> bool:
    for name, raw in artifacts.items():
        if not isinstance(name, str) or not isinstance(raw, bytes):
            raise WorkerError("artifact scan input is invalid")
        encoded_name = name.encode("utf-8", "surrogateescape")
        if any(marker in encoded_name or marker in raw for marker in forbidden):
            return True
    return False


def scan_artifacts(
    artifacts: dict[str, bytes], markers: Iterable[bytes | str] = ()
) -> dict[str, Any]:
    """Reject provider secrets, fixture programs, and hidden references."""
    forbidden = _forbidden_markers(markers)
    if _marker_hits(artifacts, forbidden):
        raise WorkerError("forbidden material found in export artifacts")
    body = {
        "schema": "autofv-artifact-scan/v1",
        "artifacts": sorted(artifacts),
        "artifact_sha256": {
            name: _sha256(raw) for name, raw in sorted(artifacts.items())
        },
        "marker_count": len(forbidden),
        "clean": True,
    }
    return {**body, "scan_sha256": _sha256(_canonical_bytes(body))}


def _retained_markers(run: dict[str, Any]) -> tuple[bytes | str, ...]:
    """Return markers safe to pass into the isolated worker scanner."""
    return tuple(run.get("artifact_scan_markers", ()))


def _worker_environment_artifacts(run: dict[str, Any]) -> dict[str, bytes]:
    artifacts = {"lima": _lima("env").stdout}
    names = [CLAIM_CONTAINER]
    if run.get("proxy_relay"):
        names.append(run["proxy_relay"])
    for name in names:
        values = _json_output(
            _docker("container", "inspect", name), f"worker environment {name}"
        )
        try:
            environment = values[0]["Config"]["Env"] or []
        except (KeyError, IndexError, TypeError) as exc:
            raise WorkerError("worker container environment is incomplete") from exc
        if not isinstance(environment, list) or any(
            not isinstance(value, str) for value in environment
        ):
            raise WorkerError("worker container environment is invalid")
        artifacts[name] = "\n".join(sorted(environment)).encode("utf-8")
    return artifacts


def _scan_worker_volume(
    run: dict[str, Any], forbidden: tuple[bytes, ...]
) -> dict[str, Any]:
    completed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            _VOLUME_SCAN_PROGRAM,
        ),
        input_bytes=_canonical_bytes({"markers": [marker.hex() for marker in forbidden]}),
    )
    value = _json_output(completed, "worker filesystem scan")
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "roots",
        "hit_surfaces",
        "clean",
    }:
        raise WorkerError("worker filesystem scan receipt is invalid")
    expected_roots = [
        ("/volume/work", "filesystem"),
        ("/volume/accepted", "filesystem"),
        ("/volume/autofv-control", "filesystem"),
        ("/volume/logs", "log"),
        ("/volume/evidence", "transcript"),
        ("/volume/lanes", "state"),
    ]
    roots = value["roots"]
    if (
        value["schema"] != "autofv-worker-filesystem-scan/v1"
        or not isinstance(roots, list)
        or any(not isinstance(item, dict) for item in roots)
        or [(item.get("root"), item.get("surface")) for item in roots]
        != expected_roots
        or not isinstance(value["hit_surfaces"], list)
        or value["hit_surfaces"] != sorted(set(value["hit_surfaces"]))
        or any(surface not in SCANNED_SURFACES for surface in value["hit_surfaces"])
        or type(value["clean"]) is not bool
        or value["clean"] != (not value["hit_surfaces"])
    ):
        raise WorkerError("worker filesystem scan receipt mismatch")
    for item in roots:
        if (
            not isinstance(item, dict)
            or set(item) != {
                "root",
                "surface",
                "files",
                "bytes",
                "manifest_sha256",
            }
            or type(item["files"]) is not int
            or item["files"] < 0
            or type(item["bytes"]) is not int
            or item["bytes"] < 0
            or not isinstance(item["manifest_sha256"], str)
            or SHA256.fullmatch(item["manifest_sha256"]) is None
        ):
            raise WorkerError("worker filesystem scan root receipt is invalid")
    body = dict(value)
    return {**body, "scan_sha256": _sha256(_canonical_bytes(body))}


def _trusted_worker_volume_scan(
    run: dict[str, Any],
    forbidden: tuple[bytes, ...],
    worker_scan: dict[str, Any],
) -> dict[str, Any]:
    """Stream the complete retained volume to the host and scan it there."""
    completed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "tar",
            "--create",
            "--file=-",
            "--directory=/volume",
            *(root for root, _surface in _VOLUME_ROOTS),
        )
    )
    archive_raw = completed.stdout
    _safe_tar(
        archive_raw,
        "trusted worker-volume scan",
        forbidden=forbidden,
    )
    expected = {
        item["root"].removeprefix("/volume/"): item
        for item in worker_scan["roots"]
    }
    receipts = []
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:*") as archive:
        members = archive.getmembers()
        present = {member.name.rstrip("/") for member in members if member.isdir()}
        for root, surface in _VOLUME_ROOTS:
            if root not in present:
                raise WorkerError("trusted worker-volume scan is incomplete")
            manifest = hashlib.sha256()
            entries: list[bytes] = []
            file_count = byte_count = 0
            prefix = root + "/"
            for member in sorted(members, key=lambda item: item.name):
                if not member.name.startswith(prefix):
                    continue
                relative = member.name[len(prefix):].rstrip("/")
                if not relative:
                    continue
                if member.isdir():
                    entries.append(
                        json.dumps(
                            [relative, "directory"], ensure_ascii=True
                        ).encode()
                    )
                    continue
                if not member.isfile():
                    raise WorkerError("trusted worker-volume scan is incomplete")
                source = archive.extractfile(member)
                if source is None:
                    raise WorkerError("trusted worker-volume scan is incomplete")
                raw = source.read()
                if len(raw) != member.size or _marker_hits(
                    {relative: raw}, forbidden
                ):
                    raise WorkerError(
                        "forbidden material found in trusted worker-volume scan"
                    )
                digest = hashlib.sha256(raw).hexdigest()
                entries.append(
                    json.dumps(
                        [relative, len(raw), digest], ensure_ascii=True
                    ).encode()
                )
                file_count += 1
                byte_count += len(raw)
            for entry in sorted(entries):
                manifest.update(entry + b"\n")
            receipt = {
                "root": f"/volume/{root}",
                "surface": surface,
                "files": file_count,
                "bytes": byte_count,
                "manifest_sha256": manifest.hexdigest(),
            }
            if receipt != expected.get(root):
                raise WorkerError("trusted worker-volume scan changed during export")
            receipts.append(receipt)
    body = {
        "schema": "autofv-trusted-worker-volume-scan/v1",
        "roots": receipts,
        "archive_sha256": _sha256(archive_raw),
        "clean": True,
    }
    return {**body, "scan_sha256": _sha256(_canonical_bytes(body))}


def _host_surface(name: str) -> str:
    lowered = name.lower()
    if name == "result.json":
        return "result"
    if "transcript" in lowered:
        return "transcript"
    if "log" in lowered:
        return "log"
    if name.startswith("checkpoints/"):
        return "state"
    return "filesystem"


def scan_retained_state(
    run: dict[str, Any],
    artifacts: dict[str, bytes],
    markers: Iterable[bytes | str] = (),
    *,
    trusted_markers: Iterable[bytes | str] = (),
) -> dict[str, Any]:
    """Scan retained state without disclosing provider secrets to the worker.

    ``trusted_markers`` are used only by controller-side scans. They must never
    enter a runsc argv, environment, or stdin payload.
    """
    markers = tuple(markers)
    trusted_markers = tuple(trusted_markers)
    provider_markers: tuple[bytes, ...] = ()
    if isinstance(run.get("provider_binding"), dict):
        from . import provider_config

        try:
            provider_markers = provider_config.secret_markers(run)
        except provider_config.ProviderConfigError as exc:
            raise WorkerError(
                "provider secrets are unavailable for artifact scan"
            ) from exc
    provider_set = set(provider_markers)
    worker_markers_list: list[bytes | str] = []
    for marker in markers:
        if isinstance(marker, str):
            raw_marker = marker.encode("utf-8")
        elif isinstance(marker, bytes):
            raw_marker = marker
        else:
            raise WorkerError("artifact scan marker must be bytes or text")
        if raw_marker not in provider_set:
            worker_markers_list.append(marker)
    worker_markers = tuple(worker_markers_list)
    trusted_markers = (*trusted_markers, *provider_markers)
    worker_forbidden = _forbidden_markers(worker_markers)
    trusted_forbidden = _forbidden_markers((*markers, *trusted_markers))
    hits: set[str] = set()

    environment = _worker_environment_artifacts(run)
    if _marker_hits(environment, trusted_forbidden):
        hits.add("environment")

    filesystem = _scan_worker_volume(run, worker_forbidden)
    hits.update(filesystem["hit_surfaces"])
    trusted_filesystem = (
        _trusted_worker_volume_scan(run, trusted_forbidden, filesystem)
        if provider_markers
        else None
    )

    state = {key: value for key, value in run.items() if key != "artifact_scan_markers"}
    try:
        state_raw = _canonical_bytes(state)
    except (TypeError, ValueError) as exc:
        raise WorkerError("controller run state is not canonical JSON") from exc
    if _marker_hits({"run.json": state_raw}, trusted_forbidden):
        hits.add("state")

    host = _host_artifacts(run)
    for name, raw in host.items():
        if _marker_hits({name: raw}, trusted_forbidden):
            hits.add(_host_surface(name))
    if _marker_hits(artifacts, trusted_forbidden):
        hits.add("export")

    if hits:
        ordered = [surface for surface in SCANNED_SURFACES if surface in hits]
        raise WorkerError(
            "forbidden material found in retained surfaces: " + ", ".join(ordered)
        )

    export = scan_artifacts(artifacts, (*markers, *trusted_markers))
    body = {
        "schema": "autofv-retained-state-scan/v1",
        "run_id": run["run_id"],
        "scanned_surfaces": list(SCANNED_SURFACES),
        "marker_count": len(trusted_forbidden),
        "environment_sha256": {
            name: _sha256(raw) for name, raw in sorted(environment.items())
        },
        "worker_filesystem": filesystem,
        "trusted_worker_filesystem": trusted_filesystem,
        "controller_state_sha256": _sha256(state_raw),
        "host_artifact_sha256": {
            name: _sha256(raw) for name, raw in sorted(host.items())
        },
        "export": export,
        "clean": True,
    }
    return {**body, "scan_sha256": _sha256(_canonical_bytes(body))}


def _host_artifacts(run: dict[str, Any]) -> dict[str, bytes]:
    root = Path(run["run_root"])
    artifacts: dict[str, bytes] = {}
    result = root / "result.json"
    if result.is_file():
        artifacts["result.json"] = result.read_bytes()
    for directory in ("evidence", "checkpoints"):
        source_root = root / directory
        if not source_root.exists():
            continue
        for source in sorted(source_root.rglob("*")):
            status = source.lstat()
            relative = source.relative_to(root).as_posix()
            if source.is_symlink():
                raise WorkerError(f"host artifact is not a regular file: {relative}")
            if source.is_dir():
                continue
            if not stat.S_ISREG(status.st_mode):
                raise WorkerError(f"host artifact is not a regular file: {relative}")
            artifacts[relative] = source.read_bytes()
    return artifacts


def _finalization_sequence(run: dict[str, Any]) -> int:
    sequence = int(run.get("finalization_sequence", 0)) + 1
    run["finalization_sequence"] = sequence
    return sequence


def _untracked_archive(run: dict[str, Any], names: list[str]) -> bytes:
    if not names:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w"):
            pass
        return stream.getvalue()
    raw_names = b"".join(name.encode("utf-8") + b"\0" for name in names)
    return _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "tar",
            "--create",
            "--file=-",
            "--null",
            "--verbatim-files-from",
            "--files-from=-",
        ),
        input_bytes=raw_names,
    ).stdout

def _export_artifacts(run: dict[str, Any]) -> dict[str, bytes]:
    untracked = _git(run, "ls-files", "--others", "--exclude-standard", "-z")
    untracked_names = []
    for raw_name in filter(None, untracked.split(b"\0")):
        name = raw_name.decode("utf-8", "strict")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise WorkerError(f"untracked working artifact path is unsafe: {name}")
        if any(part in SKIP_PARTS for part in path.parts) or path.name in SKIP_NAMES | {
            "lake-manifest.json"
        }:
            continue
        untracked_names.append(name)

    accepted_tar = export_accepted(run)
    _safe_tar(accepted_tar, "accepted tree")
    accepted = run.get("accepted") or {}
    accepted_commit = _git(run, "rev-parse", "HEAD").decode().strip()
    if accepted_commit != accepted.get("accepted_commit"):
        raise WorkerError("accepted commit mismatch during export")
    if _sha256(accepted_tar) != accepted.get("accepted_tree_sha256"):
        raise WorkerError("accepted tree mismatch during export")
    untracked_tar = _untracked_archive(run, untracked_names)
    _safe_tar(untracked_tar, "untracked working tree")
    return {
        "accepted/tree.tar": accepted_tar,
        "accepted/repository.bundle": _git(run, "bundle", "create", "-", "HEAD"),
        "accepted/commit.txt": (accepted_commit + "\n").encode("ascii"),
        "working/changes.patch": _git(run, "diff", "--binary", "HEAD"),
        "working/untracked.tar": untracked_tar,
        **_host_artifacts(run),
    }


def export_run(run: dict[str, Any], *, interrupted: bool = False) -> dict[str, Any]:
    """Export the exact accepted repository and bounded working delta."""
    existing = run.get("export_receipt")
    if isinstance(existing, dict):
        verified, stored = _load_verified_export(run)
        if verified != existing:
            raise WorkerError("export receipt changed after verification")
        if not run.get("worker_disposed") and _export_artifacts(run) != stored:
            raise WorkerError("working state changed after export")
        return verified
    artifacts = _export_artifacts(run)
    markers = tuple(run.get("artifact_scan_markers", ()))
    scan = scan_retained_state(run, artifacts, markers)
    export_root = Path(run["run_root"]) / "export"
    for name, raw in artifacts.items():
        _atomic_write(export_root / name, raw)
    for name, raw in artifacts.items():
        if (export_root / name).read_bytes() != raw:
            raise WorkerError(f"export hash verification failed: {name}")
    _atomic_write(export_root / "artifact-scan.json", _canonical_bytes(scan) + b"\n")
    provider_scan_receipt_sha256 = None
    if isinstance(run.get("provider_binding"), dict):
        from . import provider_config, provider_receipts

        binding = provider_config.provider_binding(run)
        if binding is None:
            raise WorkerError("provider binding is unavailable for artifact scan")
        provider_scan = provider_receipts.sign_scan_receipt(
            binding, run_id=run["run_id"], scan_sha256=scan["scan_sha256"]
        )
        provider_scan_raw = _canonical_bytes(provider_scan) + b"\n"
        _atomic_write(export_root / "provider-scan-receipt.json", provider_scan_raw)
        provider_scan_receipt_sha256 = _sha256(provider_scan_raw)
    entries = [
        {"path": name, "sha256": _sha256(raw), "size": len(raw)}
        for name, raw in sorted(artifacts.items())
    ]
    body = {
        "schema": "autofv-export/v1",
        "run_id": run["run_id"],
        "worker_id": run.get("agent_worker_id"),
        "volume": run["volume"],
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run.get("control_bundle_sha256"),
        "native_decide_policy_sha256": run.get("native_decide_policy_sha256"),
        "fixed_proxy_sha256": run.get("fixed_proxy_sha256"),
        "proxy_policy_sha256": run.get("proxy_policy_sha256"),
        "proxy_client_identity_sha256": run.get("proxy_client_identity_sha256"),
        "worker_inventory_sha256": run.get("worker_inventory_sha256"),
        "egress_policy_sha256": run.get("egress_policy_sha256"),
        "interrupted": bool(interrupted),
        "sequence": _finalization_sequence(run),
        "entries": entries,
        "scan_sha256": scan["scan_sha256"],
        "provider_scan_receipt_sha256": provider_scan_receipt_sha256,
        "verified_before_disposal": True,
    }
    receipt = {**body, "manifest_sha256": _sha256(_canonical_bytes(body))}
    _atomic_write(export_root / "manifest.json", _canonical_bytes(receipt) + b"\n")
    verified, _ = _load_verified_export(run)
    if verified != receipt:
        raise WorkerError("export manifest verification failed")
    run["artifact_scan_receipt"] = scan
    run["export_receipt"] = receipt
    run["events"].append("artifacts_exported")
    return receipt


def _load_verified_export(run: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bytes]]:
    export_root = Path(run["run_root"]) / "export"
    try:
        manifest = json.loads((export_root / "manifest.json").read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerError("disposed run has no valid export manifest") from exc
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    identities = {
        "run_id": run["run_id"],
        "volume": run["volume"],
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run.get("control_bundle_sha256"),
        "native_decide_policy_sha256": run.get("native_decide_policy_sha256"),
        "fixed_proxy_sha256": run.get("fixed_proxy_sha256"),
        "proxy_policy_sha256": run.get("proxy_policy_sha256"),
        "proxy_client_identity_sha256": run.get("proxy_client_identity_sha256"),
    }
    if (
        manifest.get("schema") != "autofv-export/v1"
        or any(manifest.get(key) != value for key, value in identities.items())
        or manifest.get("manifest_sha256") != _sha256(_canonical_bytes(body))
        or manifest.get("verified_before_disposal") is not True
        or not isinstance(manifest.get("entries"), list)
    ):
        raise WorkerError("disposed run export identity mismatch")

    artifacts = {}
    for entry in manifest["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise WorkerError("disposed run export entry is invalid")
        name = entry.get("path")
        if not isinstance(name, str):
            raise WorkerError("disposed run export path is invalid")
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or name in artifacts
        ):
            raise WorkerError("disposed run export path is unsafe")
        try:
            raw = export_root.joinpath(*path.parts).read_bytes()
        except OSError as exc:
            raise WorkerError("disposed run export is incomplete") from exc
        if len(raw) != entry["size"] or _sha256(raw) != entry["sha256"]:
            raise WorkerError("disposed run export hash mismatch")
        artifacts[name] = raw

    required = {
        "accepted/tree.tar",
        "accepted/repository.bundle",
        "accepted/commit.txt",
        "working/changes.patch",
        "working/untracked.tar",
    }
    if not required.issubset(artifacts):
        raise WorkerError("disposed run export is incomplete")
    _safe_tar(artifacts["accepted/tree.tar"], "restored accepted tree")
    _safe_tar(artifacts["working/untracked.tar"], "restored untracked tree")
    accepted = run.get("accepted") or {}
    try:
        commit = artifacts["accepted/commit.txt"].decode("ascii").strip()
    except UnicodeError as exc:
        raise WorkerError("disposed run accepted commit is invalid") from exc
    if commit != accepted.get("accepted_commit"):
        raise WorkerError("disposed run accepted commit mismatch")
    if _sha256(artifacts["accepted/tree.tar"]) != accepted.get(
        "accepted_tree_sha256"
    ):
        raise WorkerError("disposed run accepted tree mismatch")

    try:
        recorded_scan = (export_root / "artifact-scan.json").read_bytes()
        scan = json.loads(recorded_scan)
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerError("disposed run artifact scan is missing") from exc
    if not isinstance(scan, dict) or "scan_sha256" not in scan:
        raise WorkerError("disposed run artifact scan is invalid")
    scan_body = {key: value for key, value in scan.items() if key != "scan_sha256"}
    provider_bound = isinstance(run.get("provider_binding"), dict)
    if provider_bound:
        from . import provider_receipts

        try:
            provider_scan_raw = (
                export_root / "provider-scan-receipt.json"
            ).read_bytes()
            provider_scan = json.loads(provider_scan_raw)
            provider_receipts.validate_scan_receipt(
                provider_scan,
                binding=run["provider_binding"],
                run_id=run["run_id"],
                scan_sha256=scan["scan_sha256"],
            )
        except (OSError, json.JSONDecodeError, WorkerError) as exc:
            raise WorkerError("provider artifact scan receipt is invalid") from exc
        if (
            provider_scan_raw != _canonical_bytes(provider_scan) + b"\n"
            or manifest.get("provider_scan_receipt_sha256")
            != _sha256(provider_scan_raw)
        ):
            raise WorkerError("provider artifact scan receipt changed")
        export_scan = scan.get("export")
        if not isinstance(export_scan, dict) or export_scan.get(
            "artifact_sha256"
        ) != {name: _sha256(raw) for name, raw in sorted(artifacts.items())}:
            raise WorkerError("provider-scanned export changed after disposal")
    else:
        export_scan = scan_artifacts(
            artifacts, run.get("artifact_scan_markers", ())
        )
        if manifest.get("provider_scan_receipt_sha256") is not None:
            raise WorkerError("unexpected provider artifact scan receipt")
    if (
        recorded_scan != _canonical_bytes(scan) + b"\n"
        or scan.get("schema") != "autofv-retained-state-scan/v1"
        or scan.get("clean") is not True
        or scan.get("scanned_surfaces") != list(SCANNED_SURFACES)
        or scan.get("export") != export_scan
        or scan.get("scan_sha256") != _sha256(_canonical_bytes(scan_body))
        or manifest.get("scan_sha256") != scan["scan_sha256"]
    ):
        raise WorkerError("disposed run artifact scan mismatch")
    return manifest, artifacts


def dispose_run(run: dict[str, Any], *, interrupted: bool = False) -> dict[str, Any]:
    """Verify export, then destroy the exact disposable Linux worker."""
    existing = run.get("disposal_receipt")
    if isinstance(existing, dict):
        return existing
    if run.get("worker_disposed"):
        raise WorkerError("run worker is already disposed", run=run)
    exported = export_run(run, interrupted=interrupted)
    _destroy_worker(run)
    body = {
        "schema": "autofv-disposal/v1",
        "run_id": run["run_id"],
        "worker_id": run.get("agent_worker_id"),
        "volume": run["volume"],
        "interrupted": bool(interrupted),
        "sequence": _finalization_sequence(run),
        "export_manifest_sha256": exported["manifest_sha256"],
        "worker_absent": inspect_lima_instance(AGENT_VM) is None,
        "run_resources_absent": True,
    }
    if body["worker_absent"] is not True:
        raise WorkerError("disposable worker still exists after disposal", run=run)
    receipt = {**body, "disposal_sha256": _sha256(_canonical_bytes(body))}
    _atomic_write(
        Path(run["run_root"]) / "disposal.json",
        _canonical_bytes(receipt) + b"\n",
    )
    run["disposal_receipt"] = receipt
    run["events"].append("worker_disposed")
    if isinstance(run.get("provider_binding"), dict):
        from . import provider_service

        provider_service.release(run)
    return receipt


def export_accepted(run: dict[str, Any]) -> bytes:
    """Return the exact accepted Git tree, without worker caches or metadata."""
    return _git(run, "archive", "--format=tar", "HEAD")


def _restore_export(run: dict[str, Any]) -> None:
    manifest, artifacts = _load_verified_export(run)
    run.pop("export_receipt", None)
    run.pop("disposal_receipt", None)
    run.pop("artifact_scan_receipt", None)
    for key in (
        "proxy_firewall",
        "proxy_network",
        "proxy_relay",
        "proxy_policy_sha256",
        "proxy_policy_receipt",
        "upstream_policy_sha256",
        "upstream_policy_receipt",
        "egress_policy_sha256",
        "egress_receipt",
    ):
        run.pop(key, None)
    (Path(run["evidence_dir"]) / "egress.json").unlink(missing_ok=True)
    run["finalization_sequence"] = int(manifest.get("sequence", 0))
    control_manifest, control_files = _control_manifest(run["lock"])
    if control_manifest["bundle_sha256"] != run.get("control_bundle_sha256"):
        raise WorkerError("restored control bundle identity mismatch")

    existing_worker = _owned_worker(run)
    if existing_worker is not None:
        _destroy_worker(run)

    run["worker_disposed"] = False
    worker_created = False
    try:
        _create_worker(run)
        worker_created = True
        inventory = inspect_worker(run["lock"], run_id=run["run_id"])
        run["worker_inventory"] = inventory
        run["worker_inventory_sha256"] = inventory["inventory_sha256"]
        run["agent_worker_id"] = f"lima:{AGENT_VM}:{inventory['machine_id']}"
        _atomic_write(
            Path(run["evidence_dir"]) / "worker-inventory.json",
            _canonical_bytes(inventory) + b"\n",
        )
        claim_worker(run)
        if _docker("volume", "inspect", run["volume"], check=False).returncode == 0:
            raise WorkerError("disposed run volume was unexpectedly reused")
        _docker("volume", "create", *_labels(run, "volume"), run["volume"])
        seed = io.BytesIO()
        with tarfile.open(fileobj=seed, mode="w") as archive:
            _add_bytes(archive, "tree.tar", artifacts["accepted/tree.tar"], 0o444)
            _add_bytes(
                archive,
                "repository.bundle",
                artifacts["accepted/repository.bundle"],
                0o444,
            )
            _add_bytes(
                archive,
                "changes.patch",
                artifacts["working/changes.patch"],
                0o444,
            )
            _add_bytes(
                archive,
                "untracked.tar",
                artifacts["working/untracked.tar"],
                0o444,
            )
            for name, raw, mode in control_files:
                _add_bytes(archive, f"control/{name}", raw, mode)
            _add_bytes(
                archive,
                "control/manifest.json",
                _canonical_bytes(control_manifest) + b"\n",
                0o444,
            )
        command = (
            "mkdir -p /volume/recovery /volume/work/project /volume/evidence "
            "/volume/accepted /volume/logs /volume/lanes /volume/autofv-control && "
            "tar -xf - -C /volume/recovery && "
            "cp -a /volume/recovery/control/. /volume/autofv-control/ && "
            "chmod -R a-w /volume/autofv-control && chmod 0555 /volume/autofv-control && "
            "git -C /volume/work/project init -q --object-format=sha1 && "
            "git -C /volume/work/project fetch -q /volume/recovery/repository.bundle HEAD && "
            "git -C /volume/work/project checkout -q --detach FETCH_HEAD && "
            "git -C /volume/work/project config core.autocrlf false && "
            "git -C /volume/work/project config core.filemode false && "
            "if test -s /volume/recovery/changes.patch; then "
            "git -C /volume/work/project apply --binary /volume/recovery/changes.patch; fi && "
            "tar -xf /volume/recovery/untracked.tar -C /volume/work/project && "
            "chown -R 65532:65532 /volume/work /volume/evidence /volume/accepted "
            "/volume/logs /volume/lanes"
        )
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
            f"type=volume,src={run['volume']},dst=/volume,volume-nocopy",
            run["image_digest"],
            "sh",
            "-eu",
            "-c",
            command,
            input_bytes=seed.getvalue(),
        )
        _git(run, "bundle", "verify", "/volume/recovery/repository.bundle")
        restored_commit = _git(run, "rev-parse", "HEAD").decode().strip()
        restored_tree = _git(run, "archive", "--format=tar", "HEAD")
        if (
            restored_commit != run["accepted"]["accepted_commit"]
            or _sha256(restored_tree) != run["accepted"]["accepted_tree_sha256"]
        ):
            raise WorkerError("restored accepted state mismatch")
        run["scored_container_receipt"] = inspect_scored_container(run)
    except BaseException:
        if worker_created:
            _destroy_worker(run)
        raise
    run["events"].append("export_restored")


def inspect_resume_state(
    run: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Verify the managed Git HEAD before the controller trusts resumed state."""
    try:
        instance = _owned_worker(run)
        if instance is None:
            _restore_export(run)
        elif _docker("volume", "inspect", run["volume"], check=False).returncode:
            _restore_export(run)
        status = _git(run, "status", "--porcelain").decode().strip()
        _docker(*_runtime_argv(run["lock"], run["volume"], *manifest["verify"]))
        commit = _git(run, "rev-parse", "HEAD").decode().strip()
        tree = _git(run, "archive", "--format=tar", "HEAD")
    except WorkerError as exc:
        return {"valid": False, "dirty": None, "reason": str(exc)[:1000]}
    return {
        "valid": True,
        "dirty": bool(status),
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
