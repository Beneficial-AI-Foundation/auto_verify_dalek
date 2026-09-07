"""Trusted Docker/runsc launcher for the V1 sealed experiment."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import tarfile
import tempfile
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
AGENT_VM = "autofv-agent"
AGENT_UID = "65532:65532"
SKIP_PARTS = frozenset({".git", ".lake", "target", "__pycache__"})
SKIP_NAMES = frozenset({"Cargo.lock", "functions.json"})
FIXTURE_RUN_ID = "fixture-diamond-run-0001"
CLAIM_CONTAINER = "autofv-worker-claim"
RELAY_PORT = 8080
RESOURCE_LABEL = "org.autofv"
SHA256 = re.compile(r"[0-9a-f]{64}")

_RELAY_PROGRAM = r"""
import http.server
import os
import urllib.error
import urllib.request

path = os.environ["AUTOFV_PROXY_PATH"]
upstream = os.environ["AUTOFV_PROXY_BASE"].rstrip("/") + path
token = os.environ["AUTOFV_RUN_TOKEN"]

class Handler(http.server.BaseHTTPRequestHandler):
    def send_value(self, status, raw=b'{"error":"rejected"}'):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.path != path:
            self.send_value(404)
            return
        if self.headers.get("Authorization") or self.headers.get("X-AutoFV-Upstream-Host"):
            self.send_value(403)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if length <= 0 or length > 1_000_000:
                raise ValueError
            raw = self.rfile.read(length)
            request = urllib.request.Request(
                upstream,
                data=raw,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-AutoFV-Run-Token": token,
                },
            )
            with urllib.request.urlopen(request, timeout=30) as reply:
                self.send_value(reply.status, reply.read())
        except urllib.error.HTTPError as error:
            self.send_value(error.code, error.read())
        except Exception:
            self.send_value(502, b'{"error":"fixed proxy failed"}')

    def do_CONNECT(self):
        self.send_value(405)

    def do_GET(self):
        self.send_value(405 if self.path == path else 404)

    def log_message(self, *args):
        return

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""


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


def _lima(
    *argv: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ("limactl", "shell", AGENT_VM, "--", *argv),
            input=input_bytes,
            capture_output=True,
        )
    except OSError as exc:
        raise WorkerError(f"agent worker launcher failed: {exc}") from exc
    if check and completed.returncode:
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


def _docker(
    *argv: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return _lima("sudo", "docker", *argv, input_bytes=input_bytes, check=check)


def _runtime_argv(
    lock: dict[str, Any],
    volume: str,
    *command: str,
    network: str = "none",
    name: str | None = None,
    detach: bool = False,
) -> tuple[str, ...]:
    lifecycle = (("-d",) if detach else ()) + (("--rm",) if name is None else ("--name", name))
    dns = ("--dns", "127.0.0.1") if network != "none" else ()
    return (
        "run",
        *lifecycle,
        "-i",
        "--pull",
        "never",
        "--runtime",
        lock["tools"]["runsc"]["runtime_name"],
        "--read-only",
        "--network",
        network,
        *dns,
        "--user",
        AGENT_UID,
        "--workdir",
        "/volume/work/project",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--cgroupns",
        "private",
        "--pids-limit",
        "256",
        "--cpus",
        "2",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--tmpfs",
        "/home/autofv/.cache:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--mount",
        f"type=volume,src={volume},dst=/volume,volume-nocopy",
        lock["image"]["image_digest"],
        *command,
    )


def _git(run: dict[str, Any], *argv: str, input_bytes: bytes | None = None) -> bytes:
    if not _resource_matches("volume", run["volume"], run):
        raise WorkerError("run volume identity is missing or mismatched")
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


def _json_output(completed: subprocess.CompletedProcess[bytes], label: str) -> Any:
    try:
        return json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WorkerError(f"{label} inventory is missing or invalid") from exc


def _resource_inventory() -> dict[str, list[dict[str, Any]] | list[str]]:
    containers = []
    output = _docker("container", "ls", "--all", "--format", "{{json .}}").stdout
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise WorkerError("Docker container inventory is incomplete") from exc
        name = item.get("Names")
        if not isinstance(name, str) or not name.startswith("autofv-"):
            raise WorkerError("worker contains an unrelated Docker workload")
        if item.get("State") == "running":
            raise WorkerError("worker contains a running Docker workload")
        containers.append({"name": name, "state": item.get("State")})

    volumes = []
    output = _docker("volume", "ls", "--format", "{{.Name}}").stdout
    for raw in output.splitlines():
        name = raw.decode("utf-8", "strict")
        if not name.startswith("autofv-"):
            raise WorkerError("worker contains an unrelated Docker volume")
        volumes.append(name)

    networks = []
    output = _docker("network", "ls", "--format", "{{json .}}").stdout
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise WorkerError("Docker network inventory is incomplete") from exc
        name = item.get("Name")
        if name in {"bridge", "host", "none"}:
            continue
        if not isinstance(name, str) or not name.startswith("autofv-"):
            raise WorkerError("worker contains an unrelated Docker network")
        networks.append(name)
    return {
        "containers": sorted(containers, key=lambda item: item["name"]),
        "volumes": sorted(volumes),
        "networks": sorted(networks),
    }


def inspect_worker(lock: dict[str, Any]) -> dict[str, Any]:
    """Fail closed unless the supplied worker matches the locked Linux boundary."""
    image = lock.get("image", {}).get("image_digest")
    if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise WorkerError("immutable image digest is required")
    runtime = lock.get("tools", {}).get("runsc", {})
    if runtime.get("runtime_name") != "runsc-hardened":
        raise WorkerError("runsc runtime identity mismatch")
    if runtime.get("runtime_args") != ["--network=sandbox", "--directfs=false"]:
        raise WorkerError("runsc runtime arguments mismatch")
    policy = lock.get("native_decide_policy")
    policy_hash = lock.get("native_decide_policy_sha256")
    if not isinstance(policy, dict) or policy_hash != _sha256(_canonical_bytes(policy)):
        raise WorkerError("native_decide policy identity mismatch")
    members = lock.get("controller_delivery", {}).get("allowed_members")
    if not isinstance(members, list) or not members:
        raise WorkerError("control bundle allowlist is missing")
    try:
        control_manifest, _ = _control_manifest(lock)
    except (KeyError, OSError, WorkerError) as exc:
        raise WorkerError(f"control bundle contract mismatch: {exc}") from exc

    platform = _lima("uname", "-s").stdout.decode().strip().lower()
    kernel = _lima("uname", "-r").stdout.decode().strip()
    machine_id = _lima("cat", "/etc/machine-id").stdout.decode().strip()
    docker_version = _docker("version", "--format", "{{.Server.Version}}").stdout.decode().strip()
    runsc_version = _lima("runsc", "--version").stdout.decode().strip()
    if platform != "linux":
        raise WorkerError("worker platform is not Linux")
    if kernel != lock["tools"]["kernel"]["pin"]:
        raise WorkerError("worker kernel identity mismatch")
    if not re.fullmatch(r"[0-9a-f]{32}", machine_id):
        raise WorkerError("worker machine identity is missing")
    if docker_version != lock["tools"]["docker"]["observed_version"].removeprefix("Docker "):
        raise WorkerError("Docker identity mismatch")
    if lock["tools"]["runsc"]["pin"] not in runsc_version:
        raise WorkerError("runsc version mismatch")

    runtimes = _json_output(
        _docker("info", "--format", "{{json .Runtimes}}"), "Docker runtime"
    )
    configured = runtimes.get(runtime["runtime_name"])
    if not isinstance(configured, dict) or configured.get("path") != "/usr/bin/runsc":
        raise WorkerError("runsc runtime is missing")
    if configured.get("runtimeArgs") != runtime["runtime_args"]:
        raise WorkerError("runsc daemon configuration mismatch")

    images = _json_output(_docker("image", "inspect", image), "Docker image")
    if not isinstance(images, list) or len(images) != 1:
        raise WorkerError("locked image inventory is incomplete")
    observed_image = images[0]
    labels = observed_image.get("Config", {}).get("Labels") or {}
    expected_labels = lock["image"]["labels"]
    if (
        observed_image.get("Id") != image
        or observed_image.get("Os") != "linux"
        or observed_image.get("Config", {}).get("User") != AGENT_UID
        or any(labels.get(key) != value for key, value in expected_labels.items())
    ):
        raise WorkerError("locked image identity mismatch")

    environment_names = sorted(
        _lima("sh", "-c", "env | cut -d= -f1 | sort").stdout.decode().splitlines()
    )
    forbidden_names = {
        "SSH_AUTH_SOCK",
        "DOCKER_AUTH_CONFIG",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
    }
    if forbidden_names.intersection(environment_names):
        raise WorkerError("worker environment contains a reusable credential")
    mounts = _lima("findmnt", "-rn", "-o", "FSTYPE,SOURCE,TARGET").stdout.decode()
    if any(kind in mounts for kind in ("virtiofs", "9p", str(ROOT))):
        raise WorkerError("worker contains a host checkout mount")

    resources = _resource_inventory()
    body = {
        "schema": "autofv-worker-inventory/v1",
        "platform": platform,
        "kernel": kernel,
        "machine_id": machine_id,
        "docker_version": docker_version,
        "runsc_version": runsc_version.splitlines()[0],
        "runtime": runtime["runtime_name"],
        "runtime_args": runtime["runtime_args"],
        "image_digest": image,
        "image_user": observed_image["Config"]["User"],
        "image_labels": {key: labels[key] for key in sorted(expected_labels)},
        "control_bundle_sha256": control_manifest["bundle_sha256"],
        "native_decide_policy_sha256": policy_hash,
        "environment_names": environment_names,
        "host_checkout_mounts": [],
        "resources": resources,
    }
    return {**body, "inventory_sha256": _sha256(_canonical_bytes(body))}


def _labels(run: dict[str, Any], kind: str) -> tuple[str, ...]:
    return (
        "--label",
        f"{RESOURCE_LABEL}.run_id={run['run_id']}",
        "--label",
        f"{RESOURCE_LABEL}.volume={run['volume']}",
        "--label",
        f"{RESOURCE_LABEL}.kind={kind}",
    )


def _resource_matches(kind: str, name: str, run: dict[str, Any]) -> bool:
    noun = "container" if kind in {"claim", "relay"} else kind
    completed = _docker(noun, "inspect", name, check=False)
    if completed.returncode:
        return False
    value = _json_output(completed, f"{kind} resource")
    item = value[0] if isinstance(value, list) else value
    if noun == "volume":
        labels = item.get("Labels") or {}
    elif noun == "network":
        labels = item.get("Labels") or {}
    else:
        labels = item.get("Config", {}).get("Labels") or {}
    expected = {
        f"{RESOURCE_LABEL}.kind": kind,
        f"{RESOURCE_LABEL}.run_id": run["run_id"],
        f"{RESOURCE_LABEL}.volume": run["volume"],
    }
    return all(labels.get(key) == value for key, value in expected.items())


def claim_worker(run: dict[str, Any]) -> None:
    """Atomically reserve the one dedicated worker for this run."""
    existing = _docker("container", "inspect", CLAIM_CONTAINER, check=False)
    if existing.returncode == 0:
        if _resource_matches("claim", CLAIM_CONTAINER, run):
            return
        raise WorkerError("worker is already claimed by another run")
    created = _docker(
        "create",
        "--name",
        CLAIM_CONTAINER,
        *_labels(run, "claim"),
        "--pull",
        "never",
        "--read-only",
        "--network",
        "none",
        "--user",
        AGENT_UID,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        run["image_digest"],
        "true",
        check=False,
    )
    if created.returncode:
        raise WorkerError("worker is already claimed by another run")
    run.setdefault("events", []).append("worker_claimed")


def lima_host_address() -> str:
    """Return Lima's fixed host-gateway address without using container DNS."""
    output = _lima("getent", "ahostsv4", "host.lima.internal").stdout.decode()
    try:
        address = output.split()[0]
        ipaddress.IPv4Address(address)
    except (IndexError, ipaddress.AddressValueError) as exc:
        raise WorkerError("Lima host address is unavailable") from exc
    return address


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
        "native_decide_policy": lock["native_decide_policy"]["selection"],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
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
    claimed = False
    try:
        inventory = inspect_worker(lock)
        run["worker_inventory"] = inventory
        run["worker_inventory_sha256"] = inventory["inventory_sha256"]
        run["agent_worker_id"] = f"lima:{AGENT_VM}:{inventory['machine_id']}"
        evidence = Path(run["evidence_dir"])
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "worker-inventory.json").write_bytes(
            _canonical_bytes(inventory) + b"\n"
        )
        claim_worker(run)
        claimed = True
        if _docker("volume", "inspect", volume, check=False).returncode == 0:
            raise WorkerError("run volume identity already exists")
        _docker("volume", "create", *_labels(run, "volume"), volume)
        if not _resource_matches("volume", volume, run):
            raise WorkerError("run volume claim mismatch")
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
        if claimed:
            try:
                _cleanup_owned_resources(run)
            except WorkerError as cleanup_exc:
                raise WorkerError(
                    f"{exc}; preparation cleanup failed: {cleanup_exc}", run=run
                ) from exc
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


def inspect_scored_container(run: dict[str, Any]) -> dict[str, Any]:
    """Start and inspect one short-lived container using the scored launch contract."""
    name = f"{run['volume']}-inspect"
    started = False
    try:
        _docker(
            *_runtime_argv(
                run["lock"],
                run["volume"],
                "sleep",
                "30",
                name=name,
                detach=True,
            )
        )
        started = True
        values = _json_output(
            _docker("container", "inspect", name), "scored container"
        )
        if not isinstance(values, list) or len(values) != 1:
            raise WorkerError("scored container inspection is incomplete")
        value = values[0]
        host = value.get("HostConfig") or {}
        config = value.get("Config") or {}
        mounts = value.get("Mounts") or []
        sockets = [
            mount
            for mount in mounts
            if any(
                marker in str(mount.get(field, ""))
                for marker in ("docker.sock", "containerd.sock", "podman.sock")
                for field in ("Source", "Destination")
            )
        ]
        volume_mounts = [
            mount
            for mount in mounts
            if mount.get("Type") == "volume"
            and mount.get("Name") == run["volume"]
            and mount.get("Destination") == "/volume"
        ]
        body = {
            "schema": "autofv-scored-container/v1",
            "container_id": value.get("Id"),
            "runtime": host.get("Runtime"),
            "read_only_root": host.get("ReadonlyRootfs"),
            "user": config.get("User"),
            "network_mode": host.get("NetworkMode"),
            "volume": run["volume"],
            "mount_count": len(mounts),
            "volume_mounts": len(volume_mounts),
            "bind_mounts": [mount for mount in mounts if mount.get("Type") == "bind"],
            "runtime_sockets": sockets,
            "cap_add": host.get("CapAdd") or [],
            "cap_drop": host.get("CapDrop") or [],
            "privileged": host.get("Privileged"),
            "security_opt": host.get("SecurityOpt") or [],
            "cgroupns_mode": host.get("CgroupnsMode"),
            "pids_limit": host.get("PidsLimit"),
            "memory_bytes": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "tmpfs": host.get("Tmpfs") or {},
            "image_digest": value.get("Image"),
            "state": (value.get("State") or {}).get("Status"),
        }
        expected = {
            "runtime": run["lock"]["tools"]["runsc"]["runtime_name"],
            "read_only_root": True,
            "user": AGENT_UID,
            "network_mode": "none",
            "mount_count": 1,
            "volume_mounts": 1,
            "bind_mounts": [],
            "runtime_sockets": [],
            "cap_add": [],
            "cap_drop": ["ALL"],
            "privileged": False,
            "security_opt": ["no-new-privileges"],
            "cgroupns_mode": "private",
            "pids_limit": 256,
            "memory_bytes": 2 * 1024**3,
            "nano_cpus": 2_000_000_000,
            "image_digest": run["image_digest"],
            "state": "running",
        }
        for field, expected_value in expected.items():
            if body[field] != expected_value:
                raise WorkerError(f"scored container {field} mismatch")
        if set(body["tmpfs"]) != {"/tmp", "/home/autofv/.cache"}:
            raise WorkerError("scored container tmpfs mismatch")
        receipt = {**body, "inspection_sha256": _sha256(_canonical_bytes(body))}
        evidence = Path(run["evidence_dir"])
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "scored-container.json").write_bytes(
            _canonical_bytes(receipt) + b"\n"
        )
        run["events"].append("scored_container_inspected")
        return receipt
    finally:
        if started:
            _docker("container", "rm", "--force", name, check=False)


def _proxy_resources(run: dict[str, Any]) -> tuple[str, str]:
    return f"{run['volume']}-network", f"{run['volume']}-relay"


def _ensure_proxy_relay(run: dict[str, Any]) -> tuple[str, str]:
    network, relay = _proxy_resources(run)
    if _resource_matches("network", network, run) and _resource_matches(
        "relay", relay, run
    ):
        values = _json_output(_docker("container", "inspect", relay), "proxy relay")
        address = values[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        return network, address

    base = os.environ.get("AUTOFV_PROXY_BASE")
    token = os.environ.get("AUTOFV_RUN_TOKEN")
    if not base or not token:
        raise WorkerError("trusted proxy identity is not configured")
    parsed = urllib.parse.urlsplit(base)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise WorkerError("trusted proxy base address is invalid")

    if _docker("network", "inspect", network, check=False).returncode == 0:
        raise WorkerError("proxy network identity already exists")
    _docker("network", "create", "--internal", *_labels(run, "network"), network)
    if not _resource_matches("network", network, run):
        raise WorkerError("proxy network claim mismatch")
    if _docker("container", "inspect", relay, check=False).returncode == 0:
        raise WorkerError("proxy relay identity already exists")
    _docker(
        "run",
        "-d",
        "--name",
        relay,
        *_labels(run, "relay"),
        "--pull",
        "never",
        "--read-only",
        "--network",
        "bridge",
        "--user",
        AGENT_UID,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--env",
        f"AUTOFV_PROXY_BASE={base.rstrip('/')}",
        "--env",
        f"AUTOFV_PROXY_PATH={run['lock']['fixed_proxy']['path']}",
        "--env",
        f"AUTOFV_RUN_TOKEN={token}",
        run["image_digest"],
        "python",
        "-c",
        _RELAY_PROGRAM,
    )
    _docker("network", "connect", network, relay)
    if not _resource_matches("relay", relay, run):
        raise WorkerError("proxy relay claim mismatch")
    values = _json_output(_docker("container", "inspect", relay), "proxy relay")
    try:
        address = values[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        ipaddress.IPv4Address(address)
    except (KeyError, IndexError, ipaddress.AddressValueError) as exc:
        raise WorkerError("proxy relay address is unavailable") from exc
    run["proxy_network"] = network
    run["proxy_relay"] = relay
    run["events"].append("fixed_proxy_relay_started")
    return network, address


def proxy_round(run: dict[str, Any], request: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Call only the launcher-selected fixed route from the runsc worker."""
    route = run["lock"]["fixed_proxy"]
    if route["method"] != "POST" or request.get("run_id") != run["run_id"]:
        raise WorkerError("fixed proxy request identity mismatch")
    network, address = _ensure_proxy_relay(run)
    client = (
        "import json,sys,time,urllib.request;"
        "raw=sys.stdin.buffer.read(1000001);"
        "assert 0<len(raw)<=1000000;"
        "req=urllib.request.Request(sys.argv[1],data=raw,method='POST',"
        "headers={'Content-Type':'application/json'});"
        "reply=urllib.request.urlopen(req,timeout=30);"
        "sys.stdout.buffer.write(reply.read())"
    )
    completed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            client,
            f"http://{address}:{RELAY_PORT}{route['path']}",
            network=network,
        ),
        input_bytes=_canonical_bytes(request),
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace")[-1000:]
        raise WorkerError(f"fixed proxy request failed: {detail}".rstrip())
    body = _json_output(completed, "fixed proxy response")
    if not isinstance(body, dict) or set(body) != {"response", "receipt"}:
        raise WorkerError("fixed proxy returned an invalid envelope")
    return body["response"], body["receipt"]


def run_egress_matrix(
    run: dict[str, Any], fixture: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    """Exercise denied destinations and the fixed relay on one internal network."""
    if fixture.get("schema") != "autofv-linux-isolation-fixture/v1":
        raise WorkerError("egress fixture schema mismatch")
    denied = fixture.get("denied")
    if not isinstance(denied, list) or [item.get("id") for item in denied] != [
        "external_dns",
        "literal_ipv4",
        "literal_ipv6",
        "link_local_metadata",
    ]:
        raise WorkerError("egress fixture cases mismatch")
    if fixture.get("fixed_proxy") != {
        "method": run["lock"]["fixed_proxy"]["method"],
        "path": run["lock"]["fixed_proxy"]["path"],
    }:
        raise WorkerError("egress fixed route mismatch")
    network, _ = _ensure_proxy_relay(run)
    probe = (
        "import json,socket,sys;"
        "kind,host,port=sys.argv[1],sys.argv[2],int(sys.argv[3]);"
        "socket.setdefaulttimeout(2);"
        "blocked=False;reason='';"
        "\ntry:\n"
        "  if kind=='dns': socket.getaddrinfo(host,port)\n"
        "  else:\n"
        "    family=socket.AF_INET6 if kind=='ipv6' else socket.AF_INET\n"
        "    address=(host,port,0,0) if family==socket.AF_INET6 else (host,port)\n"
        "    sock=socket.socket(family,socket.SOCK_STREAM);sock.connect(address)\n"
        "except OSError as error:\n"
        "  blocked=True;reason=type(error).__name__\n"
        "print(json.dumps({'blocked':blocked,'reason':reason},sort_keys=True,separators=(',',':')))\n"
        "raise SystemExit(0 if blocked else 23)"
    )
    observed = []
    for case in denied:
        if set(case) != {"id", "kind", "host", "port"}:
            raise WorkerError("egress case fields mismatch")
        completed = _docker(
            *_runtime_argv(
                run["lock"],
                run["volume"],
                "python",
                "-c",
                probe,
                case["kind"],
                case["host"],
                str(case["port"]),
                network=network,
            ),
            check=False,
        )
        value = _json_output(completed, f"egress case {case['id']}")
        if completed.returncode != 0 or value.get("blocked") is not True:
            raise WorkerError(f"external policy allowed {case['id']}")
        observed.append({"id": case["id"], **value})

    response, receipt = proxy_round(run, request)
    network_values = _json_output(
        _docker("network", "inspect", network), "proxy network"
    )
    policy = {
        "schema": "autofv-egress-policy/v1",
        "enforcer": "docker-internal-network-with-fixed-relay",
        "network_id": network_values[0].get("Id"),
        "internal": network_values[0].get("Internal"),
        "fixture_sha256": _sha256(_canonical_bytes(fixture)),
    }
    if policy["internal"] is not True or not policy["network_id"]:
        raise WorkerError("external egress policy inspection mismatch")
    body = {
        "schema": "autofv-egress-evidence/v1",
        "run_id": run["run_id"],
        "policy": {**policy, "policy_sha256": _sha256(_canonical_bytes(policy))},
        "denied": observed,
        "fixed_proxy": {
            "status": "ok",
            "request_id": response.get("request_id"),
            "receipt_sha256": receipt.get("receipt_sha256"),
        },
    }
    evidence = {**body, "evidence_sha256": _sha256(_canonical_bytes(body))}
    path = Path(run["evidence_dir"])
    path.mkdir(parents=True, exist_ok=True)
    (path / "egress.json").write_bytes(_canonical_bytes(evidence) + b"\n")
    run["egress_policy_sha256"] = evidence["policy"]["policy_sha256"]
    run["events"].append("egress_matrix_passed")
    return evidence


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
    if run.get("execution_tier") == "sealed_runsc" and run.get("base_commit"):
        dispose_run(run)


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def _safe_tar(raw: bytes, label: str) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not (member.isfile() or member.isdir())
                ):
                    raise WorkerError(f"{label} contains an unsafe member")
    except tarfile.TarError as exc:
        raise WorkerError(f"{label} is not a valid archive") from exc


def scan_artifacts(
    artifacts: dict[str, bytes], markers: Iterable[bytes | str] = ()
) -> dict[str, Any]:
    """Reject provider secrets, fixture programs, and hidden references."""
    forbidden = [
        b"tests/fixtures/model-proxy/diamond-responses.json",
        b"diamond-responses.json",
        b"diamond-reference",
        b"tests/fixtures/diamond-reference",
    ]
    for marker in markers:
        raw = marker.encode("utf-8") if isinstance(marker, str) else marker
        if not raw:
            raise WorkerError("artifact scan marker must not be empty")
        forbidden.append(raw)
    for name, raw in artifacts.items():
        for marker in forbidden:
            if marker in raw:
                raise WorkerError(f"forbidden material found in export artifact {name}")
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


def export_run(run: dict[str, Any], *, interrupted: bool = False) -> dict[str, Any]:
    """Export the exact accepted repository and bounded working delta."""
    existing = run.get("export_receipt")
    if isinstance(existing, dict):
        return existing
    untracked = _git(run, "ls-files", "--others", "--exclude-standard", "-z")
    for raw_name in filter(None, untracked.split(b"\0")):
        name = raw_name.decode("utf-8", "strict")
        path = PurePosixPath(name)
        if not (
            any(part in SKIP_PARTS for part in path.parts)
            or path.name in SKIP_NAMES | {"lake-manifest.json"}
        ):
            raise WorkerError(f"untracked working artifact is not exportable: {name}")

    accepted_tar = export_accepted(run)
    _safe_tar(accepted_tar, "accepted tree")
    artifacts = {
        "accepted/tree.tar": accepted_tar,
        "accepted/repository.bundle": _git(run, "bundle", "create", "-", "HEAD"),
        "accepted/commit.txt": _git(run, "rev-parse", "HEAD"),
        "working/changes.patch": _git(run, "diff", "--binary", "HEAD"),
        **_host_artifacts(run),
    }
    markers = run.get("artifact_scan_markers", ())
    scan = scan_artifacts(artifacts, markers)
    export_root = Path(run["run_root"]) / "export"
    for name, raw in artifacts.items():
        _atomic_write(export_root / name, raw)
    for name, raw in artifacts.items():
        if (export_root / name).read_bytes() != raw:
            raise WorkerError(f"export hash verification failed: {name}")
    _atomic_write(export_root / "artifact-scan.json", _canonical_bytes(scan) + b"\n")
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
        "worker_inventory_sha256": run.get("worker_inventory_sha256"),
        "egress_policy_sha256": run.get("egress_policy_sha256"),
        "interrupted": bool(interrupted),
        "sequence": _finalization_sequence(run),
        "entries": entries,
        "scan_sha256": scan["scan_sha256"],
        "verified_before_disposal": True,
    }
    receipt = {**body, "manifest_sha256": _sha256(_canonical_bytes(body))}
    _atomic_write(export_root / "manifest.json", _canonical_bytes(receipt) + b"\n")
    if _sha256(_canonical_bytes(body)) != receipt["manifest_sha256"]:
        raise WorkerError("export manifest verification failed")
    run["export_receipt"] = receipt
    run["events"].append("artifacts_exported")
    return receipt


def _remove_owned(kind: str, name: str, run: dict[str, Any]) -> None:
    noun = "container" if kind in {"claim", "relay"} else kind
    present = _docker(noun, "inspect", name, check=False)
    if present.returncode:
        return
    if not _resource_matches(kind, name, run):
        raise WorkerError(f"refusing to remove unowned {kind} resource")
    if noun == "container":
        _docker("container", "rm", "--force", name)
    else:
        _docker(noun, "rm", name)


def _cleanup_owned_resources(run: dict[str, Any]) -> dict[str, Any]:
    network, relay = _proxy_resources(run)
    _remove_owned("relay", relay, run)
    _remove_owned("network", network, run)
    _remove_owned("volume", run["volume"], run)
    _remove_owned("claim", CLAIM_CONTAINER, run)
    run["resources_disposed"] = True
    observed = _resource_inventory()
    expected = run.get("worker_inventory", {}).get("resources")
    if expected is not None and observed != expected:
        raise WorkerError("worker did not return to its pre-run resource inventory")
    return observed


def dispose_run(run: dict[str, Any], *, interrupted: bool = False) -> dict[str, Any]:
    """Verify export, remove only run-owned resources, and prove baseline reset."""
    existing = run.get("disposal_receipt")
    if isinstance(existing, dict):
        return existing
    if run.get("resources_disposed"):
        raise WorkerError("run resources are already disposed", run=run)
    try:
        exported = export_run(run, interrupted=interrupted)
    finally:
        observed = _cleanup_owned_resources(run)
    body = {
        "schema": "autofv-disposal/v1",
        "run_id": run["run_id"],
        "worker_id": run.get("agent_worker_id"),
        "volume": run["volume"],
        "interrupted": bool(interrupted),
        "sequence": _finalization_sequence(run),
        "export_manifest_sha256": exported["manifest_sha256"],
        "resource_inventory_sha256": _sha256(_canonical_bytes(observed)),
        "run_resources_absent": True,
    }
    receipt = {**body, "disposal_sha256": _sha256(_canonical_bytes(body))}
    _atomic_write(
        Path(run["run_root"]) / "disposal.json",
        _canonical_bytes(receipt) + b"\n",
    )
    run["disposal_receipt"] = receipt
    run["events"].append("worker_disposed")
    return receipt


def export_accepted(run: dict[str, Any]) -> bytes:
    """Return the exact accepted Git tree, without worker caches or metadata."""
    return _git(run, "archive", "--format=tar", "HEAD")


def _restore_export(run: dict[str, Any]) -> None:
    export_root = Path(run["run_root"]) / "export"
    try:
        manifest = json.loads((export_root / "manifest.json").read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerError("disposed run has no valid export manifest") from exc
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if (
        manifest.get("schema") != "autofv-export/v1"
        or manifest.get("run_id") != run["run_id"]
        or manifest.get("volume") != run["volume"]
        or manifest.get("image_digest") != run["image_digest"]
        or manifest.get("manifest_sha256") != _sha256(_canonical_bytes(body))
        or manifest.get("verified_before_disposal") is not True
    ):
        raise WorkerError("disposed run export identity mismatch")
    run.pop("export_receipt", None)
    run.pop("disposal_receipt", None)
    run["finalization_sequence"] = int(manifest.get("sequence", 0))
    artifacts = {}
    for entry in manifest.get("entries", []):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise WorkerError("disposed run export entry is invalid")
        path = PurePosixPath(entry["path"])
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise WorkerError("disposed run export path is unsafe")
        raw = (export_root.joinpath(*path.parts)).read_bytes()
        if len(raw) != entry["size"] or _sha256(raw) != entry["sha256"]:
            raise WorkerError("disposed run export hash mismatch")
        artifacts[path.as_posix()] = raw
    required = {
        "accepted/tree.tar",
        "accepted/repository.bundle",
        "accepted/commit.txt",
        "working/changes.patch",
    }
    if not required.issubset(artifacts):
        raise WorkerError("disposed run export is incomplete")
    _safe_tar(artifacts["accepted/tree.tar"], "restored accepted tree")
    scan_artifacts(artifacts, run.get("artifact_scan_markers", ()))
    control_manifest, control_files = _control_manifest(run["lock"])
    if control_manifest["bundle_sha256"] != run.get("control_bundle_sha256"):
        raise WorkerError("restored control bundle identity mismatch")

    inventory = inspect_worker(run["lock"])
    run["worker_inventory"] = inventory
    run["worker_inventory_sha256"] = inventory["inventory_sha256"]
    claim_worker(run)
    if _docker("volume", "inspect", run["volume"], check=False).returncode == 0:
        raise WorkerError("disposed run volume was unexpectedly reused")
    _docker("volume", "create", *_labels(run, "volume"), run["volume"])
    run["resources_disposed"] = False
    seed = io.BytesIO()
    with tarfile.open(fileobj=seed, mode="w") as archive:
        _add_bytes(archive, "tree.tar", artifacts["accepted/tree.tar"], 0o444)
        _add_bytes(
            archive,
            "repository.bundle",
            artifacts["accepted/repository.bundle"],
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
    run["events"].append("export_restored")


def inspect_resume_state(
    run: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Verify the managed Git HEAD before the controller trusts resumed state."""
    try:
        if _docker("volume", "inspect", run["volume"], check=False).returncode:
            _restore_export(run)
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
