"""Lima, Docker, gVisor, and sealed-volume runtime primitives."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
AGENT_TEMPLATE_VM = "autofv-agent-template"
AGENT_VM = "autofv-agent-run"
AGENT_UID = "65532:65532"
SKIP_PARTS = frozenset({".git", ".lake", "target", "__pycache__"})
SKIP_NAMES = frozenset({"Cargo.lock", "functions.json"})
CLAIM_CONTAINER = "autofv-worker-claim"
RESOURCE_LABEL = "org.autofv"
OUTPUT_CHAIN = "AUTOFV-OUTPUT"
FORWARD_CHAIN = "AUTOFV-FORWARD"
NETWORK_ENFORCER = "upstream-default-deny+worker-firewall+docker-internal-network"
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")


class WorkerError(RuntimeError):
    """The trusted worker could not preserve its launch contract."""

    def __init__(self, message: str, *, run: dict[str, Any] | None = None):
        super().__init__(message)
        self.run = run


def _limactl(
    *argv: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ("limactl", *argv),
            input=input_bytes,
            capture_output=True,
        )
    except OSError as exc:
        raise WorkerError(f"Lima lifecycle command failed: {exc}") from exc
    if check and completed.returncode:
        detail = "\n".join(
            part
            for part in (
                completed.stdout.decode("utf-8", "replace").strip(),
                completed.stderr.decode("utf-8", "replace").strip(),
            )
            if part
        )[-4000:]
        raise WorkerError(f"Lima lifecycle command failed: {detail or argv[0]}")
    return completed


def inspect_lima_instance(name: str) -> dict[str, Any] | None:
    """Return one exact Lima instance record, or None when it does not exist."""
    completed = _limactl("list", "--json", name, check=False)
    if completed.returncode:
        detail = (completed.stderr + completed.stdout).decode("utf-8", "replace")
        if "unmatched instances" in detail.lower():
            return None
        raise WorkerError(f"Lima instance inventory failed: {detail.strip()[-4000:]}")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WorkerError("Lima instance inventory is invalid") from exc
    if not isinstance(value, dict) or value.get("name") != name:
        raise WorkerError("Lima instance inventory is incomplete")
    return value


def _new_run_id() -> str:
    run_id = os.environ.get("AUTOFV_RUN_ID") or f"autofv-{secrets.token_hex(16)}"
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", run_id) is None:
        raise WorkerError("trusted run identity is invalid")
    return run_id


def _firewall(
    tool: str, *argv: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return _lima("sudo", tool, *argv, check=check)


def _replace_firewall_chain(
    tool: str, parent: str, chain: str, rules: tuple[tuple[str, ...], ...]
) -> None:
    while _firewall(tool, "-C", parent, "-j", chain, check=False).returncode == 0:
        _firewall(tool, "-D", parent, "-j", chain)
    if _firewall(tool, "-S", chain, check=False).returncode == 0:
        _firewall(tool, "-F", chain)
    else:
        _firewall(tool, "-N", chain)
    for rule in rules:
        _firewall(tool, "-A", chain, *rule)
    _firewall(tool, "-I", parent, "1", "-j", chain)


def _firewall_snapshot(
    ipv4_allows: tuple[tuple[str, ...], ...] = (),
) -> dict[str, Any]:
    common_output = (
        ("-o", "lo", "-j", "ACCEPT"),
        ("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
        ("-j", "REJECT"),
    )
    common_forward = (
        ("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
        *(ipv4_allows),
        ("-j", "REJECT"),
    )
    evidence: dict[str, Any] = {}
    families = (
        ("iptables", common_forward),
        ("ip6tables", common_forward[:1] + common_forward[-1:]),
    )
    for tool, allows in families:
        expected = {OUTPUT_CHAIN: common_output, FORWARD_CHAIN: allows}
        for parent, chain in (("OUTPUT", OUTPUT_CHAIN), ("DOCKER-USER", FORWARD_CHAIN)):
            parent_rules = _firewall(tool, "-S", parent).stdout.decode().splitlines()
            if not parent_rules or parent_rules[1:2] != [f"-A {parent} -j {chain}"]:
                raise WorkerError(f"{tool} {parent} deny gate is not first")
            chain_rules = _firewall(tool, "-S", chain).stdout.decode().splitlines()
            observed = [
                line for line in chain_rules if line.startswith(f"-A {chain} ")
            ]
            if len(observed) != len(expected[chain]):
                raise WorkerError(f"{tool} {chain} rule count mismatch")
            for rule in expected[chain]:
                if _firewall(tool, "-C", chain, *rule, check=False).returncode:
                    raise WorkerError(f"{tool} {chain} rule mismatch")
        raw = _firewall(tool.replace("tables", "tables-save"), "-t", "filter").stdout
        evidence[tool] = {"filter_sha256": _sha256(raw)}
    return evidence


def _install_worker_firewall() -> None:
    _lima("sudo", "modprobe", "br_netfilter")
    _lima(
        "sudo",
        "sysctl",
        "-qw",
        "net.bridge.bridge-nf-call-iptables=1",
        "net.bridge.bridge-nf-call-ip6tables=1",
    )
    output = (
        ("-o", "lo", "-j", "ACCEPT"),
        ("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
        ("-j", "REJECT"),
    )
    forward = (
        ("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
        ("-j", "REJECT"),
    )
    for tool in ("iptables", "ip6tables"):
        _replace_firewall_chain(tool, "OUTPUT", OUTPUT_CHAIN, output)
        _replace_firewall_chain(tool, "DOCKER-USER", FORWARD_CHAIN, forward)
    _firewall_snapshot()


def _proxy_endpoint(base: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(base)
    try:
        address = str(ipaddress.IPv4Address(parsed.hostname or ""))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise WorkerError("trusted proxy must use one literal IPv4 endpoint") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not 1 <= port <= 65535
    ):
        raise WorkerError("trusted proxy base address is invalid")
    return address, port


def _seatbelt_profile(
    instance_dir: Path, *, ssh_port: int, proxy_port: int | None
) -> str:
    """Deny Lima host-agent egress except its own SSH and fixed proxy ports."""
    if not instance_dir.is_absolute() or not 1 <= ssh_port <= 65535:
        raise WorkerError("Lima Seatbelt identity is invalid")
    ports = sorted({ssh_port, *(() if proxy_port is None else (proxy_port,))})
    if any(not 1 <= port <= 65535 for port in ports):
        raise WorkerError("Lima Seatbelt port is invalid")
    allows = "\n".join(
        f'(allow network-outbound (remote ip "localhost:{port}"))'
        for port in ports
    )
    socket_scope = json.dumps(str(instance_dir))
    return (
        "(version 1)\n"
        "(allow default)\n"
        "(deny network-outbound)\n"
        f"{allows}\n"
        f"(allow network-outbound (remote unix-socket (subpath {socket_scope})))\n"
    )


def _available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


def _upstream_policy(
    run: dict[str, Any], instance: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    if sys.platform != "darwin":
        raise WorkerError("local upstream policy requires macOS Seatbelt")
    try:
        instance_dir = Path(instance["dir"]).resolve(strict=True)
        ssh_port = int(instance["sshLocalPort"])
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise WorkerError("Lima Seatbelt identity is incomplete") from exc
    if instance_dir.name != AGENT_VM:
        raise WorkerError("Lima Seatbelt instance scope mismatch")
    base = os.environ.get("AUTOFV_PROXY_BASE") or run.get("proxy_base")
    proxy_port = _proxy_endpoint(base)[1] if isinstance(base, str) else None
    profile = _seatbelt_profile(
        instance_dir, ssh_port=ssh_port, proxy_port=proxy_port
    )
    try:
        sandbox_status = SANDBOX_EXEC.stat()
        sandbox_raw = SANDBOX_EXEC.read_bytes()
    except OSError as exc:
        raise WorkerError("macOS Seatbelt launcher is unavailable") from exc
    if (
        not stat.S_ISREG(sandbox_status.st_mode)
        or sandbox_status.st_uid != 0
        or sandbox_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise WorkerError("macOS Seatbelt launcher is not trusted")
    limactl = shutil.which("limactl")
    if limactl is None:
        raise WorkerError("Lima lifecycle command is unavailable")
    body = {
        "schema": "autofv-upstream-egress-policy/v1",
        "run_id": run["run_id"],
        "enforcer": "macos-seatbelt-network-outbound",
        "lima_instance": AGENT_VM,
        "allowed_loopback_ports": sorted(
            {ssh_port, *(() if proxy_port is None else (proxy_port,))}
        ),
        "proxy_loopback_port": proxy_port,
        "instance_socket_scope_sha256": _sha256(str(instance_dir).encode()),
        "profile_sha256": _sha256(profile.encode()),
        "sandbox_exec_sha256": _sha256(sandbox_raw),
        "limactl_sha256": _sha256(Path(limactl).read_bytes()),
    }
    receipt = {**body, "policy_sha256": _sha256(_canonical_bytes(body))}
    existing = run.get("upstream_policy_sha256")
    if existing not in (None, receipt["policy_sha256"]):
        raise WorkerError("upstream egress policy changed during the run")
    return profile, receipt


def _start_worker(run: dict[str, Any], instance: dict[str, Any]) -> None:
    profile, receipt = _upstream_policy(run, instance)
    limactl = shutil.which("limactl")
    if limactl is None:
        raise WorkerError("Lima lifecycle command is unavailable")
    try:
        completed = subprocess.run(
            (str(SANDBOX_EXEC), "-p", profile, limactl, "start", AGENT_VM),
            capture_output=True,
        )
    except OSError as exc:
        raise WorkerError(f"sandboxed Lima launch failed: {exc}") from exc
    if completed.returncode:
        detail = (completed.stdout + completed.stderr).decode(
            "utf-8", "replace"
        ).strip()[-4000:]
        raise WorkerError(f"sandboxed Lima launch failed: {detail or 'limactl'}")
    run["upstream_policy_sha256"] = receipt["policy_sha256"]
    run["upstream_policy_receipt"] = receipt
    _atomic_write(
        Path(run["evidence_dir"]) / "upstream-policy.json",
        _canonical_bytes(receipt) + b"\n",
    )
    if "upstream_policy_bound" not in run["events"]:
        run["events"].append("upstream_policy_bound")


def _create_worker(run: dict[str, Any]) -> None:
    if inspect_lima_instance(AGENT_VM) is not None:
        raise WorkerError("worker is already claimed by another run")
    template = inspect_lima_instance(AGENT_TEMPLATE_VM)
    if template is None:
        raise WorkerError("pristine worker template is missing")
    config = template.get("config") or {}
    if (
        template.get("status") != "Stopped"
        or config.get("plain") is not True
        or config.get("mounts") not in (None, [])
        or (config.get("ssh") or {}).get("forwardAgent") is not False
    ):
        raise WorkerError("pristine worker template contract mismatch")
    ssh_port = _available_loopback_port()
    _limactl(
        "clone",
        "--mount-none",
        "--ssh-port",
        str(ssh_port),
        "--set",
        ".hostResolver.enabled = false",
        "--set",
        ".propagateProxyEnv = false",
        "--set",
        ".ssh.forwardAgent = false",
        AGENT_TEMPLATE_VM,
        AGENT_VM,
    )
    try:
        instance = inspect_lima_instance(AGENT_VM)
        if (
            instance is None
            or instance.get("status") != "Stopped"
            or instance.get("sshLocalPort") != ssh_port
        ):
            raise WorkerError("disposable worker clone identity mismatch")
        _start_worker(run, instance)
        hostname = _lima("hostname").stdout.decode("ascii", "replace").strip()
        if re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", hostname) is None:
            raise WorkerError("disposable worker hostname is invalid")
        hosts = _lima("cat", "/etc/hosts").stdout.decode("utf-8", "replace")
        if not any(hostname in line.split() for line in hosts.splitlines()):
            _lima(
                "sudo",
                "sh",
                "-c",
                "umask 022; cat >> /etc/hosts",
                input_bytes=f"127.0.1.1 {hostname}\n".encode("ascii"),
            )
        _lima(
            "sudo",
            "sh",
            "-c",
            "umask 022; cat > /etc/autofv-run-id",
            input_bytes=(run["run_id"] + "\n").encode("utf-8"),
        )
        _install_worker_firewall()
    except BaseException as exc:
        _limactl("stop", AGENT_VM, check=False)
        _limactl("delete", AGENT_VM, check=False)
        if inspect_lima_instance(AGENT_VM) is not None:
            raise WorkerError(
                f"{exc}; failed to remove incomplete disposable worker", run=run
            ) from exc
        raise
    run["worker_created"] = True
    run["firewall_installed"] = True
    run["events"].append("worker_created")


def _owned_worker(run: dict[str, Any]) -> dict[str, Any] | None:
    instance = inspect_lima_instance(AGENT_VM)
    if instance is None:
        return None
    if instance.get("status") == "Stopped":
        _start_worker(run, instance)
        _install_worker_firewall()
        run["firewall_installed"] = True
        run.pop("proxy_firewall", None)
        instance = inspect_lima_instance(AGENT_VM)
    if instance is None or instance.get("status") != "Running":
        raise WorkerError("disposable worker is not running", run=run)
    assignment = _lima("cat", "/etc/autofv-run-id").stdout.decode().strip()
    if assignment != run["run_id"]:
        raise WorkerError("disposable worker belongs to another run", run=run)
    return instance


def _destroy_worker(run: dict[str, Any]) -> None:
    instance = _owned_worker(run)
    if instance is None:
        run["worker_disposed"] = True
        return
    _limactl("stop", AGENT_VM)
    _limactl("delete", AGENT_VM)
    if inspect_lima_instance(AGENT_VM) is not None:
        raise WorkerError("disposable worker still exists after deletion", run=run)
    run["worker_disposed"] = True


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
        "--env",
        "CARGO_NET_OFFLINE=true",
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
        if not isinstance(name, str):
            raise WorkerError("Docker container inventory is incomplete")
        containers.append({"name": name, "state": item.get("State")})

    volumes = []
    output = _docker("volume", "ls", "--format", "{{.Name}}").stdout
    for raw in output.splitlines():
        name = raw.decode("utf-8", "strict")
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
        if not isinstance(name, str):
            raise WorkerError("Docker network inventory is incomplete")
        networks.append(name)
    return {
        "containers": sorted(containers, key=lambda item: item["name"]),
        "volumes": sorted(volumes),
        "networks": sorted(networks),
    }


def _guest_forbidden_paths() -> list[str]:
    completed = _lima(
        "sudo",
        "find",
        "/home",
        "/root",
        "/opt",
        "/srv",
        "-xdev",
        "(",
        "-type",
        "d",
        "(",
        "-name",
        ".git",
        "-o",
        "-name",
        ".aws",
        "-o",
        "-name",
        ".azure",
        "-o",
        "-name",
        ".kube",
        ")",
        "-o",
        "-type",
        "f",
        "(",
        "-name",
        ".env",
        "-o",
        "-name",
        ".netrc",
        "-o",
        "-name",
        ".git-credentials",
        "-o",
        "-name",
        ".bash_history",
        "-o",
        "-name",
        ".zsh_history",
        "-o",
        "-path",
        "*/.ssh/id_*",
        "-o",
        "-path",
        "*/.docker/config.json",
        "-o",
        "-path",
        "*/.config/gcloud/*",
        ")",
        ")",
        "-print",
    )
    return sorted(filter(None, completed.stdout.decode("utf-8", "strict").splitlines()))


def inspect_worker(lock: dict[str, Any], *, run_id: str) -> dict[str, Any]:
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

    instance = inspect_lima_instance(AGENT_VM)
    config = (instance or {}).get("config") or {}
    if (
        instance is None
        or instance.get("status") != "Running"
        or config.get("plain") is not True
        or config.get("mounts") not in (None, [])
        or config.get("propagateProxyEnv") is not False
        or (config.get("hostResolver") or {}).get("enabled") is not False
        or (config.get("ssh") or {}).get("forwardAgent") is not False
    ):
        raise WorkerError("disposable Lima worker configuration mismatch")

    platform = _lima("uname", "-s").stdout.decode().strip().lower()
    kernel = _lima("uname", "-r").stdout.decode().strip()
    machine_id = _lima("cat", "/etc/machine-id").stdout.decode().strip()
    docker_version = _docker("version", "--format", "{{.Server.Version}}").stdout.decode().strip()
    runsc_version = _lima("runsc", "--version").stdout.decode().strip()
    firewall_backend = _json_output(
        _docker("info", "--format", "{{json .FirewallBackend}}"),
        "Docker firewall backend",
    )
    bridge_filters = {
        family: _lima("sysctl", "-n", key).stdout.decode().strip()
        for family, key in (
            ("ipv4", "net.bridge.bridge-nf-call-iptables"),
            ("ipv6", "net.bridge.bridge-nf-call-ip6tables"),
        )
    }
    if platform != "linux":
        raise WorkerError("worker platform is not Linux")
    if kernel != lock["tools"]["kernel"]["pin"]:
        raise WorkerError("worker kernel identity mismatch")
    if not re.fullmatch(r"[0-9a-f]{32}", machine_id):
        raise WorkerError("worker machine identity is missing")
    assignment = _lima("cat", "/etc/autofv-run-id").stdout.decode().strip()
    if assignment != run_id:
        raise WorkerError("worker run identity mismatch")
    if docker_version != lock["tools"]["docker"]["observed_version"].removeprefix("Docker "):
        raise WorkerError("Docker identity mismatch")
    if lock["tools"]["runsc"]["pin"] not in runsc_version:
        raise WorkerError("runsc version mismatch")
    if firewall_backend.get("Driver") != "iptables" or set(bridge_filters.values()) != {"1"}:
        raise WorkerError("Docker traffic does not cross the worker firewall")

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
    image_ids = sorted(
        set(
            _docker("image", "ls", "--all", "--no-trunc", "--quiet")
            .stdout.decode()
            .splitlines()
        )
    )
    if image_ids != [image]:
        raise WorkerError("disposable worker contains an unrelated image")

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
    forbidden_guest_paths = _guest_forbidden_paths()
    if forbidden_guest_paths:
        raise WorkerError("worker contains a checkout, credential, or shell history")

    resources = _resource_inventory()
    if any(resources.values()):
        raise WorkerError("disposable worker is not empty")
    firewall = _firewall_snapshot()
    body = {
        "schema": "autofv-worker-inventory/v1",
        "run_id": run_id,
        "lima_instance": AGENT_VM,
        "platform": platform,
        "kernel": kernel,
        "machine_id": machine_id,
        "docker_version": docker_version,
        "docker_firewall_backend": firewall_backend["Driver"],
        "bridge_netfilter": bridge_filters,
        "firewall": firewall,
        "runsc_version": runsc_version.splitlines()[0],
        "runtime": runtime["runtime_name"],
        "runtime_args": runtime["runtime_args"],
        "image_digest": image,
        "image_ids": image_ids,
        "image_user": observed_image["Config"]["User"],
        "image_labels": {key: labels[key] for key in sorted(expected_labels)},
        "control_bundle_sha256": control_manifest["bundle_sha256"],
        "native_decide_policy_sha256": policy_hash,
        "environment_names": environment_names,
        "host_checkout_mounts": [],
        "forbidden_guest_paths": forbidden_guest_paths,
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
    """Return the local VM gateway without relying on guest DNS."""
    output = _lima("ip", "-4", "route", "show", "default").stdout.decode()
    try:
        fields = output.split()
        address = fields[fields.index("via") + 1]
        ipaddress.IPv4Address(address)
    except (ValueError, IndexError, ipaddress.AddressValueError) as exc:
        raise WorkerError("Lima host address is unavailable") from exc
    return address
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
            "run_id": run["run_id"],
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


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
