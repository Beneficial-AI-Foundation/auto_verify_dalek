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
AGENT_TEMPLATE_VM = "autofv-agent-template"
AGENT_VM = "autofv-agent-run"
AGENT_UID = "65532:65532"
SKIP_PARTS = frozenset({".git", ".lake", "target", "__pycache__"})
SKIP_NAMES = frozenset({"Cargo.lock", "functions.json"})
CLAIM_CONTAINER = "autofv-worker-claim"
RELAY_PORT = 8080
RESOURCE_LABEL = "org.autofv"
OUTPUT_CHAIN = "AUTOFV-OUTPUT"
FORWARD_CHAIN = "AUTOFV-FORWARD"
SHA256 = re.compile(r"[0-9a-f]{64}")
PROXY_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "sequence",
        "batch_id",
        "request_id",
        "role",
        "model_id",
        "input_hashes",
        "prompt_sha256",
    }
)
SCANNED_SURFACES = (
    "environment",
    "filesystem",
    "log",
    "transcript",
    "state",
    "result",
    "export",
)

_RELAY_PROGRAM = r"""
import http.server
import os
import socket
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
                response = reply.read(1_000_001)
                if len(response) > 1_000_000:
                    self.send_value(502, b'{"error":"fixed proxy response too large"}')
                else:
                    self.send_value(reply.status, response)
        except urllib.error.HTTPError as error:
            self.send_value(error.code, b'{"error":"fixed proxy rejected"}')
        except (TimeoutError, socket.timeout):
            self.send_value(504, b'{"error":"fixed proxy timeout"}')
        except urllib.error.URLError as error:
            status = 504 if isinstance(error.reason, (TimeoutError, socket.timeout)) else 502
            self.send_value(status, b'{"error":"fixed proxy unavailable"}')
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

_PROXY_CLIENT_PROGRAM = r"""
import json
import sys
import urllib.error
import urllib.request

raw = sys.stdin.buffer.read(1_000_001)
if not 0 < len(raw) <= 1_000_000:
    raise SystemExit(22)
request = urllib.request.Request(
    sys.argv[1], data=raw, method="POST", headers={"Content-Type": "application/json"}
)
try:
    with urllib.request.urlopen(request, timeout=30) as reply:
        output = reply.read(1_000_001)
        if len(output) > 1_000_000:
            output = (
                b'{"proxy_error":{"classification":"malformed_response",'
                b'"status_code":null}}'
            )
except urllib.error.HTTPError as error:
    classification = {
        401: "authentication_error",
        403: "authentication_error",
        408: "timeout",
        429: "rate_limited",
        504: "timeout",
    }.get(error.code, "upstream_error")
    output = json.dumps(
        {"proxy_error": {"classification": classification, "status_code": error.code}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
except urllib.error.URLError as error:
    classification = "timeout" if isinstance(error.reason, TimeoutError) else "upstream_error"
    output = json.dumps(
        {"proxy_error": {"classification": classification, "status_code": None}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
except TimeoutError:
    output = b'{"proxy_error":{"classification":"timeout","status_code":null}}'
sys.stdout.buffer.write(output)
"""

_PROXY_POLICY_CLIENT_PROGRAM = r"""
import http.client
import json
import sys

host = sys.argv[1]
port = int(sys.argv[2])
method = sys.argv[3]
path = sys.argv[4]
header = sys.argv[5]
raw = sys.stdin.buffer.read(1_000_001)
headers = {"Content-Type": "application/json"}
if header:
    headers[header] = "caller-controlled"
connection = http.client.HTTPConnection(host, port, timeout=5)
connection.request(method, path, body=raw, headers=headers)
reply = connection.getresponse()
reply.read()
blocked = not 200 <= reply.status < 300
print(
    json.dumps(
        {"blocked": blocked, "status": reply.status},
        sort_keys=True,
        separators=(",", ":"),
    )
)
raise SystemExit(0 if blocked else 23)
"""

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
    file_count = byte_count = 0
    for current, directories, names in os.walk(root, topdown=True, onerror=failed):
        directories.sort()
        names.sort()
        for name in names:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root)
            encoded_path = relative.encode("utf-8", "surrogateescape")
            if any(marker in encoded_path for marker in markers):
                hits.add(surface)
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode):
                entry = json.dumps([relative, "non-regular"], ensure_ascii=True)
                manifest.update(entry.encode() + b"\n")
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
            manifest.update(entry.encode() + b"\n")
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
    _limactl(
        "clone",
        "--start",
        "--mount-none",
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
        _limactl("start", AGENT_VM)
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


def prepare_run(target: Path, manifest: dict[str, Any], lock: dict[str, Any]) -> dict[str, Any]:
    """Copy target/control bytes into a fresh named volume without a bind mount."""
    archive, control_manifest, snapshot_sha256 = _seed_archive(target, lock)
    run_id = _new_run_id()
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
        "fixed_proxy_sha256": _sha256(_canonical_bytes(lock["fixed_proxy"])),
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
        _create_worker(run)
        worker_created = True
        inventory = inspect_worker(lock, run_id=run_id)
        run["worker_inventory"] = inventory
        run["worker_inventory_sha256"] = inventory["inventory_sha256"]
        run["agent_worker_id"] = f"lima:{AGENT_VM}:{inventory['machine_id']}"
        evidence = Path(run["evidence_dir"])
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "worker-inventory.json").write_bytes(
            _canonical_bytes(inventory) + b"\n"
        )
        claim_worker(run)
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
    except BaseException as exc:
        if worker_created:
            try:
                _destroy_worker(run)
            except WorkerError as cleanup_exc:
                raise WorkerError(
                    f"{exc}; preparation cleanup failed: {cleanup_exc}", run=run
                ) from exc
        if isinstance(exc, WorkerError):
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


def _validate_proxy_request(run: dict[str, Any], request: Any) -> str:
    """Reject any model call not produced by the fixed request envelope."""
    route = run.get("lock", {}).get("fixed_proxy")
    if not isinstance(route, dict):
        raise WorkerError("fixed proxy policy is missing")
    observed_policy = _sha256(_canonical_bytes(route))
    bound_policy = run.setdefault("fixed_proxy_sha256", observed_policy)
    if not isinstance(bound_policy, str) or not secrets.compare_digest(
        bound_policy, observed_policy
    ):
        raise WorkerError("fixed proxy policy changed during the run")
    if route.get("method") != "POST" or not isinstance(route.get("path"), str):
        raise WorkerError("fixed proxy policy is invalid")
    if not isinstance(request, dict) or set(request) != PROXY_REQUEST_FIELDS:
        raise WorkerError("fixed proxy request fields mismatch")
    if request["schema"] != "autofv-model-request/v1" or request["run_id"] != run.get(
        "run_id"
    ):
        raise WorkerError("fixed proxy request identity mismatch")
    if type(request["sequence"]) is not int or request["sequence"] <= 0:
        raise WorkerError("fixed proxy request sequence is invalid")
    if request["batch_id"] is not None and (
        not isinstance(request["batch_id"], str) or not request["batch_id"]
    ):
        raise WorkerError("fixed proxy request batch identity is invalid")
    for field in ("request_id", "role", "model_id"):
        if not isinstance(request[field], str) or not request[field]:
            raise WorkerError(f"fixed proxy request {field} is invalid")
    model_id = run.get("proxy_model_id")
    if model_id is not None and model_id != request["model_id"]:
        raise WorkerError("fixed proxy request model identity mismatch")
    expected_prompt = _sha256(
        (
            f"{run['run_id']}\0{request['request_id']}\0{request['role']}\0bounded-v1"
        ).encode("utf-8")
    )
    hashes = request["input_hashes"]
    if (
        not isinstance(hashes, list)
        or any(not isinstance(value, str) for value in hashes)
        or hashes != sorted(set(hashes))
        or any(SHA256.fullmatch(value) is None for value in hashes)
        or not isinstance(request["prompt_sha256"], str)
        or SHA256.fullmatch(request["prompt_sha256"]) is None
        or not secrets.compare_digest(request["prompt_sha256"], expected_prompt)
    ):
        raise WorkerError("fixed proxy request hashes are invalid")
    run.setdefault("proxy_model_id", request["model_id"])
    return _sha256(_canonical_bytes(request))


def _bind_proxy_client_identity(run: dict[str, Any], token: str) -> str:
    digest = _sha256(token.encode("utf-8"))
    bound = run.setdefault("proxy_client_identity_sha256", digest)
    if not isinstance(bound, str) or not secrets.compare_digest(bound, digest):
        raise WorkerError("trusted proxy client identity changed during the run")
    return digest


def _record_proxy_policy(run: dict[str, Any]) -> dict[str, Any]:
    route = run["lock"]["fixed_proxy"]
    body = {
        "schema": "autofv-fixed-proxy-policy/v1",
        "run_id": run["run_id"],
        "proxy_id": route["proxy_id"],
        "route_id": route["route_id"],
        "method": route["method"],
        "path": route["path"],
        "auth_scope": "run-scoped-fixed-inference",
        "provider_authorization_location": route["provider_authorization_location"],
        "proxy_endpoint_sha256": _sha256(run["proxy_base"].encode("utf-8")),
        "proxy_client_identity_sha256": run["proxy_client_identity_sha256"],
        "receipt_schema_sha256": _sha256(_canonical_bytes(route["receipt_schema"])),
        "fixed_proxy_sha256": run["fixed_proxy_sha256"],
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run["control_bundle_sha256"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "worker_inventory_sha256": run.get("worker_inventory_sha256"),
    }
    receipt = {**body, "policy_sha256": _sha256(_canonical_bytes(body))}
    existing = run.get("proxy_policy_sha256")
    if existing not in (None, receipt["policy_sha256"]):
        raise WorkerError("fixed proxy policy evidence changed during the run")
    _atomic_write(
        Path(run["evidence_dir"]) / "fixed-proxy-policy.json",
        _canonical_bytes(receipt) + b"\n",
    )
    run["proxy_policy_sha256"] = receipt["policy_sha256"]
    if "fixed_proxy_policy_bound" not in run["events"]:
        run["events"].append("fixed_proxy_policy_bound")
    return receipt


def _record_proxy_error(
    run: dict[str, Any],
    request: dict[str, Any],
    request_sha256: str,
    classification: str,
    status_code: int | None,
    detail: bytes | str,
) -> dict[str, Any]:
    allowed = set(run["lock"]["fixed_proxy"]["receipt_schema"]["status_values"]) - {
        "ok"
    }
    if classification not in allowed:
        raise WorkerError("fixed proxy error classification is invalid")
    if status_code is not None and (
        type(status_code) is not int or not 100 <= status_code <= 599
    ):
        raise WorkerError("fixed proxy error status is invalid")
    if isinstance(detail, str):
        raw_detail = detail.encode("utf-8", "replace")
    elif isinstance(detail, bytes):
        raw_detail = detail
    else:
        raise WorkerError("fixed proxy error detail is invalid")
    route = run["lock"]["fixed_proxy"]
    body = {
        "schema": "autofv-proxy-error/v1",
        "run_id": run["run_id"],
        "proxy_id": route["proxy_id"],
        "route_id": route["route_id"],
        "sequence": request["sequence"],
        "request_id": request["request_id"],
        "model_id": request["model_id"],
        "request_sha256": request_sha256,
        "classification": classification,
        "status_code": status_code,
        "detail_sha256": _sha256(raw_detail),
        "fixed_proxy_sha256": run.get("fixed_proxy_sha256"),
        "proxy_policy_sha256": run.get("proxy_policy_sha256"),
        "proxy_client_identity_sha256": run.get("proxy_client_identity_sha256"),
        "image_digest": run.get("image_digest"),
        "control_bundle_sha256": run.get("control_bundle_sha256"),
        "native_decide_policy_sha256": run.get("native_decide_policy_sha256"),
        "worker_inventory_sha256": run.get("worker_inventory_sha256"),
    }
    receipt = {**body, "error_sha256": _sha256(_canonical_bytes(body))}
    name = f"{request['sequence']:08d}-{_sha256(request['request_id'].encode())[:16]}.json"
    _atomic_write(
        Path(run["run_root"]) / "evidence" / "proxy-errors" / name,
        _canonical_bytes(receipt) + b"\n",
    )
    event = f"proxy_error:{classification}"
    if event not in run["events"]:
        run["events"].append(event)
    return receipt


def _configure_proxy_firewall(
    run: dict[str, Any], network: str, relay: str
) -> dict[str, Any]:
    base = os.environ.get("AUTOFV_PROXY_BASE") or run.get("proxy_base")
    if not isinstance(base, str):
        raise WorkerError("trusted proxy identity is not configured")
    upstream_address, upstream_port = _proxy_endpoint(base)
    networks = _json_output(_docker("network", "inspect", network), "proxy network")
    relays = _json_output(_docker("container", "inspect", relay), "proxy relay")
    try:
        network_id = networks[0]["Id"]
        internal_address = relays[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        bridge_address = relays[0]["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        ipaddress.IPv4Address(internal_address)
        ipaddress.IPv4Address(bridge_address)
    except (KeyError, IndexError, ipaddress.AddressValueError) as exc:
        raise WorkerError("proxy relay network identity is incomplete") from exc
    identity = {
        "base": base.rstrip("/"),
        "network_id": network_id,
        "internal_address": internal_address,
        "bridge_address": bridge_address,
        "upstream_address": upstream_address,
        "upstream_port": upstream_port,
    }
    if run.get("proxy_firewall") not in (None, identity):
        raise WorkerError("trusted proxy endpoint changed during the run")
    allows = (
        (
            "-i",
            f"br-{network_id[:12]}",
            "-d",
            f"{internal_address}/32",
            "-p",
            "tcp",
            "--dport",
            str(RELAY_PORT),
            "-j",
            "ACCEPT",
        ),
        (
            "-s",
            f"{bridge_address}/32",
            "-d",
            f"{upstream_address}/32",
            "-p",
            "tcp",
            "--dport",
            str(upstream_port),
            "-j",
            "ACCEPT",
        ),
    )
    if run.get("proxy_firewall") is None:
        try:
            snapshot = _firewall_snapshot(allows)
        except WorkerError:
            _firewall_snapshot()
            for position, rule in enumerate(allows, start=2):
                _firewall("iptables", "-I", FORWARD_CHAIN, str(position), *rule)
            snapshot = _firewall_snapshot(allows)
    else:
        snapshot = _firewall_snapshot(allows)
    run["proxy_base"] = identity["base"]
    run["proxy_firewall"] = identity
    return {**identity, "rules": snapshot}


def _ensure_proxy_relay(run: dict[str, Any]) -> tuple[str, str]:
    network, relay = _proxy_resources(run)
    base = os.environ.get("AUTOFV_PROXY_BASE") or run.get("proxy_base")
    token = os.environ.get("AUTOFV_RUN_TOKEN")
    if not isinstance(base, str) or not token:
        raise WorkerError("trusted proxy identity is not configured")
    _proxy_endpoint(base)
    _bind_proxy_client_identity(run, token)

    if _resource_matches("network", network, run) and _resource_matches(
        "relay", relay, run
    ):
        values = _json_output(_docker("container", "inspect", relay), "proxy relay")
        expected_environment = {
            f"AUTOFV_PROXY_BASE={base.rstrip('/')}",
            f"AUTOFV_PROXY_PATH={run['lock']['fixed_proxy']['path']}",
            f"AUTOFV_RUN_TOKEN={token}",
        }
        environment = set(values[0].get("Config", {}).get("Env") or [])
        if not expected_environment.issubset(environment):
            raise WorkerError("trusted proxy relay identity mismatch")
        address = values[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        _configure_proxy_firewall(run, network, relay)
        run["proxy_network"] = network
        run["proxy_relay"] = relay
        _record_proxy_policy(run)
        return network, address

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
    _configure_proxy_firewall(run, network, relay)
    run["proxy_network"] = network
    run["proxy_relay"] = relay
    run["events"].append("fixed_proxy_relay_started")
    _record_proxy_policy(run)
    return network, address


def proxy_round(
    run: dict[str, Any], request: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Call only the launcher-selected fixed route from the runsc worker."""
    request_sha256 = _validate_proxy_request(run, request)
    route = run["lock"]["fixed_proxy"]
    try:
        network, address = _ensure_proxy_relay(run)
    except WorkerError as exc:
        _record_proxy_error(
            run, request, request_sha256, "upstream_error", None, str(exc)
        )
        raise WorkerError("fixed proxy upstream_error", run=run) from exc
    completed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            _PROXY_CLIENT_PROGRAM,
            f"http://{address}:{RELAY_PORT}{route['path']}",
            network=network,
        ),
        input_bytes=_canonical_bytes(request),
        check=False,
    )
    if completed.returncode:
        _record_proxy_error(
            run,
            request,
            request_sha256,
            "upstream_error",
            None,
            completed.stdout + completed.stderr,
        )
        raise WorkerError("fixed proxy upstream_error", run=run)
    try:
        body = _json_output(completed, "fixed proxy response")
    except WorkerError as exc:
        _record_proxy_error(
            run,
            request,
            request_sha256,
            "malformed_response",
            None,
            completed.stdout + completed.stderr,
        )
        raise WorkerError("fixed proxy malformed_response", run=run) from exc
    if isinstance(body, dict) and set(body) == {"proxy_error"}:
        error = body["proxy_error"]
        if not isinstance(error, dict) or set(error) != {"classification", "status_code"}:
            classification, status_code = "malformed_response", None
        else:
            classification, status_code = error["classification"], error["status_code"]
            allowed = set(route["receipt_schema"]["status_values"]) - {"ok"}
            if classification not in allowed or (
                status_code is not None
                and (type(status_code) is not int or not 100 <= status_code <= 599)
            ):
                classification, status_code = "malformed_response", None
        _record_proxy_error(
            run,
            request,
            request_sha256,
            classification,
            status_code,
            completed.stdout + completed.stderr,
        )
        raise WorkerError(f"fixed proxy {classification}", run=run)
    if not isinstance(body, dict) or set(body) != {"response", "receipt"}:
        _record_proxy_error(
            run,
            request,
            request_sha256,
            "malformed_response",
            None,
            completed.stdout + completed.stderr,
        )
        raise WorkerError("fixed proxy malformed_response", run=run)
    return body["response"], body["receipt"]


def run_proxy_policy_matrix(
    run: dict[str, Any], fixture: dict[str, Any]
) -> dict[str, Any]:
    """Prove that the worker-visible relay exposes only fixed inference."""
    cases = fixture.get("rejected_proxy")
    expected_ids = [
        "connect_tunnel",
        "caller_upstream",
        "caller_authorization",
        "provider_admin",
        "file_transfer",
        "batch_jobs",
        "unclassified_surface",
    ]
    if (
        not isinstance(cases, list)
        or any(not isinstance(case, dict) for case in cases)
        or [case.get("id") for case in cases] != expected_ids
    ):
        raise WorkerError("proxy policy fixture cases mismatch")
    network, address = _ensure_proxy_relay(run)
    observed = []
    for case in cases:
        expected_fields = {"id", "method", "path"} | (
            {"header"}
            if case["id"] in {"caller_upstream", "caller_authorization"}
            else set()
        )
        if set(case) != expected_fields:
            raise WorkerError(f"proxy policy case fields mismatch: {case.get('id')}")
        completed = _docker(
            *_runtime_argv(
                run["lock"],
                run["volume"],
                "python",
                "-c",
                _PROXY_POLICY_CLIENT_PROGRAM,
                address,
                str(RELAY_PORT),
                case["method"],
                case["path"],
                case.get("header", ""),
                network=network,
            ),
            input_bytes=_canonical_bytes(
                {
                    "schema": "autofv-model-request/v1",
                    "run_id": run["run_id"],
                    "sequence": 1,
                    "batch_id": None,
                    "request_id": "policy-probe",
                    "role": "policy-probe",
                    "model_id": "policy-probe",
                    "input_hashes": [],
                    "prompt_sha256": "0" * 64,
                }
            ),
            check=False,
        )
        value = _json_output(completed, f"proxy policy case {case['id']}")
        if (
            completed.returncode != 0
            or not isinstance(value, dict)
            or set(value) != {"blocked", "status"}
            or value["blocked"] is not True
            or type(value["status"]) is not int
        ):
            raise WorkerError(f"fixed proxy allowed {case['id']}")
        observed.append({"id": case["id"], **value})

    body = {
        "schema": "autofv-proxy-policy-matrix/v1",
        "run_id": run["run_id"],
        "proxy_policy_sha256": run["proxy_policy_sha256"],
        "fixture_sha256": _sha256(_canonical_bytes(fixture)),
        "rejected": observed,
    }
    receipt = {**body, "matrix_sha256": _sha256(_canonical_bytes(body))}
    _atomic_write(
        Path(run["evidence_dir"]) / "proxy-policy-matrix.json",
        _canonical_bytes(receipt) + b"\n",
    )
    run["events"].append("proxy_policy_matrix_passed")
    return receipt


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
    layers = {}
    for layer in ("worker_denied", "container_denied"):
        observed = []
        for case in denied:
            if set(case) != {"id", "kind", "host", "port"}:
                raise WorkerError("egress case fields mismatch")
            argv = (
                "python3",
                "-c",
                probe,
                case["kind"],
                case["host"],
                str(case["port"]),
            )
            completed = (
                _lima(*argv, check=False)
                if layer == "worker_denied"
                else _docker(
                    *_runtime_argv(
                        run["lock"], run["volume"], *argv, network=network
                    ),
                    check=False,
                )
            )
            value = _json_output(completed, f"egress case {case['id']}")
            if completed.returncode != 0 or value.get("blocked") is not True:
                raise WorkerError(f"external policy allowed {case['id']} at {layer}")
            observed.append({"id": case["id"], **value})
        layers[layer] = observed

    response, receipt = proxy_round(run, request)
    network_values = _json_output(
        _docker("network", "inspect", network), "proxy network"
    )
    policy = {
        "schema": "autofv-egress-policy/v1",
        "enforcer": "worker-firewall-and-docker-internal-network",
        "network_id": network_values[0].get("Id"),
        "internal": network_values[0].get("Internal"),
        "firewall": _configure_proxy_firewall(
            run, network, _proxy_resources(run)[1]
        ),
        "fixture_sha256": _sha256(_canonical_bytes(fixture)),
    }
    if policy["internal"] is not True or not policy["network_id"]:
        raise WorkerError("external egress policy inspection mismatch")
    body = {
        "schema": "autofv-egress-evidence/v1",
        "run_id": run["run_id"],
        "policy": {**policy, "policy_sha256": _sha256(_canonical_bytes(policy))},
        **layers,
        "fixed_proxy": {
            "status": "ok",
            "request_id": response.get("request_id"),
            "receipt_sha256": receipt.get("receipt_sha256"),
        },
    }
    evidence = {**body, "evidence_sha256": _sha256(_canonical_bytes(body))}
    path = Path(run["evidence_dir"])
    path.mkdir(parents=True, exist_ok=True)
    _atomic_write(path / "egress.json", _canonical_bytes(evidence) + b"\n")
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
    except BaseException:
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
    for path, value in ((root / "result.json", result), (evidence / "l0.json", receipt)):
        _atomic_write(path, _canonical_bytes(value) + b"\n")
    if run.get("execution_tier") == "sealed_runsc" and run.get("base_commit"):
        dispose_run(run, interrupted=result.get("termination_reason") == "interrupted")


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
            seen = set()
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
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
) -> dict[str, Any]:
    """Scan every retained worker and export surface before destruction."""
    forbidden = _forbidden_markers(markers)
    hits: set[str] = set()

    environment = _worker_environment_artifacts(run)
    if _marker_hits(environment, forbidden):
        hits.add("environment")

    filesystem = _scan_worker_volume(run, forbidden)
    hits.update(filesystem["hit_surfaces"])

    state = {key: value for key, value in run.items() if key != "artifact_scan_markers"}
    try:
        state_raw = _canonical_bytes(state)
    except (TypeError, ValueError) as exc:
        raise WorkerError("controller run state is not canonical JSON") from exc
    if _marker_hits({"run.json": state_raw}, forbidden):
        hits.add("state")

    host = _host_artifacts(run)
    for name, raw in host.items():
        if _marker_hits({name: raw}, forbidden):
            hits.add(_host_surface(name))
    if _marker_hits(artifacts, forbidden):
        hits.add("export")

    if hits:
        ordered = [surface for surface in SCANNED_SURFACES if surface in hits]
        raise WorkerError(
            "forbidden material found in retained surfaces: " + ", ".join(ordered)
        )

    export = scan_artifacts(artifacts, markers)
    body = {
        "schema": "autofv-retained-state-scan/v1",
        "run_id": run["run_id"],
        "scanned_surfaces": list(SCANNED_SURFACES),
        "marker_count": len(forbidden),
        "environment_sha256": {
            name: _sha256(raw) for name, raw in sorted(environment.items())
        },
        "worker_filesystem": filesystem,
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
    markers = run.get("artifact_scan_markers", ())
    scan = scan_retained_state(run, artifacts, markers)
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
        "fixed_proxy_sha256": run.get("fixed_proxy_sha256"),
        "proxy_policy_sha256": run.get("proxy_policy_sha256"),
        "proxy_client_identity_sha256": run.get("proxy_client_identity_sha256"),
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
    verified, _ = _load_verified_export(run)
    if verified != receipt:
        raise WorkerError("export manifest verification failed")
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

    export_scan = scan_artifacts(artifacts, run.get("artifact_scan_markers", ()))
    try:
        recorded_scan = (export_root / "artifact-scan.json").read_bytes()
        scan = json.loads(recorded_scan)
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerError("disposed run artifact scan is missing") from exc
    if not isinstance(scan, dict) or "scan_sha256" not in scan:
        raise WorkerError("disposed run artifact scan is invalid")
    scan_body = {key: value for key, value in scan.items() if key != "scan_sha256"}
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
    return receipt


def export_accepted(run: dict[str, Any]) -> bytes:
    """Return the exact accepted Git tree, without worker caches or metadata."""
    return _git(run, "archive", "--format=tar", "HEAD")


def _restore_export(run: dict[str, Any]) -> None:
    manifest, artifacts = _load_verified_export(run)
    run.pop("export_receipt", None)
    run.pop("disposal_receipt", None)
    for key in (
        "proxy_firewall",
        "proxy_network",
        "proxy_relay",
        "proxy_policy_sha256",
    ):
        run.pop(key, None)
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
