"""Trusted-host supervisor for the fixed Pi one-generation bridge.

No credential contents enter Python. This is a private-pipe/process boundary,
not evidence of OS network isolation or successful upstream cancellation.
"""
from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any

PROTOCOL = "autofv-pi-ipc/v1"
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_CONTINUATION_BYTES = 256 * 1024
SDK_VERSIONS = {"@earendil-works/pi-ai": "1.2.0", "@earendil-works/pi-coding-agent": "1.2.0"}
REQUEST_KEYS = {"run_id", "conversation_id", "request_id", "sequence", "role", "model_id", "history_sha256", "profile_sha256"}


class PiProcessError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        self.classification = code
        self.retain_dispatch_ambiguity = True
        super().__init__(f"Pi transport: {code}")


def _fail(code: str) -> None:
    raise PiProcessError(code)


def _exact(value: Any, keys: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict) or not keys <= value.keys() or value.keys() - keys - optional:
        _fail("invalid_shape")
    return value


def _bounded(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if depth > 24 or count[0] > 32768:
        _fail("structure_limit")
    if value is None or type(value) is bool:
        return
    if type(value) is int and abs(value) <= 2**53 - 1:
        return
    if isinstance(value, str):
        try:
            if len(value.encode("utf-8")) > MAX_FRAME_BYTES:
                _fail("frame_limit")
        except UnicodeError:
            _fail("invalid_string")
        return
    if isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1, count)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for key, item in value.items():
            _bounded(key, depth + 1, count)
            _bounded(item, depth + 1, count)
        return
    _fail("invalid_json")


def canonical(value: Any) -> bytes:
    _bounded(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _decode(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_FRAME_BYTES:
        _fail("frame_limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        _fail("invalid_json")
    if canonical(value) != raw:
        _fail("noncanonical_json")
    if not isinstance(value, dict) or value.get("v") != 1:
        _fail("invalid_protocol")
    return value


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_continuation(value: Any, request: dict[str, Any], response: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate private allowlisted continuation, never project it into role traces."""
    _exact(value, {"schema", "request", "canonical_tool_id", "tool_call", "native"})
    if value["schema"] != "autofv-pi-continuation/v1" or len(canonical(value)) > MAX_CONTINUATION_BYTES:
        _fail("invalid_continuation")
    stored = _exact(value["request"], REQUEST_KEYS)
    for key in REQUEST_KEYS:
        if key == "profile_sha256" and key not in request:
            if stored[key] not in request.get("input_hashes", []):
                _fail("continuation_identity_mismatch")
        elif key not in request or stored[key] != request[key]:
            _fail("continuation_identity_mismatch")
    if value["canonical_tool_id"] != request["request_id"] + "-tool":
        _fail("continuation_identity_mismatch")
    call = _exact(value["tool_call"], {"name", "arguments"})
    if call["name"] not in {"read_allowed", "search_allowed", "edit_assigned", "check_lean", "submit_candidate"} or not isinstance(call["arguments"], dict):
        _fail("invalid_tool_call")
    if response is not None:
        expected = response.get("payload", response.get("tool_call", {}))
        if expected.get("name") != call["name"] or expected.get("arguments") != call["arguments"]:
            _fail("continuation_response_mismatch")
    native = _exact(value["native"], {"tool_call_id", "content", "response_id"})
    if not isinstance(native["tool_call_id"], str) or not re.fullmatch(r"[A-Za-z0-9._:-]+(?:\|[A-Za-z0-9._:-]+)?", native["tool_call_id"]) or len(native["tool_call_id"]) > 512:
        _fail("invalid_continuation")
    if native["response_id"] is not None and (not isinstance(native["response_id"], str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,512}", native["response_id"])):
        _fail("invalid_continuation")
    if not isinstance(native["content"], list) or len(native["content"]) > 32:
        _fail("invalid_continuation")
    calls = 0
    for block in native["content"]:
        kind = block.get("type") if isinstance(block, dict) else None
        if kind == "toolCall":
            _exact(block, {"type"})
            calls += 1
        elif kind == "thinking":
            _exact(block, {"type", "thinkingSignature"}, {"redacted"})
            if not isinstance(block["thinkingSignature"], str) or not block["thinkingSignature"] or ("redacted" in block and type(block["redacted"]) is not bool):
                _fail("invalid_continuation")
            _validate_thinking_signature(block["thinkingSignature"])
        elif kind == "text":
            _exact(block, {"type", "text"}, {"textSignature"})
            if not isinstance(block["text"], str) or ("textSignature" in block and not isinstance(block["textSignature"], str)):
                _fail("invalid_continuation")
        else:
            _fail("invalid_continuation")
    if calls != 1:
        _fail("invalid_continuation")
    return json.loads(canonical(value))


def _validate_thinking_signature(signature: str) -> None:
    try:
        item = json.loads(signature)
    except (ValueError, RecursionError):
        _fail("invalid_continuation")
    _exact(item, {"id", "type", "summary"}, {"encrypted_content", "status"})
    if item["type"] != "reasoning" or not isinstance(item["id"], str) or not isinstance(item["summary"], list):
        _fail("invalid_continuation")
    for entry in item["summary"]:
        _exact(entry, {"type", "text"})
        if entry["type"] != "summary_text" or not isinstance(entry["text"], str):
            _fail("invalid_continuation")
    if "encrypted_content" in item and item["encrypted_content"] is not None and not isinstance(item["encrypted_content"], str):
        _fail("invalid_continuation")
    if "status" in item and item["status"] not in {"in_progress", "completed", "incomplete"}:
        _fail("invalid_continuation")


def runtime_path() -> Path:
    path = Path(str(importlib.resources.files("autofv").joinpath("pi_runtime")))
    if not path.is_dir() or not (path / "transport.mjs").is_file():
        _fail("runtime_resources_missing")
    return path.resolve()


def _node_path(node_path: str | Path) -> Path:
    path = Path(node_path)
    if not path.is_absolute():
        _fail("node_path_not_absolute")
    path = path.resolve(strict=True)
    meta = path.stat()
    if not stat.S_ISREG(meta.st_mode) or not os.access(path, os.X_OK) or meta.st_mode & 0o022:
        _fail("unsafe_node_executable")
    return path


def minimal_environment(node_path: Path, directory: Path) -> dict[str, str]:
    return {"PATH": str(node_path.parent), "HOME": str(directory), "TMPDIR": str(directory),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC", "PI_OFFLINE": "1"}


def _runtime_identity(node: Path, packages: dict[str, str]) -> dict[str, Any]:
    root = runtime_path()
    files = sorted([*root.glob("*.mjs"), root / "tool-schemas.json", root / "package.json"], key=lambda p: p.name)
    bridge = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    # Qualification binds bytes actually executed, not merely package metadata.
    modules = root / "node_modules"
    if not modules.is_dir() or modules.is_symlink():
        _fail("sdk_not_installed")
    dependency_bytes: dict[str, str] = {}
    module_root = modules.resolve()
    for path in sorted(modules.rglob("*")):
        relative = path.relative_to(modules).as_posix()
        if path.is_symlink():
            try:
                path.resolve(strict=True).relative_to(module_root)
            except (OSError, ValueError):
                _fail("sdk_symlink_outside_runtime")
            dependency_bytes[relative] = "link:" + os.readlink(path)
        elif path.is_file():
            dependency_bytes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    controller = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(root.parent.glob("*.py"))}
    checkout = root.parent.parent
    python_lock = {name: hashlib.sha256((checkout / name).read_bytes()).hexdigest()
                   for name in ("pyproject.toml", "uv.lock") if (checkout / name).is_file()}
    identity_material = {"bridge": bridge, "installed_node_files": dependency_bytes,
                         "trusted_controller": controller, "python_lock": python_lock}
    lock = root / "package-lock.json"
    if not lock.is_file():
        _fail("package_lock_missing")
    return {"schema": "autofv-pi-runtime-identity/v1", "protocol_version": 1,
            "node_sha256": hashlib.sha256(node.read_bytes()).hexdigest(), "bridge_sha256": hashlib.sha256(json.dumps(identity_material, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "package_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(), "packages": packages}


def runtime_diagnostic(node_path: str | Path) -> dict[str, Any]:
    """Inspect installed resources/metadata only; never initializes auth or a model."""
    node = _node_path(node_path)
    with tempfile.TemporaryDirectory(prefix="autofv-pi-doctor-") as temp:
        result = subprocess.run([str(node), str(runtime_path() / "transport.mjs"), "--diagnostic"],
            cwd=temp, env=minimal_environment(node, Path(temp)), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False, start_new_session=True)
    if result.returncode or len(result.stdout) > 8192 or result.stderr:
        _fail("runtime_diagnostic_failed")
    try:
        value = json.loads(result.stdout)
    except ValueError:
        _fail("runtime_diagnostic_failed")
    if value != {"protocol": PROTOCOL, "packages": SDK_VERSIONS}:
        _fail("runtime_metadata_mismatch")
    return {"runtime_identity": _runtime_identity(node, value["packages"]), "credential_accessed": False,
            "model_dispatched": False, "account_identity_verified": False, "server_output_cap": None}


class PiProcess:
    """One long-lived run process. A failure quarantines it permanently."""
    def __init__(self, node_path: str | Path, *, store_path: str | Path,
                 account_binding_sha256: str, runtime_dir: str | Path | None = None):
        self.node = _node_path(node_path)
        self.store_path = Path(store_path)
        if not self.store_path.is_absolute() or not re.fullmatch(r"[a-f0-9]{64}", account_binding_sha256):
            _fail("invalid_store_binding")
        self.account_binding_sha256 = account_binding_sha256
        if runtime_dir is not None:
            parent = Path(runtime_dir)
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            meta = parent.lstat()
            if parent.is_symlink() or not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
                _fail("unsafe_runtime_directory")
        self._temp = tempfile.TemporaryDirectory(prefix="autofv-pi-", dir=runtime_dir)
        self.directory = Path(self._temp.name)
        self._lock, self._write_lock = threading.Lock(), threading.Lock()
        self._termination_lock = threading.Lock()
        self._terminated = False
        self._seen_ids: set[str] = set()
        self._seen_sequences: set[int] = set()
        self._quarantined = False
        self._closed = False
        self._active: dict[str, Any] | None = None
        self._pending = bytearray()
        self._stderr_bytes = 0
        self.process = self._spawn()
        assert self.process.stdin and self.process.stdout and self.process.stderr
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(pipe.fileno(), False)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self.process.stdout, selectors.EVENT_READ, "stdout")
        self._selector.register(self.process.stderr, selectors.EVENT_READ, "stderr")
        try:
            deadline = time.monotonic() + 15
            self._send({"v": 1, "op": "hello"}, deadline)
            hello = self._receive(deadline)
            if hello != {"v": 1, "op": "hello", "protocol": PROTOCOL, "packages": SDK_VERSIONS}:
                _fail("hello_mismatch")
        except BaseException:
            self._quarantined = True
            self.close()
            raise

    def _spawn(self) -> subprocess.Popen[bytes]:
        return subprocess.Popen([str(self.node), str(runtime_path() / "transport.mjs"),
                                 str(self.store_path), self.account_binding_sha256],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.directory, env=minimal_environment(self.node, self.directory),
            start_new_session=True, close_fds=True, shell=False, bufsize=0)

    def _send(self, value: dict[str, Any], deadline: float) -> None:
        raw = canonical(value) + b"\n"
        if len(raw) > MAX_FRAME_BYTES + 1:
            _fail("frame_limit")
        if not self._write_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            _fail("write_timeout_uncertain")
        try:
            offset = 0
            while offset < len(raw):
                if time.monotonic() >= deadline:
                    _fail("request_timeout_uncertain")
                try:
                    offset += os.write(self.process.stdin.fileno(), raw[offset:])
                except BlockingIOError:
                    # Keep large-input backpressure bounded by the original deadline.
                    time.sleep(min(.005, max(0, deadline - time.monotonic())))
                except (BrokenPipeError, OSError):
                    _fail("process_closed_uncertain")
        finally:
            self._write_lock.release()

    def _receive(self, deadline: float) -> dict[str, Any]:
        while True:
            if b"\n" in self._pending:
                raw, _, remainder = self._pending.partition(b"\n")
                self._pending = bytearray(remainder)
                value = _decode(bytes(raw))
                if value.get("op") == "error":
                    _exact(value, {"v", "op", "request_id", "sequence", "code"})
                    code = value["code"]
                    if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code):
                        _fail("invalid_error_frame")
                    _fail(code)
                return value
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("request_timeout_uncertain")
            for key, _ in self._selector.select(min(remaining, .1)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    self._selector.unregister(key.fileobj)
                    if key.data == "stdout":
                        _fail("process_closed_uncertain")
                    continue
                if key.data == "stderr":
                    self._stderr_bytes += len(chunk)
                    # Never retain/log SDK stderr, even on failure.
                    if self._stderr_bytes > 65536:
                        _fail("stderr_limit")
                else:
                    self._pending.extend(chunk)
                    if len(self._pending) > MAX_FRAME_BYTES + 1:
                        _fail("frame_limit")
            if self.process.poll() is not None and not self._pending:
                _fail("process_closed_uncertain")

    def generate_one(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._closed or self._quarantined:
                _fail("process_quarantined")
            _exact(payload, {"request", "messages", "profile", "continuations", "admission", "tools"})
            request = _exact(payload["request"], REQUEST_KEYS)
            admission = _exact(payload["admission"], {"deadline_ms", "sequence", "request_id"})
            if admission["sequence"] != request["sequence"] or admission["request_id"] != request["request_id"] or type(admission["deadline_ms"]) is not int:
                _fail("invalid_admission")
            if request["request_id"] in self._seen_ids or request["sequence"] in self._seen_sequences:
                self._quarantined = True
                _fail("duplicate_request")
            self._seen_ids.add(request["request_id"])
            self._seen_sequences.add(request["sequence"])
            deadline = time.monotonic() + max(0, admission["deadline_ms"] / 1000 - time.time())
            self._active = request
            try:
                self._send({"v": 1, "op": "generate_one", "payload": payload}, deadline)
                frame = self._receive(deadline)
                _exact(frame, {"v", "op", "request_id", "sequence", "result"})
                if frame["op"] != "result" or frame["request_id"] != request["request_id"] or frame["sequence"] != request["sequence"]:
                    _fail("response_identity_mismatch")
                result = _exact(frame["result"], {"request_id", "sequence", "tool_call", "usage", "provider_response_id", "observed_model", "requested_effort", "observed_effort", "continuation"})
                if result["request_id"] != request["request_id"] or result["sequence"] != request["sequence"]:
                    _fail("response_identity_mismatch")
                validate_continuation(result["continuation"], request, result)
                if self._quarantined:
                    _fail("request_aborted_uncertain")
                return result
            except BaseException:
                self._quarantined = True
                self.cancel()
                raise
            finally:
                self._active = None

    def cancel(self) -> None:
        self._quarantined = True
        if self._closed:
            return
        if self._active:
            try:
                self._send({"v": 1, "op": "cancel", "request_id": self._active["request_id"], "sequence": self._active["sequence"]}, time.monotonic() + .2)
            except (PiProcessError, OSError, ValueError):
                pass
        self._terminate_group()

    def _terminate_group(self) -> None:
        # Serialize cancellation/cleanup; never signal an already reaped group ID.
        with self._termination_lock:
            if self._terminated:
                return
            # Kill the entire session even if its leader exited, then reap the leader.
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=.3)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=2)
            self._terminated = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.process.poll() is None:
                try:
                    self._send({"v": 1, "op": "close"}, time.monotonic() + .2)
                except (PiProcessError, OSError, ValueError):
                    pass
            self._terminate_group()
        finally:
            self._selector.close()
            for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
                if pipe:
                    pipe.close()
            self._temp.cleanup()

    def __enter__(self) -> "PiProcess":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
