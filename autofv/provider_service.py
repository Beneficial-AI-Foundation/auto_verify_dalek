"""Trusted fixed-route HTTP service and durable provider dispatch journal."""

from __future__ import annotations

import copy
import hashlib
import hmac
import http.server
import json
import os
import socket
import stat
import threading
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from .contracts import ContractError, canonical_json_bytes
from . import (
    preflight,
    provider_config,
    provider_messages,
    provider_receipts,
    provider_transport,
)


JOURNAL_SCHEMA = provider_receipts.PROVIDER_JOURNAL_SCHEMA
FAILURE_COMPANION_SCHEMA = "autofv-provider-failure-companion/v1"
REJECTED_RESPONSE_SCHEMA = provider_receipts.REJECTED_RESPONSE_SCHEMA
_JOURNAL_FIELDS = frozenset({
    "schema", "status", "run_id", "request_id", "sequence", "request_sha256",
    "messages_sha256", "binding_sha256", "reservation_usd", "response", "receipt", "auth",
    "record_sha256",
})


@dataclass
class _Service:
    server: http.server.ThreadingHTTPServer
    thread: threading.Thread
    local_base: str
    context: "_DispatchContext"


class _DispatchContext:
    """Serialize dispatch with checkpoint-state reattachment."""

    def __init__(
        self, run: dict[str, Any], binding: provider_config.ProviderBinding
    ) -> None:
        self._binding_sha256 = binding.public["binding_sha256"]
        self._run = run
        self._lock = threading.Lock()

    def reattach(
        self, run: dict[str, Any], binding: provider_config.ProviderBinding
    ) -> None:
        if binding.public["binding_sha256"] != self._binding_sha256:
            raise provider_transport.ProviderError(
                "provider service binding changed",
                classification="upstream_error",
            )
        with self._lock:
            self._run = run

    def dispatch(
        self, request: dict[str, Any], *, run_token: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        with self._lock:
            return dispatch(self._run, request, run_token=run_token)


_SERVICES: dict[str, _Service] = {}
_SERVICES_LOCK = threading.Lock()


class _BoundedHTTPServer(http.server.ThreadingHTTPServer):
    """Fixed-capacity service that drops excess and lingering clients."""

    daemon_threads = True
    block_on_close = False
    request_queue_size = 8

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(8)
        self._active: set[socket.socket] = set()
        self._active_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        with self._active_lock:
            self._active.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._active_lock:
                self._active.discard(request)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active.discard(request)
            self._slots.release()

    def close_active(self) -> None:
        with self._active_lock:
            active = tuple(self._active)
            self._active.clear()
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _journal_path(run: dict[str, Any], request_id: str) -> Path:
    name = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
    return Path(run["evidence_dir"]) / "provider-journal" / f"{name}.json"


def _record(
    binding: provider_config.ProviderBinding,
    request: dict[str, Any],
    messages_sha256: str,
    reservation_usd: str,
    status: str,
    *,
    response: dict[str, Any] | None = None,
    receipt: dict[str, Any] | None = None,
    schema: str = JOURNAL_SCHEMA,
) -> dict[str, Any]:
    if schema not in {JOURNAL_SCHEMA, FAILURE_COMPANION_SCHEMA}:
        raise provider_transport.ProviderError("unknown provider record purpose")
    body = {
        "schema": schema,
        "status": status,
        "run_id": binding.public["run_id"],
        "request_id": request["request_id"],
        "sequence": request["sequence"],
        "request_sha256": _sha(request),
        "messages_sha256": messages_sha256,
        "binding_sha256": binding.public["binding_sha256"],
        "reservation_usd": reservation_usd,
        "response": copy.deepcopy(response),
        "receipt": copy.deepcopy(receipt),
    }
    auth = provider_receipts._sign(binding, body)
    signed = {**body, "auth": auth}
    return {**signed, "record_sha256": _sha(signed)}


def _normalize_rejected_response(value: Any) -> Any:
    if isinstance(value, Decimal):
        provider_messages.bounded_decimal(value)
        return format(value, "f")
    if isinstance(value, list):
        return [_normalize_rejected_response(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _normalize_rejected_response(item)
            for key, item in sorted(value.items())
        }
    return value


_validate_rejected_response = provider_receipts.validate_rejected_response


def _validate_record(
    value: Any,
    binding: provider_config.ProviderBinding,
    request: dict[str, Any],
    *, schema: str = JOURNAL_SCHEMA,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _JOURNAL_FIELDS:
        raise provider_transport.ProviderError("provider journal fields mismatch")
    signed = {key: item for key, item in value.items() if key != "record_sha256"}
    body = {key: item for key, item in signed.items() if key != "auth"}
    expected = {
        "schema": schema,
        "run_id": binding.public["run_id"],
        "request_id": request["request_id"],
        "sequence": request["sequence"],
        "request_sha256": _sha(request),
        "binding_sha256": binding.public["binding_sha256"],
    }
    if (
        any(value.get(key) != item for key, item in expected.items())
        or value.get("status")
        not in {"reserved", "dispatched", "rejected", "completed"}
        or not isinstance(value.get("messages_sha256"), str)
        or value.get("record_sha256") != _sha(signed)
        or not provider_receipts.is_reservation(value.get("reservation_usd"))
    ):
        raise provider_transport.ProviderError("provider journal identity mismatch")
    if schema == FAILURE_COMPANION_SCHEMA and value["status"] != "rejected":
        raise provider_transport.ProviderError("provider failure companion purpose mismatch")
    provider_receipts.verify_signature(
        body, value["auth"], binding.public["receipt_authentication"], "provider journal"
    )
    if value["status"] == "completed":
        if not isinstance(value["response"], dict) or not isinstance(
            value["receipt"], dict
        ):
            raise provider_transport.ProviderError(
                "provider journal completion mismatch"
            )
    elif value["status"] == "rejected":
        if (
            not isinstance(value["response"], dict)
            or value["receipt"] is not None
        ):
            raise provider_transport.ProviderError(
                "provider journal rejection mismatch"
            )
        _validate_rejected_response(value["response"])
    elif value["response"] is not None or value["receipt"] is not None:
        raise provider_transport.ProviderError("provider journal completion mismatch")
    return value


def _load(
    path: Path,
    binding: provider_config.ProviderBinding,
    request: dict[str, Any],
    *, schema: str = JOURNAL_SCHEMA,
) -> dict[str, Any] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise provider_transport.ProviderError("provider journal path is unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2_000_000:
            raise provider_transport.ProviderError("provider journal path is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(2_000_001)
        if len(raw) > 2_000_000:
            raise provider_transport.ProviderError("provider journal is too large")
        value = json.loads(raw)
        if raw != canonical_json_bytes(value) + b"\n":
            raise provider_transport.ProviderError("provider journal is not canonical")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ContractError, RecursionError) as exc:
        raise provider_transport.ProviderError("provider journal is unreadable") from exc
    finally:
        os.close(descriptor)
    provider_messages.scan_response(value, binding, raw=raw)
    return _validate_record(value, binding, request, schema=schema)


def _load_failure_companion(
    path: Path, binding: provider_config.ProviderBinding, request: dict[str, Any],
) -> dict[str, Any] | None:
    return _load(path, binding, request, schema=FAILURE_COMPANION_SCHEMA)


def _write(path: Path, value: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{threading.get_ident()}.tmp")
        raw = canonical_json_bytes(value) + b"\n"
        with temporary.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise provider_transport.ProviderError(
            "provider journal is unavailable", classification="upstream_error"
        ) from exc
    finally:
        if "temporary" in locals():
            temporary.unlink(missing_ok=True)


def _remember(run: dict[str, Any], value: dict[str, Any]) -> None:
    run.setdefault("provider_journal", {})[value["request_id"]] = value["record_sha256"]


def _check_remembered(
    run: dict[str, Any],
    binding: provider_config.ProviderBinding,
    request: dict[str, Any],
    existing: dict[str, Any] | None,
) -> None:
    remembered = run.get("provider_journal")
    if remembered is None:
        return
    if not isinstance(remembered, dict) or any(
        not isinstance(key, str) or not isinstance(digest, str) or len(digest) != 64
        for key, digest in remembered.items()
    ):
        raise provider_transport.ProviderError("provider journal memory is invalid")
    digest = remembered.get(request["request_id"])
    if digest is None:
        return
    if existing is None:
        raise provider_transport.ProviderError("provider journal memory changed")
    allowed = {existing["record_sha256"]}
    messages_sha256 = existing["messages_sha256"]
    if existing["status"] in {"dispatched", "rejected", "completed"}:
        allowed.add(
            _record(
                binding, request, messages_sha256, existing["reservation_usd"], "reserved"
            )["record_sha256"]
        )
    if existing["status"] in {"rejected", "completed"}:
        allowed.add(
            _record(
                binding, request, messages_sha256, existing["reservation_usd"], "dispatched"
            )["record_sha256"]
        )
    if digest not in allowed:
        raise provider_transport.ProviderError("provider journal memory changed")


validate_provider_receipt = provider_receipts.validate_receipt
validate_provider_preflight = provider_receipts.validate_preflight
_write_preflight = provider_receipts.write_preflight


def validate_pinned_receipt(receipt: Any, *, run: dict[str, Any], **bindings: Any):
    return provider_receipts.validate_receipt(
        receipt, binding=provider_transport.pinned_public_binding(run), **bindings
    )


def validate_pinned_preflight(path: str | Path, *, run: dict[str, Any]):
    return provider_receipts.validate_preflight(
        path, expected_binding=provider_transport.pinned_public_binding(run)
    )


def load_preflight_authorization(
    run: dict[str, Any],
    *,
    preflight_path: str | Path,
    suite_artifact_path: str | Path,
    max_age_seconds: int,
) -> dict[str, Any]:
    """Load sealed evidence and bind it to the process-held provider identity."""
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise provider_transport.ProviderError("provider binding is unavailable")
    try:
        body, record = preflight.load_provider_evidence(
            run,
            binding.public,
            preflight_path=preflight_path,
            suite_artifact_path=suite_artifact_path,
            max_age_seconds=max_age_seconds,
        )
    except ContractError as exc:
        raise provider_transport.ProviderError(
            "provider preflight evidence loading failed"
        ) from exc
    authorization = {**body, "auth": provider_receipts._sign(binding, body)}
    run["deterministic_preflight"] = authorization
    run["deterministic_preflight_sha256"] = record["preflight_sha256"]
    run["deterministic_suite_sha256"] = record["suite_sha256"]
    return copy.deepcopy(authorization)


def _validate_completed_exchange(
    binding: provider_config.ProviderBinding,
    request: dict[str, Any],
    response: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    provider_transport.validate_dispatch_request(binding, request)
    provider_messages.scan_response(response, binding)
    provider_messages.scan_response(receipt, binding)
    if not isinstance(response, dict) or any(
        response.get(field) != request.get(field)
        for field in (
            "run_id", "sequence", "batch_id", "request_id", "role", "model_id",
            "input_hashes", "prompt_sha256",
        )
    ):
        raise provider_transport.ProviderError("provider completed response identity mismatch")
    provider_receipts.validate_receipt(
        receipt,
        binding=binding.public,
        run_id=request["run_id"],
        sequence=request["sequence"],
        request_id=request["request_id"],
        model_id=request["model_id"],
        request_sha256=_sha(request),
        response_sha256=_sha(response),
        seen_receipt_sha256=frozenset(),
    )


def _handler(
    context: _DispatchContext, binding: provider_config.ProviderBinding
):
    route_path = binding.route_path

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(5.0)

        def _send(self, status: int, value: dict[str, Any]) -> None:
            raw = canonical_json_bytes(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def do_POST(self) -> None:  # noqa: N802
            if self.path != route_path:
                self._send(404, {"error": "rejected"})
                return
            if self.headers.get("Authorization") or self.headers.get("X-AutoFV-Upstream-Host"):
                self._send(403, {"error": "caller authority forbidden"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
                if not 0 < length <= provider_messages.MAX_WIRE_BYTES:
                    raise ValueError("invalid request length")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("incomplete request body")
                request = provider_messages.strict_request_json(raw)
                response, receipt = context.dispatch(
                    request, run_token=self.headers.get("X-AutoFV-Run-Token", "")
                )
            except provider_transport.ProviderError as exc:
                status = {
                    "authentication_error": 401,
                    "timeout": 504,
                    "rate_limited": 429,
                    "malformed_response": 400,
                }.get(exc.classification, 502)
                self._send(status, {"error": "provider service rejected"})
                return
            except (TypeError, ValueError):
                self._send(400, {"error": "provider service rejected"})
                return
            self._send(200, {"response": response, "receipt": receipt})

        def do_GET(self) -> None:  # noqa: N802
            self._send(405 if self.path == route_path else 404, {"error": "rejected"})

        def do_CONNECT(self) -> None:  # noqa: N802
            self._send(405, {"error": "rejected"})

        def log_message(self, *_args) -> None:
            return

    return Handler


def _serve(handler, port: int = 0):
    return _BoundedHTTPServer(("0.0.0.0", port), handler)


def _stop_service(service: _Service) -> None:
    stopper = threading.Thread(target=service.server.shutdown, daemon=True)
    try:
        stopper.start()
        stopper.join(timeout=1)
    finally:
        try:
            close_active = getattr(service.server, "close_active", None)
            if callable(close_active):
                close_active()
        finally:
            try:
                service.server.server_close()
            finally:
                service.thread.join(timeout=1)
    if stopper.is_alive() or service.thread.is_alive():
        raise provider_transport.ProviderError("provider service cleanup did not finish")


def _record_service(run: dict[str, Any], digest: str, service: _Service) -> str:
    run["provider_service"] = {
        "schema": "autofv-provider-service/v1",
        "binding_sha256": digest,
        "local_base_sha256": hashlib.sha256(service.local_base.encode()).hexdigest(),
        "port": service.server.server_port,
    }
    run["proxy_base"] = service.local_base
    return service.local_base


def start(run: dict[str, Any]) -> str:
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise provider_transport.ProviderError("provider binding is unavailable")
    digest = binding.public["binding_sha256"]
    with _SERVICES_LOCK:
        existing = _SERVICES.get(digest)
        if existing is not None:
            existing.context.reattach(run, binding)
            return _record_service(run, digest, existing)
        context = _DispatchContext(run, binding)
        try:
            server = _serve(_handler(context, binding))
        except OSError as exc:
            raise provider_transport.ProviderError(
                "provider service unavailable", classification="upstream_error"
            ) from exc
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"autofv-provider-{digest[:12]}",
            daemon=True,
        )
        local_base = f"http://127.0.0.1:{server.server_port}"
        _SERVICES[digest] = _Service(server, thread, local_base, context)
        try:
            thread.start()
        except RuntimeError as exc:
            _SERVICES.pop(digest, None)
            server.server_close()
            raise provider_transport.ProviderError(
                "provider service unavailable", classification="upstream_error"
            ) from exc
    return _record_service(run, digest, _SERVICES[digest])


def rebind(
    run: dict[str, Any],
    *,
    required_port: int | None = None,
    forbidden_ports: frozenset[int] = frozenset(),
) -> str:
    """Rotate only transient listener state while preserving stable provider identity."""
    if (
        required_port is not None
        and (
            type(required_port) is not int
            or not 1 <= required_port <= 65535
            or forbidden_ports
        )
    ):
        raise provider_transport.ProviderError(
            "provider service listener requirement is invalid",
            classification="upstream_error",
        )
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise provider_transport.ProviderError("provider binding is unavailable")
    digest = binding.public["binding_sha256"]
    with _SERVICES_LOCK:
        previous = _SERVICES.get(digest)
        if (
            previous is not None
            and required_port is not None
            and previous.server.server_port == required_port
        ):
            previous.context.reattach(run, binding)
            return _record_service(run, digest, previous)
        server = None
        context = _DispatchContext(run, binding)
        attempts = 1 if required_port is not None else 16
        for _attempt in range(attempts):
            try:
                candidate = (
                    _serve(_handler(context, binding), required_port)
                    if required_port is not None
                    else _serve(_handler(context, binding))
                )
            except OSError as exc:
                raise provider_transport.ProviderError(
                    "provider service unavailable", classification="upstream_error"
                ) from exc
            if (
                required_port is not None
                and candidate.server_port != required_port
            ):
                candidate.server_close()
                raise provider_transport.ProviderError(
                    "provider service did not bind its required listener port",
                    classification="upstream_error",
                )
            if required_port is not None or candidate.server_port not in forbidden_ports:
                server = candidate
                break
            candidate.server_close()
        if server is None:
            raise provider_transport.ProviderError(
                "provider service could not rotate its transient port",
                classification="upstream_error",
            )
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"autofv-provider-{digest[:12]}",
            daemon=True,
        )
        replacement = _Service(
            server,
            thread,
            f"http://127.0.0.1:{server.server_port}",
            context,
        )
        try:
            thread.start()
        except RuntimeError as exc:
            server.server_close()
            raise provider_transport.ProviderError(
                "provider service unavailable", classification="upstream_error"
            ) from exc
        _SERVICES[digest] = replacement
    if previous is not None:
        _stop_service(previous)
    return _record_service(run, digest, replacement)


def relay_base(run: dict[str, Any], host_address: str) -> str:
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise provider_transport.ProviderError("provider binding is unavailable")
    with _SERVICES_LOCK:
        service = _SERVICES.get(binding.public["binding_sha256"])
    if service is None:
        start(run)
        with _SERVICES_LOCK:
            service = _SERVICES[binding.public["binding_sha256"]]
    return f"http://{host_address}:{service.server.server_port}"


def dispatch(
    run: dict[str, Any], request: dict[str, Any], *, run_token: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise provider_transport.ProviderError("provider binding is unavailable")
    if (
        not isinstance(run_token, str)
        or not run_token
        or len(run_token.encode("utf-8")) > 4096
        or any(ord(character) < 32 for character in run_token)
    ):
        raise provider_transport.ProviderError(
            "provider service authentication failed", classification="authentication_error"
        )
    token_sha256 = hashlib.sha256(run_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(token_sha256, binding.public["client_identity_sha256"]):
        raise provider_transport.ProviderError(
            "provider service authentication failed", classification="authentication_error"
        )
    provider_transport.validate_dispatch_request(binding, request)
    path = _journal_path(run, request["request_id"])
    with binding.lock:
        existing = _load(path, binding, request)
        if existing is not None and existing["status"] == "completed":
            _validate_completed_exchange(binding, request, existing["response"], existing["receipt"])
        _check_remembered(run, binding, request, existing)
        if existing is not None and existing["status"] == "completed":
            _remember(run, existing)
            return copy.deepcopy(existing["response"]), copy.deepcopy(existing["receipt"])
        if existing is not None and existing["status"] == "rejected":
            raise provider_transport.ProviderError(
                "previous provider response was rejected",
                classification=existing["response"]["classification"],
            )
        if existing is not None and existing["status"] == "dispatched":
            raise provider_transport.ProviderError(
                "provider dispatch outcome is ambiguous", classification="upstream_error"
            )
        messages_sha256 = provider_messages.staged_messages_sha256(binding, request)
        if existing is None:
            # The controller reserved this same amount from the same messages.
            reservation_usd = provider_transport.reservation_usd(
                run, request, provider_messages.staged_messages(binding, request)
            )
            existing = _record(
                binding, request, messages_sha256, f"{reservation_usd:.6f}", "reserved"
            )
            _write(path, existing)
        elif existing["messages_sha256"] != messages_sha256:
            raise provider_transport.ProviderError("provider journal message identity mismatch")
        try:
            preflight.authorize_provider_action(run, binding.public)
        except (ContractError, provider_transport.ProviderError) as exc:
            raise provider_transport.ProviderError(
                "provider preflight authorization failed"
            ) from exc
        handoff = run.get("helper_handoff")
        if handoff is not None and "first_scored_request_id" not in handoff:
            from .preflight_runner import validate_helper_handoff
            try:
                validate_helper_handoff(run)
            except (ContractError, provider_transport.ProviderError, OSError, KeyError, TypeError) as exc:
                raise provider_transport.ProviderError("helper handoff validation failed") from exc
        reservation_usd = existing["reservation_usd"]
        dispatched = _record(
            binding, request, messages_sha256, reservation_usd, "dispatched"
        )
        _write(path, dispatched)
        _remember(run, dispatched)
        if handoff is not None:
            handoff.setdefault("first_scored_request_id", request["request_id"])

    try:
        response, receipt = provider_transport.provider_round(run, request)
    except provider_transport.ProviderError as exc:
        if exc.provider_response is not None:
            normalized_response = _normalize_rejected_response(exc.provider_response)
            rejected_response = {
                "schema": REJECTED_RESPONSE_SCHEMA,
                "classification": exc.classification,
                "message": str(exc),
                "provider_response": normalized_response,
                "provider_response_sha256": _sha(normalized_response),
            }
            _validate_rejected_response(rejected_response)
            provider_messages.scan_response(rejected_response, binding)
            rejected = _record(
                binding,
                request,
                messages_sha256,
                reservation_usd,
                "rejected",
                response=rejected_response,
                schema=FAILURE_COMPANION_SCHEMA if getattr(exc, "retain_dispatch_ambiguity", False) else JOURNAL_SCHEMA,
            )
            with binding.lock:
                if getattr(exc, "retain_dispatch_ambiguity", False):
                    # Transport failure cannot establish whether upstream received or billed the call.
                    _write(path.with_suffix(".failure"), rejected)
                else:
                    _write(path, rejected)
                    _remember(run, rejected)
        raise
    completed = _record(
        binding,
        request,
        messages_sha256,
        reservation_usd,
        "completed",
        response=response,
        receipt=receipt,
    )
    provider_messages.scan_response(completed, binding)
    with binding.lock:
        _write(path, completed)
        _remember(run, completed)
        _write_preflight(binding, run, request, response, receipt)
    return response, receipt


def release(run: dict[str, Any]) -> None:
    digest = run.get("provider_binding_sha256")
    with _SERVICES_LOCK:
        service = _SERVICES.get(digest)
    try:
        if service is not None:
            _stop_service(service)
            with _SERVICES_LOCK:
                if _SERVICES.get(digest) is service:
                    _SERVICES.pop(digest)
    finally:
        # A failed/interrupted stop remains discoverable, but cannot retain dispatch authority.
        provider_config.release_provider(run)


def is_running(digest: str) -> bool:
    with _SERVICES_LOCK:
        return digest in _SERVICES
