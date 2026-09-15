"""One trusted OpenAI-compatible transport with signed provider accounting."""
from __future__ import annotations

import http.client
import json
import re
import socket
import time
import urllib.error
import urllib.request
from decimal import Decimal, ROUND_CEILING
from typing import Any

from .contracts import canonical_json_bytes
from . import provider_deadline, provider_messages, provider_receipts
from .provider_config import (
    ProviderBinding,
    ProviderConfigError,
    canonical_sha256 as _sha,
    configure_provider as _configure_provider,
    exact_dict as _config_exact,
    provider_binding as _provider_binding,
)


MAX_WIRE_BYTES = provider_messages.MAX_WIRE_BYTES
MAX_MESSAGE_BYTES = provider_messages.MAX_MESSAGE_BYTES
PROVIDER_RECEIPT_SCHEMA = provider_receipts.PROVIDER_RECEIPT_SCHEMA
PROVIDER_PREFLIGHT_SCHEMA = provider_receipts.PROVIDER_PREFLIGHT_SCHEMA
_REQUEST_FIELDS = frozenset({
    "schema", "run_id", "sequence", "batch_id", "request_id", "role",
    "model_id", "input_hashes", "prompt_sha256",
})
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REVIEW_ROLES = frozenset({
    "scout", "dependency-planner", "dependency_planner", "contract-reviewer",
    "spec_reviewer", "specification_reviewer", "proof_reviewer", "verification_adviser",
})


ProviderError = ProviderConfigError


_open_upstream = provider_deadline.open_upstream


def _remaining_seconds(deadline_monotonic_ns: int) -> float:
    remaining = (deadline_monotonic_ns - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise ProviderError("provider timeout", classification="timeout")
    return min(30.0, remaining)


def _read_upstream(reply: Any, deadline_monotonic_ns: int) -> bytes:
    read_once = getattr(reply, "read1", None)
    if not callable(read_once):
        provider_deadline.set_reply_timeout(
            reply, _remaining_seconds(deadline_monotonic_ns)
        )
        try:
            raw = reply.read(MAX_WIRE_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            if getattr(reply, "deadline_expired", False):
                raise ProviderError(
                    "provider timeout", classification="timeout"
                ) from exc
            raise
        _remaining_seconds(deadline_monotonic_ns)
        if not isinstance(raw, bytes):
            raise ProviderError("provider response body is invalid")
        if len(raw) > MAX_WIRE_BYTES:
            raise ProviderError("provider response is too large")
        return raw
    chunks: list[bytes] = []
    size = 0
    while True:
        provider_deadline.set_reply_timeout(
            reply, _remaining_seconds(deadline_monotonic_ns)
        )
        try:
            chunk = read_once(min(65_536, MAX_WIRE_BYTES + 1 - size))
        except (OSError, http.client.HTTPException) as exc:
            if getattr(reply, "deadline_expired", False):
                raise ProviderError(
                    "provider timeout", classification="timeout"
                ) from exc
            raise
        _remaining_seconds(deadline_monotonic_ns)
        if not chunk:
            return b"".join(chunks)
        if not isinstance(chunk, bytes):
            raise ProviderError("provider response body is invalid")
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_WIRE_BYTES:
            raise ProviderError("provider response is too large")


def _strict_json(raw: bytes, label: str) -> Any:
    return provider_messages.strict_json(raw, label)


def strict_request_json(raw: bytes) -> dict[str, Any]:
    return provider_messages.strict_request_json(raw)


def _bounded_wire(value: Any, *, depth: int = 0) -> int:
    return provider_messages.bounded_wire(value, depth=depth)


def _provider_json(raw: bytes) -> Any:
    return provider_messages.provider_json(raw)


def scan_response_secrets(
    value: Any,
    binding: ProviderBinding,
    *,
    raw: bytes | None = None,
) -> None:
    provider_messages.scan_response(value, binding, raw=raw)


_scan_response_secrets = scan_response_secrets


def _shape(
    value: Any,
    required: set[str],
    optional: set[str],
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or not set(value) <= required | optional
    ):
        raise ProviderError(f"{label} fields mismatch")
    return value


def _bounded_text(value: Any, limit: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeEncodeError:
        return False


_exact = _config_exact
configure_provider = _configure_provider
_binding = _provider_binding


def is_configured(run: dict[str, Any]) -> bool:
    return _binding(run) is not None


def pinned_public_binding(run: dict[str, Any]) -> dict[str, Any]:
    binding = _binding(run)
    if binding is None:
        raise ProviderError("provider binding is not configured")
    return json.loads(canonical_json_bytes(binding.public))


def _messages(value: Any) -> list[dict[str, Any]]:
    return provider_messages.validate_messages(value)


def messages_sha256(value: Any) -> str:
    return provider_messages.messages_sha256(value)


def stage_messages(
    run: dict[str, Any],
    request: dict[str, Any],
    value: Any,
    *,
    timeout_seconds: float = 30,
) -> bool:
    """Stage trusted messages process-locally; never add transcript text to run state."""
    binding = _binding(run)
    if binding is None:
        return False
    validate_dispatch_request(binding, request)
    provider_messages.stage_messages(
        binding, request, value, timeout_seconds=timeout_seconds
    )
    return True


def discard_messages(run: dict[str, Any], request_id: str) -> None:
    binding = _binding(run)
    provider_messages.discard_messages(binding, request_id)


def staged_messages_sha256(
    binding: ProviderBinding, request: dict[str, Any]
) -> str:
    return provider_messages.staged_messages_sha256(binding, request)


def _take_messages(
    binding: ProviderBinding, request: dict[str, Any]
) -> tuple[list[dict[str, Any]], int]:
    return provider_messages.take_messages(binding, request)


def validate_dispatch_request(binding: ProviderBinding, request: Any) -> dict[str, Any]:
    """Validate a relay dispatch against independently pinned process state."""
    if not isinstance(request, dict) or set(request) != _REQUEST_FIELDS:
        raise ProviderError("provider dispatch fields mismatch")
    if (
        request.get("schema") != "autofv-model-request/v1"
        or request.get("run_id") != binding.public["run_id"]
        or request.get("model_id") != binding.model_id
        or type(request.get("sequence")) is not int
        or request["sequence"] <= 0
        or not _bounded_text(request.get("request_id"), 512)
        or not _bounded_text(request.get("role"), 128)
        or (
            request.get("batch_id") is not None
            and not _bounded_text(request["batch_id"], 512)
        )
        or not isinstance(request.get("input_hashes"), list)
        or any(
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
            for value in request["input_hashes"]
        )
        or request["input_hashes"] != sorted(set(request["input_hashes"]))
        or not isinstance(request.get("prompt_sha256"), str)
        or _SHA256.fullmatch(request["prompt_sha256"]) is None
    ):
        raise ProviderError("provider dispatch identity mismatch")
    return request


def _upstream_request(
    binding: ProviderBinding,
    request: dict[str, Any],
    messages: list[dict[str, Any]],
) -> dict[str, Any]:
    max_tokens = 4096 if request["role"] in _REVIEW_ROLES else 8192
    return {
        "model": binding.model_id,
        "messages": messages,
        "tools": binding.tools,
        "tool_choice": "required",
        "temperature": 0,
        "max_tokens": max_tokens,
        "stream": False,
    }


def reservation_usd(
    run: dict[str, Any], request: dict[str, Any], messages: Any
) -> Decimal:
    """Return a conservative authenticated-cost ceiling before dispatch."""
    binding = _binding(run)
    if binding is None:
        raise ProviderError("provider binding is not configured")
    validate_dispatch_request(binding, request)
    validated = _messages(messages)
    if _sha(validated) not in request["input_hashes"]:
        raise ProviderError("provider messages are not bound to the request")
    upstream = _upstream_request(binding, request, validated)
    input_tokens = len(canonical_json_bytes(upstream)) + 4096
    input_rate = max(
        Decimal(binding.pricing["input_usd_per_million"]),
        Decimal(binding.pricing["cached_input_usd_per_million"]),
    )
    amount = (
        Decimal(input_tokens) * input_rate
        + Decimal(upstream["max_tokens"])
        * Decimal(binding.pricing["output_usd_per_million"])
    ) / Decimal(1_000_000)
    return amount.quantize(Decimal("0.000001"), rounding=ROUND_CEILING)


def _provider_response(
    binding: ProviderBinding, request: dict[str, Any], value: Any, base_commit: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _shape(
        value,
        {"id", "model", "choices", "usage"},
        {"object", "created", "system_fingerprint", "service_tier", "provider"},
        "provider response",
    )
    if (
        not isinstance(value["id"], str)
        or not value["id"]
        or value["model"] != binding.model_id
        or not isinstance(value["choices"], list)
        or len(value["choices"]) != 1
        or ("object" in value and not isinstance(value["object"], str))
        or ("created" in value and (type(value["created"]) is not int or value["created"] < 0))
        or (
            "system_fingerprint" in value
            and value["system_fingerprint"] is not None
            and not isinstance(value["system_fingerprint"], str)
        )
        or (
            "service_tier" in value
            and value["service_tier"] is not None
            and not isinstance(value["service_tier"], str)
        )
        or ("provider" in value and not isinstance(value["provider"], str))
    ):
        raise ProviderError("provider response identity drift")
    choice = _shape(
        value["choices"][0],
        {"finish_reason", "message"},
        {"index", "logprobs", "native_finish_reason"},
        "provider choice",
    )
    message = _shape(
        choice["message"],
        {"role", "tool_calls"},
        {"content", "refusal", "annotations", "reasoning", "reasoning_details"},
        "provider message",
    )
    if (
        choice["finish_reason"] != "tool_calls"
        or ("index" in choice and type(choice["index"]) is not int)
        or (
            "logprobs" in choice
            and choice["logprobs"] is not None
            and not isinstance(choice["logprobs"], dict)
        )
        or (
            "native_finish_reason" in choice
            and choice["native_finish_reason"] is not None
            and not isinstance(choice["native_finish_reason"], str)
        )
        or message["role"] != "assistant"
        or not isinstance(message["tool_calls"], list)
        or len(message["tool_calls"]) != 1
        or any(
            name in message
            and message[name] is not None
            and not isinstance(message[name], str)
            for name in ("content", "refusal", "reasoning")
        )
        or (
            "annotations" in message
            and not isinstance(message["annotations"], list)
        )
        or (
            "reasoning_details" in message
            and not isinstance(message["reasoning_details"], list)
        )
    ):
        raise ProviderError("provider response must contain exactly one tool call")
    call = _exact(message["tool_calls"][0], {"id", "type", "function"}, "provider tool call")
    function = _exact(call["function"], {"name", "arguments"}, "provider function call")
    allowed = {tool["function"]["name"] for tool in binding.tools}
    if (
        not isinstance(call["id"], str)
        or not call["id"]
        or call["type"] != "function"
        or not isinstance(function["name"], str)
        or function["name"] not in allowed
        or not isinstance(function["arguments"], str)
    ):
        raise ProviderError("provider tool call is invalid")
    try:
        argument_bytes = function["arguments"].encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProviderError("provider tool arguments are invalid") from exc
    arguments = _strict_json(argument_bytes, "provider tool arguments")
    if not isinstance(arguments, dict):
        raise ProviderError("provider tool arguments must be an object")
    _bounded_wire(arguments)
    scan_response_secrets(arguments, binding)
    usage = _shape(
        value["usage"],
        {"prompt_tokens", "completion_tokens", "total_tokens"},
        {
            "prompt_tokens_details", "completion_tokens_details", "cost",
            "cost_details", "is_byok",
        },
        "provider usage",
    )
    details = usage.get("prompt_tokens_details", {"cached_tokens": 0})
    if not isinstance(details, dict) or not set(details) <= {
        "cached_tokens", "audio_tokens", "cache_write_tokens"
    } or (
        "prompt_tokens_details" in usage and "cached_tokens" not in details
    ) or any(type(item) is not int or item < 0 for item in details.values()):
        raise ProviderError("provider cached usage fields mismatch")
    cached_tokens = details.get("cached_tokens", 0)
    completion_details = usage.get("completion_tokens_details", {})
    if not isinstance(completion_details, dict) or any(
        type(item) is not int or item < 0 for item in completion_details.values()
    ):
        raise ProviderError("provider completion usage is invalid")
    if "cost" in usage and (
        not isinstance(usage["cost"], (int, Decimal))
        or isinstance(usage["cost"], bool)
        or usage["cost"] < 0
    ):
        raise ProviderError("provider reported cost is invalid")
    if "cost_details" in usage and not isinstance(usage["cost_details"], dict):
        raise ProviderError("provider reported cost details are invalid")
    if "cost_details" in usage:
        _bounded_wire(usage["cost_details"])
    if "cost_details" in usage and "cost" not in usage:
        raise ProviderError("provider reported charges require a total cost")
    if "is_byok" in usage and type(usage["is_byok"]) is not bool:
        raise ProviderError("provider billing metadata is invalid")
    counts = (
        usage["prompt_tokens"],
        usage["completion_tokens"],
        usage["total_tokens"],
        cached_tokens,
    )
    if (
        any(type(item) is not int or item < 0 for item in counts)
        or usage["total_tokens"]
        != usage["prompt_tokens"] + usage["completion_tokens"]
        or cached_tokens > usage["prompt_tokens"]
    ):
        raise ProviderError("provider usage is invalid")
    payload = {
        "schema": "autofv-lane-tool-call/v1",
        "name": function["name"],
        "arguments": arguments,
    }
    response = {
        "schema": "autofv-model-response/v1",
        "run_id": request["run_id"],
        "sequence": request["sequence"],
        "batch_id": request["batch_id"],
        "request_id": request["request_id"],
        "role": request["role"],
        "model_id": request["model_id"],
        "input_hashes": request["input_hashes"],
        "prompt_sha256": request["prompt_sha256"],
        "kind": "tool_call",
        "assigned_path": None,
        "base_commit": base_commit,
        "statement_fingerprints": [],
        "payload": payload,
        "payload_sha256": _sha(payload),
    }
    provider = {
        "schema": "autofv-provider-accounting/v1",
        "response_id": value["id"],
        "model_id": value["model"],
        "endpoint_sha256": binding.public["endpoint_sha256"],
        "tool_schema_sha256": binding.public["tool_schema_sha256"],
        "capability_sha256": binding.public["capability_sha256"],
        "usage": {
            "input_tokens": usage["prompt_tokens"],
            "cached_input_tokens": cached_tokens,
            "output_tokens": usage["completion_tokens"],
            "total_tokens": usage["total_tokens"],
        },
        "pricing": binding.pricing,
        "pricing_sha256": binding.public["pricing_sha256"],
    }
    provider_receipts.bind_billing(provider, usage)
    return response, provider


def _cost(provider: dict[str, Any]) -> Decimal:
    return provider_receipts.calculated_cost(provider)


def _sign_receipt(
    binding: ProviderBinding,
    run: dict[str, Any],
    request: dict[str, Any],
    response: dict[str, Any],
    provider: dict[str, Any],
) -> dict[str, Any]:
    return provider_receipts.sign_receipt(binding, run, request, response, provider)


def _status_classification(status: int) -> str:
    return {
        401: "authentication_error",
        403: "authentication_error",
        408: "timeout",
        429: "rate_limited",
        504: "timeout",
    }.get(status, "upstream_error")


def provider_round(
    run: dict[str, Any], request: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Issue one non-streaming request through the immutable provider binding."""
    binding = _binding(run)
    if binding is None:
        raise ProviderError("provider binding is not configured")
    if request.get("model_id") != binding.model_id:
        raise ProviderError("provider request model identity mismatch")
    sequence, request_id = request.get("sequence"), request.get("request_id")
    validate_dispatch_request(binding, request)
    messages, deadline_monotonic_ns = _take_messages(binding, request)
    with binding.lock:
        if request_id in binding.seen_request_ids or sequence in binding.seen_sequences:
            raise ProviderError("duplicate provider request identity")
        binding.seen_request_ids.add(request_id)
        binding.seen_sequences.add(sequence)
    upstream = _upstream_request(binding, request, messages)
    wire = urllib.request.Request(
        binding.endpoint,
        data=canonical_json_bytes(upstream),
        method="POST",
        headers={
            "Authorization": f"Bearer {bytes(binding.api_key).decode('utf-8')}",
            "Content-Type": "application/json",
        },
    )
    try:
        with _open_upstream(
            wire,
            timeout=_remaining_seconds(deadline_monotonic_ns),
            deadline_monotonic_ns=deadline_monotonic_ns,
        ) as reply:
            _remaining_seconds(deadline_monotonic_ns)
            raw = _read_upstream(reply, deadline_monotonic_ns)
            if len(raw) > MAX_WIRE_BYTES:
                raise ProviderError("provider response is too large")
            status = getattr(reply, "status", 200)
            if status != 200:
                provider_messages.scan_encoded(raw, binding.secret_markers)
                try:
                    error_value = _provider_json(raw)
                except ProviderError:
                    error_value = None
                if error_value is not None:
                    scan_response_secrets(error_value, binding, raw=raw)
                classification = _status_classification(status)
                raise ProviderError(
                    f"provider {classification}",
                    classification=classification,
                    status_code=status,
                )
            value = _provider_json(raw)
            scan_response_secrets(value, binding, raw=raw)
    except urllib.error.HTTPError as exc:
        try:
            with exc:
                error_raw = _read_upstream(exc, deadline_monotonic_ns)
        except ProviderError:
            raise
        except (TimeoutError, socket.timeout) as error:
            raise ProviderError(
                "provider timeout", classification="timeout"
            ) from error
        except (OSError, http.client.HTTPException) as error:
            raise ProviderError(
                "provider upstream_error", classification="upstream_error"
            ) from error
        provider_messages.scan_encoded(error_raw, binding.secret_markers)
        try:
            error_value = _provider_json(error_raw)
        except ProviderError:
            error_value = None
        if error_value is not None:
            scan_response_secrets(error_value, binding, raw=error_raw)
        classification = _status_classification(exc.code)
        raise ProviderError(
            f"provider {classification}",
            classification=classification,
            status_code=exc.code,
        ) from None
    except (TimeoutError, socket.timeout) as exc:
        raise ProviderError("provider timeout", classification="timeout") from exc
    except urllib.error.URLError as exc:
        classification = (
            "timeout"
            if isinstance(exc.reason, (TimeoutError, socket.timeout))
            else "upstream_error"
        )
        raise ProviderError(
            f"provider {classification}", classification=classification
        ) from None
    except (OSError, http.client.HTTPException) as exc:
        raise ProviderError(
            "provider upstream_error", classification="upstream_error"
        ) from exc
    response, provider = _provider_response(
        binding, request, value, run.get("base_commit", "")
    )
    input_ceiling = len(canonical_json_bytes(upstream)) + 4096
    if (
        provider["usage"]["input_tokens"] > input_ceiling
        or provider["usage"]["output_tokens"] > upstream["max_tokens"]
    ):
        raise ProviderError("provider usage exceeds the reserved token ceiling")
    scan_response_secrets(response, binding)
    scan_response_secrets(provider, binding)
    receipt = _sign_receipt(binding, run, request, response, provider)
    scan_response_secrets(receipt, binding)
    return response, receipt
