"""Bounded ephemeral provider messages and credential-canary scanning."""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
import urllib.parse
from decimal import Decimal, DecimalException
from typing import Any

from .contracts import ContractError, canonical_json_bytes
from .provider_config import ProviderBinding, ProviderConfigError, canonical_sha256, exact_dict


ProviderError = ProviderConfigError
MAX_WIRE_BYTES = 1_000_000
MAX_MESSAGE_BYTES = 262_144
MAX_SCAN_STRUCTURE_DEPTH = 16
MAX_SCAN_DECODE_DEPTH = 4


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = item
    return result


def strict_json(raw: bytes, label: str, *, allow_floats: bool = False) -> Any:
    if not isinstance(raw, bytes):
        raise ProviderError(f"{label} is malformed")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=Decimal if allow_floats else lambda _value: (_ for _ in ()).throw(
                ValueError("JSON floats are forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON numbers are forbidden")
            ),
        )
    except (
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        OverflowError,
        RecursionError,
        DecimalException,
    ) as exc:
        raise ProviderError(f"{label} is malformed") from exc
    return value


def strict_request_json(raw: bytes) -> dict[str, Any]:
    value = strict_json(raw, "provider dispatch")
    try:
        canonical = canonical_json_bytes(value)
    except ContractError as exc:
        raise ProviderError("provider dispatch is not canonical JSON") from exc
    if not isinstance(value, dict) or raw != canonical:
        raise ProviderError("provider dispatch is not canonical JSON")
    return value


def bounded_wire(value: Any, *, depth: int = 0) -> int:
    if depth > 12:
        raise ProviderError("provider response exceeds its nesting bound")
    if value is None or isinstance(value, bool):
        return 1
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ProviderError("provider response contains invalid Unicode") from exc
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ProviderError("provider response string is too large")
        return 1
    if type(value) is int:
        if abs(value) > 10**15:
            raise ProviderError("provider response number is out of range")
        return 1
    if isinstance(value, Decimal):
        bounded_decimal(value)
        return 1
    count = 1
    try:
        if isinstance(value, list):
            for item in value:
                count += bounded_wire(item, depth=depth + 1)
        elif isinstance(value, dict) and all(isinstance(key, str) for key in value):
            for key, item in value.items():
                count += bounded_wire(key, depth=depth + 1)
                count += bounded_wire(item, depth=depth + 1)
        else:
            raise ProviderError("provider response contains an unsupported value")
    except RecursionError as exc:
        raise ProviderError("provider response exceeds its nesting bound") from exc
    if count > 4096:
        raise ProviderError("provider response exceeds its structure bound")
    return count


def bounded_decimal(value: Decimal) -> Decimal:
    """Validate a provider decimal without consulting mutable Decimal context."""
    try:
        if not isinstance(value, Decimal) or not value.is_finite():
            raise ProviderError("provider response number is out of range")
        _sign, digits, exponent = value.as_tuple()
    except DecimalException as exc:
        raise ProviderError("provider response number is out of range") from exc
    if (
        not isinstance(exponent, int)
        or len(digits) > 32
        or exponent < -18
        or exponent > 15
        or (digits and len(digits) + exponent - 1 > 15)
    ):
        raise ProviderError("provider response number is out of range")
    return value


def provider_json(raw: bytes) -> Any:
    value = strict_json(raw, "provider response", allow_floats=True)
    bounded_wire(value)
    return value


def scan_encoded(
    sample: bytes, markers: tuple[bytes, ...], *, decode_depth: int = 0
) -> None:
    """Scan one leaf through bounded reversible encodings.

    Encoding depth is intentionally independent of the JSON container depth. A
    caller may therefore place an encoded canary deep in an otherwise valid
    response without consuming the encoding budget before that leaf is reached.
    """
    if not isinstance(sample, bytes) or len(sample) > MAX_WIRE_BYTES:
        raise ProviderError("provider secret scan exceeds its size bound")
    if any(marker and marker in sample for marker in markers):
        raise ProviderError("provider response contains credential material")
    if not sample:
        return
    candidates: list[bytes] = []
    nested: Any = None
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text:
        for decoder in (
            lambda: base64.b64decode(text, validate=True),
            lambda: bytes.fromhex(text),
            lambda: urllib.parse.unquote_to_bytes(text),
        ):
            try:
                decoded = decoder()
            except (TypeError, ValueError, binascii.Error):
                continue
            if decoded != sample:
                candidates.append(decoded)
        if re.search(r"\\+u[0-9a-fA-F]{4}", text):
            decoded_text = re.sub(
                r"\\+u([0-9a-fA-F]{4})",
                lambda match: chr(int(match.group(1), 16)),
                text,
            )
            try:
                candidates.append(decoded_text.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ProviderError("provider response contains invalid Unicode") from exc
        if text[:1] in {'{', '[', '"'}:
            try:
                nested = provider_json(sample)
            except ProviderError:
                nested = None
    if (candidates or (nested is not None and nested != text)) and (
        decode_depth >= MAX_SCAN_DECODE_DEPTH
    ):
        raise ProviderError("provider secret scan exceeds its decode bound")
    if nested is not None and nested != text:
        scan_value(nested, markers, decode_depth=decode_depth + 1)
    for candidate in candidates:
        scan_encoded(candidate, markers, decode_depth=decode_depth + 1)


def scan_value(
    value: Any,
    markers: tuple[bytes, ...],
    *,
    structure_depth: int = 0,
    decode_depth: int = 0,
) -> None:
    if structure_depth > MAX_SCAN_STRUCTURE_DEPTH:
        raise ProviderError("provider secret scan exceeds its nesting bound")
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ProviderError("provider response contains invalid Unicode") from exc
        scan_encoded(raw, markers, decode_depth=decode_depth)
    elif isinstance(value, list):
        for item in value:
            scan_value(
                item,
                markers,
                structure_depth=structure_depth + 1,
                decode_depth=decode_depth,
            )
    elif isinstance(value, dict):
        for key, item in value.items():
            scan_value(
                key,
                markers,
                structure_depth=structure_depth + 1,
                decode_depth=decode_depth,
            )
            scan_value(
                item,
                markers,
                structure_depth=structure_depth + 1,
                decode_depth=decode_depth,
            )
    elif value is not None and not isinstance(value, (bool, int, Decimal)):
        raise ProviderError("provider secret scan contains an unsupported value")


def scan_response(value: Any, binding: ProviderBinding, *, raw: bytes | None = None) -> None:
    if raw is not None:
        scan_encoded(raw, binding.secret_markers)
    scan_value(value, binding.secret_markers)


def _utf8(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        return None


def validate_messages(value: Any, binding: ProviderBinding | None = None) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 2 <= len(value) <= 64:
        raise ProviderError("provider messages are not a bounded array")
    messages: list[dict[str, Any]] = []
    open_tool_call: str | None = None
    allowed = None if binding is None else {tool["function"]["name"] for tool in binding.tools}
    for item in value:
        role = item.get("role") if isinstance(item, dict) else None
        if not isinstance(role, str) or role not in {
            "system", "user", "assistant", "tool"
        }:
            raise ProviderError("provider message role is invalid")
        fields = (
            {"role", "tool_calls", "content"}
            if role == "assistant"
            else {"role", "tool_call_id", "content"}
            if role == "tool"
            else {"role", "content"}
        )
        item = exact_dict(item, fields, "provider message")
        content = item["content"]
        if role == "assistant":
            if content is not None and not isinstance(content, str):
                raise ProviderError("provider assistant content is invalid")
            calls = item["tool_calls"]
            if not isinstance(calls, list) or len(calls) != 1:
                raise ProviderError("provider assistant tool calls are invalid")
            call = exact_dict(calls[0], {"id", "type", "function"}, "provider message call")
            function = exact_dict(
                call["function"], {"name", "arguments"}, "provider message function"
            )
            argument_bytes = _utf8(function["arguments"])
            if (
                call["type"] != "function"
                or not isinstance(call["id"], str)
                or not call["id"]
                or not all(isinstance(function[name], str) and function[name] for name in ("name", "arguments"))
                or argument_bytes is None
                or not isinstance(
                    strict_json(argument_bytes, "provider message arguments"), dict
                )
                or (allowed is not None and function["name"] not in allowed)
            ):
                raise ProviderError("provider assistant tool call is invalid")
        elif (
            not isinstance(content, str)
            or not content
            or "\x00" in content
            or (content_bytes := _utf8(content)) is None
            or len(content_bytes) > 65_536
            or (role == "tool" and (not isinstance(item["tool_call_id"], str) or not item["tool_call_id"]))
        ):
            raise ProviderError("provider message content is invalid")
        if role == "assistant":
            if open_tool_call is not None:
                raise ProviderError("provider message tool sequence is invalid")
            open_tool_call = item["tool_calls"][0]["id"]
        elif role == "tool":
            if item["tool_call_id"] != open_tool_call:
                raise ProviderError("provider message tool sequence is invalid")
            open_tool_call = None
        try:
            messages.append(json.loads(canonical_json_bytes(item)))
        except (ContractError, UnicodeError, ValueError) as exc:
            raise ProviderError("provider message is not canonical") from exc
    if messages[0]["role"] != "system" or not any(item["role"] == "user" for item in messages):
        raise ProviderError("provider messages require system and user context")
    if open_tool_call is not None or len(canonical_json_bytes(messages)) > MAX_MESSAGE_BYTES:
        raise ProviderError("provider messages exceed their bound")
    if binding is not None:
        scan_response(messages, binding)
    return messages


def messages_sha256(value: Any) -> str:
    return canonical_sha256(validate_messages(value))


def stage_messages(
    binding: ProviderBinding,
    request: dict[str, Any],
    value: Any,
    *,
    timeout_seconds: float,
) -> None:
    messages = validate_messages(value, binding)
    digest = canonical_sha256(messages)
    if digest not in request.get("input_hashes", ()):
        raise ProviderError("provider messages are not bound to the request")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= 30
    ):
        raise ProviderError("provider timeout is invalid")
    request_id = request.get("request_id")
    with binding.lock:
        if request_id in binding.pending_messages:
            raise ProviderError("provider messages are already staged")
        binding.pending_messages[request_id] = {
            "messages": messages,
            "messages_sha256": digest,
            "request_sha256": canonical_sha256(request),
            "deadline_monotonic_ns": time.monotonic_ns()
            + int(float(timeout_seconds) * 1_000_000_000),
        }


def discard_messages(binding: ProviderBinding | None, request_id: str) -> None:
    if binding is not None:
        with binding.lock:
            binding.pending_messages.pop(request_id, None)


def staged_messages_sha256(binding: ProviderBinding, request: dict[str, Any]) -> str:
    staged = binding.pending_messages.get(request.get("request_id"))
    if (
        not isinstance(staged, dict)
        or staged.get("request_sha256") != canonical_sha256(request)
        or not isinstance(staged.get("messages_sha256"), str)
    ):
        raise ProviderError("provider staged request identity mismatch")
    return staged["messages_sha256"]


def take_messages(
    binding: ProviderBinding, request: dict[str, Any]
) -> tuple[list[dict[str, Any]], int]:
    with binding.lock:
        staged_messages_sha256(binding, request)
        staged = binding.pending_messages.pop(request["request_id"], None)
    if (
        not isinstance(staged, dict)
        or not isinstance(staged.get("messages"), list)
        or type(staged.get("deadline_monotonic_ns")) is not int
    ):
        raise ProviderError("provider messages were not staged by the controller")
    if staged["deadline_monotonic_ns"] <= time.monotonic_ns():
        raise ProviderError("provider timeout", classification="timeout")
    return staged["messages"], staged["deadline_monotonic_ns"]
