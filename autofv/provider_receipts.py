"""Signed provider billing, journal, and pre-disposal scan receipts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from decimal import Decimal, DecimalException, ROUND_HALF_UP, localcontext
from typing import Any
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_json_bytes
from . import provider_config, provider_messages


ProviderError = provider_config.ProviderConfigError
PROVIDER_RECEIPT_SCHEMA = "autofv-provider-proxy-receipt/v1"
PROVIDER_PREFLIGHT_SCHEMA = "autofv-provider-preflight/v1"
SCAN_RECEIPT_SCHEMA = "autofv-provider-scan-receipt/v1"
_MONEY = re.compile(r"(?:0|[1-9][0-9]{0,15})\.[0-9]{6}")
_EXACT_PROVIDER_MONEY = re.compile(
    r"(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,6})?"
)


def calculated_cost(provider: dict[str, Any]) -> Decimal:
    usage, pricing = provider["usage"], provider["pricing"]
    cached = usage["cached_input_tokens"]
    uncached = usage["input_tokens"] - cached
    try:
        with localcontext() as context:
            context.prec = 64
            amount = (
                Decimal(uncached) * Decimal(pricing["input_usd_per_million"])
                + Decimal(cached) * Decimal(pricing["cached_input_usd_per_million"])
                + Decimal(usage["output_tokens"])
                * Decimal(pricing["output_usd_per_million"])
            ) / Decimal(1_000_000)
            return amount.quantize(
                Decimal("0.000001"), rounding=ROUND_HALF_UP
            )
    except DecimalException as exc:
        raise ProviderError("provider calculated cost is invalid") from exc


def bind_billing(provider: dict[str, Any], usage: dict[str, Any]) -> None:
    calculated = calculated_cost(provider)
    estimate = {"amount": f"{calculated:.6f}", "currency": "USD"}
    reported = None
    if "cost" in usage:
        try:
            reported_amount = provider_messages.bounded_decimal(
                Decimal(usage["cost"])
            )
        except DecimalException as exc:
            raise ProviderError("provider billed cost is invalid") from exc
        exponent = reported_amount.as_tuple().exponent
        if exponent < -6:
            raise ProviderError("provider billed cost exceeds supported precision")
        if reported_amount != calculated:
            raise ProviderError("provider billed cost does not match pinned pricing")
        reported = {
            "amount": format(reported_amount, "f"),
            "currency": "USD",
            "amount_contract": "exact-decimal-usd-max-6",
            "details": _normalize_details(usage.get("cost_details", {})),
        }
    provider["billing"] = {
        "basis": "provider_billed" if reported is not None else "calculated_from_pinned_pricing",
        "provider_reported": reported,
        "calculated_estimate": estimate,
    }


def _normalize_details(value: Any) -> Any:
    if isinstance(value, Decimal):
        provider_messages.bounded_decimal(value)
        return format(value, "f")
    if isinstance(value, list):
        return [_normalize_details(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_details(item) for key, item in sorted(value.items())}
    return value


def _money(value: Any, pattern: re.Pattern[str], label: str) -> Decimal:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProviderError(f"{label} is invalid")
    try:
        return provider_messages.bounded_decimal(Decimal(value))
    except DecimalException as exc:
        raise ProviderError(f"{label} is invalid") from exc


def _sign(binding: provider_config.ProviderBinding, body: dict[str, Any]) -> dict[str, str]:
    if binding.signing_key is None:
        raise ProviderError("provider binding was released")
    authentication = binding.public["receipt_authentication"]
    return {
        "algorithm": "Ed25519",
        "key_id": authentication["key_id"],
        "signature": base64.b64encode(
            binding.signing_key.sign(canonical_json_bytes(body))
        ).decode("ascii"),
    }


def verify_signature(
    body: dict[str, Any], auth: Any, authentication: dict[str, Any], label: str
) -> None:
    auth = provider_config.exact_dict(
        auth, {"algorithm", "key_id", "signature"}, f"{label} auth"
    )
    if (
        auth["algorithm"] != "Ed25519"
        or auth["algorithm"] != authentication.get("algorithm")
        or auth["key_id"] != authentication.get("key_id")
    ):
        raise ProviderError(f"{label} authentication mismatch")
    try:
        signature = base64.b64decode(auth["signature"], validate=True)
        key = serialization.load_pem_public_key(
            authentication["public_key_pem"].encode("ascii")
        )
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("wrong public key type")
        public_der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if hashlib.sha256(public_der).hexdigest() != authentication.get(
            "public_key_der_sha256"
        ):
            raise ValueError("public key digest mismatch")
        key.verify(signature, canonical_json_bytes(body))
    except (
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
        binascii.Error,
        InvalidSignature,
    ) as exc:
        raise ProviderError(f"{label} signature verification failed") from exc


def sign_receipt(
    binding: provider_config.ProviderBinding,
    run: dict[str, Any],
    request: dict[str, Any],
    response: dict[str, Any],
    provider: dict[str, Any],
) -> dict[str, Any]:
    billing = provider["billing"]
    source = billing["provider_reported"] or billing["calculated_estimate"]
    pattern = _EXACT_PROVIDER_MONEY if billing["provider_reported"] else _MONEY
    amount = _money(source["amount"], pattern, "provider receipt amount")
    route = run["lock"]["fixed_proxy"]
    body = {
        "schema": PROVIDER_RECEIPT_SCHEMA,
        "proxy_id": route["proxy_id"],
        "route_id": route["route_id"],
        "run_id": request["run_id"],
        "sequence": request["sequence"],
        "request_id": request["request_id"],
        "model_id": request["model_id"],
        "request_sha256": provider_config.canonical_sha256(request),
        "response_sha256": provider_config.canonical_sha256(response),
        "status": "ok",
        "usage": {
            "input_tokens": provider["usage"]["input_tokens"],
            "output_tokens": provider["usage"]["output_tokens"],
            "total_tokens": provider["usage"]["total_tokens"],
        },
        "cost": {
            "amount": f"{amount:.6f}",
            "currency": "USD",
            "basis": billing["basis"],
        },
        "provider": provider,
        "auth": {
            "algorithm": "Ed25519",
            "key_id": binding.public["receipt_authentication"]["key_id"],
        },
    }
    provider_messages.scan_response(body, binding)
    signature = _sign(binding, body)["signature"]
    signed = {**body, "auth": {**body["auth"], "signature": signature}}
    receipt = {
        **signed,
        "receipt_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
    }
    provider_messages.scan_response(receipt, binding)
    return receipt


def validate_receipt(
    receipt: Any,
    *,
    binding: Any,
    run_id: str,
    sequence: int,
    request_id: str,
    model_id: str,
    request_sha256: str,
    response_sha256: str,
    seen_receipt_sha256: set[str] | frozenset[str],
    seen_request_ids: set[str] | frozenset[str] = frozenset(),
) -> Decimal:
    binding = provider_config.validate_public_binding(binding)
    receipt = provider_config.exact_dict(
        receipt,
        {
            "schema", "proxy_id", "route_id", "run_id", "sequence", "request_id",
            "model_id", "request_sha256", "response_sha256", "status", "usage",
            "cost", "provider", "auth", "receipt_sha256",
        },
        "provider receipt",
    )
    expected = {
        "schema": PROVIDER_RECEIPT_SCHEMA,
        "run_id": run_id,
        "sequence": sequence,
        "request_id": request_id,
        "model_id": model_id,
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "status": "ok",
        "proxy_id": binding["proxy_id"],
        "route_id": binding["route_id"],
    }
    if any(receipt.get(name) != value for name, value in expected.items()):
        raise ProviderError("provider receipt identity mismatch")
    if receipt["receipt_sha256"] in seen_receipt_sha256 or request_id in seen_request_ids:
        raise ProviderError("duplicate provider receipt")
    usage = provider_config.exact_dict(
        receipt["usage"], {"input_tokens", "output_tokens", "total_tokens"},
        "provider receipt usage",
    )
    if any(type(item) is not int or item < 0 for item in usage.values()) or (
        usage["total_tokens"] != usage["input_tokens"] + usage["output_tokens"]
    ):
        raise ProviderError("provider receipt usage is invalid")
    provider = provider_config.exact_dict(
        receipt["provider"],
        {
            "schema", "response_id", "model_id", "endpoint_sha256",
            "tool_schema_sha256", "capability_sha256", "usage", "pricing",
            "pricing_sha256", "billing",
        },
        "provider accounting",
    )
    provider_usage = provider_config.exact_dict(
        provider["usage"],
        {"input_tokens", "cached_input_tokens", "output_tokens", "total_tokens"},
        "provider accounting usage",
    )
    if (
        provider["schema"] != "autofv-provider-accounting/v1"
        or not isinstance(provider["response_id"], str)
        or not provider["response_id"]
        or provider["model_id"] != binding["model_id"]
        or provider["endpoint_sha256"] != binding["endpoint_sha256"]
        or provider["tool_schema_sha256"] != binding["tool_schema_sha256"]
        or provider["capability_sha256"] != binding["capability_sha256"]
        or provider["pricing"] != binding["pricing"]
        or provider["pricing_sha256"] != binding["pricing_sha256"]
        or provider_usage["input_tokens"] != usage["input_tokens"]
        or provider_usage["output_tokens"] != usage["output_tokens"]
        or provider_usage["total_tokens"] != usage["total_tokens"]
        or type(provider_usage["cached_input_tokens"]) is not int
        or not 0 <= provider_usage["cached_input_tokens"] <= usage["input_tokens"]
    ):
        raise ProviderError("provider accounting binding mismatch")
    calculated = calculated_cost(provider)
    billing = provider_config.exact_dict(
        provider["billing"],
        {"basis", "provider_reported", "calculated_estimate"},
        "provider billing",
    )
    estimate = provider_config.exact_dict(
        billing["calculated_estimate"], {"amount", "currency"}, "provider estimate"
    )
    if estimate != {"amount": f"{calculated:.6f}", "currency": "USD"}:
        raise ProviderError("provider calculated estimate mismatch")
    reported = billing["provider_reported"]
    if reported is not None:
        reported = provider_config.exact_dict(
            reported,
            {"amount", "currency", "amount_contract", "details"},
            "provider billed cost",
        )
        provider_messages.bounded_wire(reported["details"])
        reported_amount = _money(
            reported.get("amount"), _EXACT_PROVIDER_MONEY, "provider billed cost"
        )
        if (
            reported["currency"] != "USD"
            or reported["amount_contract"] != "exact-decimal-usd-max-6"
            or reported_amount != calculated
        ):
            raise ProviderError("provider billed cost mismatch")
    basis = "provider_billed" if reported is not None else "calculated_from_pinned_pricing"
    if billing["basis"] != basis:
        raise ProviderError("provider cost basis mismatch")
    amount = (
        reported_amount
        if reported is not None
        else _money(estimate.get("amount"), _MONEY, "provider estimate")
    )
    cost = provider_config.exact_dict(
        receipt["cost"], {"amount", "currency", "basis"}, "provider cost"
    )
    cost_amount = _money(cost.get("amount"), _MONEY, "provider cost")
    if (
        cost["currency"] != "USD"
        or cost["basis"] != basis
        or cost_amount != amount
    ):
        raise ProviderError("provider cost evidence mismatch")
    auth = provider_config.exact_dict(
        receipt["auth"], {"algorithm", "key_id", "signature"}, "provider receipt auth"
    )
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    body["auth"] = {"algorithm": auth["algorithm"], "key_id": auth["key_id"]}
    if (
        not isinstance(receipt["receipt_sha256"], str)
        or not hmac.compare_digest(
            receipt["receipt_sha256"], hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        )
    ):
        raise ProviderError("provider receipt hash mismatch")
    verify_signature(body, auth, binding["receipt_authentication"], "provider receipt")
    return amount


def sign_scan_receipt(
    binding: provider_config.ProviderBinding, *, run_id: str, scan_sha256: str
) -> dict[str, Any]:
    body = {
        "schema": SCAN_RECEIPT_SCHEMA,
        "run_id": run_id,
        "binding_sha256": binding.public["binding_sha256"],
        "scan_sha256": scan_sha256,
        "auth": {
            "algorithm": "Ed25519",
            "key_id": binding.public["receipt_authentication"]["key_id"],
        },
    }
    signature = _sign(binding, body)["signature"]
    signed = {**body, "auth": {**body["auth"], "signature": signature}}
    return {**signed, "receipt_sha256": provider_config.canonical_sha256(body)}


def validate_scan_receipt(
    value: Any, *, binding: Any, run_id: str, scan_sha256: str
) -> dict[str, Any]:
    binding = provider_config.validate_public_binding(binding)
    value = provider_config.exact_dict(
        value,
        {"schema", "run_id", "binding_sha256", "scan_sha256", "auth", "receipt_sha256"},
        "provider scan receipt",
    )
    auth = provider_config.exact_dict(
        value["auth"], {"algorithm", "key_id", "signature"}, "provider scan auth"
    )
    body = {key: item for key, item in value.items() if key not in {"receipt_sha256"}}
    body["auth"] = {"algorithm": auth["algorithm"], "key_id": auth["key_id"]}
    if (
        value["schema"] != SCAN_RECEIPT_SCHEMA
        or value["run_id"] != run_id
        or value["binding_sha256"] != binding["binding_sha256"]
        or value["scan_sha256"] != scan_sha256
        or value["receipt_sha256"] != provider_config.canonical_sha256(body)
    ):
        raise ProviderError("provider scan receipt identity mismatch")
    verify_signature(body, auth, binding["receipt_authentication"], "provider scan receipt")
    return value


def write_preflight(
    binding: provider_config.ProviderBinding,
    run: dict[str, Any],
    request: dict[str, Any],
    response: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    if run.get("provider_preflight_sha256") is not None:
        return
    body = {
        "schema": PROVIDER_PREFLIGHT_SCHEMA,
        "provider_binding": run["provider_binding"],
        "request": request,
        "response": response,
        "receipt": receipt,
    }
    value = {**body, "preflight_sha256": provider_config.canonical_sha256(body)}
    provider_messages.scan_response(value, binding)
    path = Path(run["evidence_dir"]) / "provider-preflight.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_json_bytes(value) + b"\n"
    try:
        with path.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as exc:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
            raise ProviderError("provider preflight replacement refused") from exc
    run["provider_preflight_sha256"] = value["preflight_sha256"]


def validate_preflight(
    path: str | Path, *, expected_binding: dict[str, Any] | None = None
) -> dict[str, Any]:
    candidate = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2_000_000:
                raise ProviderError("provider preflight is missing or unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(2_000_001)
        finally:
            os.close(descriptor)
        if len(raw) > 2_000_000:
            raise ProviderError("provider preflight is too large")
        value = json.loads(raw)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ProviderError("provider preflight is unreadable") from exc
    try:
        canonical = canonical_json_bytes(value) + b"\n"
    except Exception as exc:
        raise ProviderError("provider preflight is not canonical") from exc
    if raw != canonical:
        raise ProviderError("provider preflight is not canonical")
    value = provider_config.exact_dict(
        value,
        {"schema", "provider_binding", "request", "response", "receipt", "preflight_sha256"},
        "provider preflight",
    )
    body = {key: item for key, item in value.items() if key != "preflight_sha256"}
    if (
        value["schema"] != PROVIDER_PREFLIGHT_SCHEMA
        or value["preflight_sha256"] != provider_config.canonical_sha256(body)
    ):
        raise ProviderError("provider preflight hash mismatch")
    binding = provider_config.validate_public_binding(value["provider_binding"])
    if expected_binding is not None and binding != provider_config.validate_public_binding(
        expected_binding
    ):
        raise ProviderError("provider preflight binding is not independently pinned")
    request, response = value["request"], value["response"]
    if not isinstance(request, dict) or not isinstance(response, dict) or any(
        response.get(name) != request.get(name)
        for name in ("run_id", "sequence", "request_id", "model_id")
    ):
        raise ProviderError("provider preflight exchange is invalid")
    validate_receipt(
        value["receipt"],
        binding=binding,
        run_id=request.get("run_id"),
        sequence=request.get("sequence"),
        request_id=request.get("request_id"),
        model_id=request.get("model_id"),
        request_sha256=provider_config.canonical_sha256(request),
        response_sha256=provider_config.canonical_sha256(response),
        seen_receipt_sha256=frozenset(),
    )
    if any(
        re.search(r"(?:authorization|api[_-]?key|signing[_-]?key|secret)", key, re.I)
        for key in _walk_keys(value)
    ):
        raise ProviderError("provider preflight contains a secret-bearing field")
    return value


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)
