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
PROVIDER_JOURNAL_SCHEMA = "autofv-provider-dispatch/v1"
_JOURNAL_FIELDS = {
    "schema", "status", "run_id", "request_id", "sequence", "request_sha256",
    "messages_sha256", "binding_sha256", "response", "receipt", "auth",
    "record_sha256",
}
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


def _reduce_exchange_accounting(
    run: dict[str, Any], state: dict[str, Any], *, binding: Any, allow_empty: bool = False
) -> dict[str, Any]:
    public = provider_config.validate_public_binding(binding)
    receipts = state.get("receipts")
    exchanges = state.get("model_exchanges")
    if (
        not isinstance(receipts, list)
        or (not receipts and not allow_empty)
        or not isinstance(exchanges, dict)
        or len(exchanges) != len(receipts)
        or state.get("pending_model_exchanges")
        or run.get("run_id") != public["run_id"]
    ):
        raise ProviderError("provider receipt exchange binding is incomplete")
    configured_model = state.get("config", {}).get("model")
    if configured_model is not None and configured_model != public["model_id"]:
        raise ProviderError("provider receipt model binding mismatch")

    seen_receipts: set[str] = set()
    seen_requests: set[str] = set()
    seen_sequences: set[int] = set()
    authenticated_tokens = {"input": 0, "output": 0, "total": 0}
    estimated_tokens = {"input": 0, "output": 0, "total": 0}
    billed_cost = Decimal("0.000000")
    estimated_cost = Decimal("0.000000")
    charged_cost = Decimal("0.000000")
    accepted: list[dict[str, Any]] = []

    for receipt in receipts:
        request_id = receipt.get("request_id") if isinstance(receipt, dict) else None
        exchange = exchanges.get(request_id)
        if not isinstance(exchange, dict) or exchange.get("receipt") != receipt:
            raise ProviderError("provider receipt exchange binding mismatch")
        request = exchange.get("request")
        response = exchange.get("response")
        sequence = request.get("sequence") if isinstance(request, dict) else None
        identity = {
            "run_id": run.get("run_id"),
            "sequence": sequence,
            "request_id": request_id,
            "model_id": public["model_id"],
        }
        if (
            not isinstance(request, dict)
            or not isinstance(response, dict)
            or not isinstance(request_id, str)
            or type(sequence) is not int
            or sequence in seen_sequences
            or any(request.get(name) != value for name, value in identity.items())
            or any(response.get(name) != value for name, value in identity.items())
        ):
            raise ProviderError("provider receipt exchange identity mismatch")
        charged_cost += validate_receipt(
            receipt,
            binding=public,
            run_id=run["run_id"],
            sequence=sequence,
            request_id=request_id,
            model_id=public["model_id"],
            request_sha256=provider_config.canonical_sha256(request),
            response_sha256=provider_config.canonical_sha256(response),
            seen_receipt_sha256=seen_receipts,
            seen_request_ids=seen_requests,
        )
        seen_receipts.add(receipt["receipt_sha256"])
        seen_requests.add(request_id)
        seen_sequences.add(sequence)
        usage = receipt["usage"]
        for target, source in (
            ("input", "input_tokens"),
            ("output", "output_tokens"),
            ("total", "total_tokens"),
        ):
            authenticated_tokens[target] += usage[source]
        billing = receipt["provider"]["billing"]
        reported = billing["provider_reported"]
        if reported is None:
            for target, source in (
                ("input", "input_tokens"),
                ("output", "output_tokens"),
                ("total", "total_tokens"),
            ):
                estimated_tokens[target] += usage[source]
            estimated_cost += Decimal(billing["calculated_estimate"]["amount"])
        else:
            billed_cost += Decimal(reported["amount"])
        accepted.append(exchange)

    if seen_requests != set(exchanges):
        raise ProviderError("provider receipt exchange set mismatch")
    sequences = [exchange["request"]["sequence"] for exchange in accepted]
    if sequences != sorted(sequences):
        raise ProviderError("provider receipt sequence order mismatch")

    zero = {
        "requests": 0,
        "tokens": {"input": 0, "output": 0, "total": 0},
        "cost_usd": "0.000000",
    }
    estimated_requests = sum(
        exchange["receipt"]["provider"]["billing"]["provider_reported"] is None
        for exchange in accepted
    )
    accounting = {
        "provider_authenticated": {
            "requests": len(accepted),
            "tokens": authenticated_tokens,
            "cost_usd": f"{billed_cost:.6f}",
        },
        "synthetic": zero,
        "estimated": {
            "requests": estimated_requests,
            "tokens": estimated_tokens,
            "cost_usd": f"{estimated_cost:.6f}",
        },
    }
    return {
        "classification": "provider_authenticated",
        "requests": len(accepted),
        "tokens": authenticated_tokens,
        "cost": charged_cost,
        "accounting": accounting,
        "model_exchanges": accepted,
    }


def reduce_accounting(
    run: dict[str, Any], state: dict[str, Any], *, binding: Any
) -> dict[str, Any]:
    """Authenticate an exact, complete provider journal and exchange set."""
    public = provider_config.validate_public_binding(binding)
    recovery = validate_recovery_artifacts(run, state, binding=public)
    exchanges = state.get("model_exchanges")
    if not isinstance(exchanges, dict):
        raise ProviderError("provider receipt exchange binding is incomplete")
    journal = recovery["journal"]
    if set(journal) != set(exchanges):
        raise ProviderError("provider journal exchange set mismatch")
    for request_id, record in journal.items():
        exchange = exchanges.get(request_id)
        request = exchange.get("request") if isinstance(exchange, dict) else None
        if (
            not isinstance(request, dict)
            or record.get("status") != "completed"
            or record.get("request_sha256")
            != provider_config.canonical_sha256(request)
            or record.get("response") != exchange.get("response")
            or record.get("receipt") != exchange.get("receipt")
        ):
            raise ProviderError("provider journal exchange set mismatch")
    reduced = _reduce_exchange_accounting(run, state, binding=public)
    return {**reduced, "accounting_complete": True, "unresolved_requests": []}


def reduce_incomplete_accounting(
    run: dict[str, Any], state: dict[str, Any], *, binding: Any
) -> dict[str, Any]:
    """Authenticate completed spend while retaining unresolved provider liability."""
    pinned = binding if isinstance(binding, provider_config.ProviderBinding) else None
    public = provider_config.validate_public_binding(
        pinned.public if pinned is not None else binding
    )
    recovery = validate_recovery_artifacts(
        run, state, binding=(pinned if pinned is not None else public)
    )
    journal = recovery["journal"]
    pending = (
        state.get("pending_model_exchanges")
        if isinstance(state.get("pending_model_exchanges"), dict)
        else {}
    )
    completed_state = (
        state.get("model_exchanges")
        if isinstance(state.get("model_exchanges"), dict)
        else {}
    )
    completed: dict[str, dict[str, Any]] = {}
    unresolved: list[dict[str, Any]] = []
    for request_id, record in sorted(
        journal.items(), key=lambda item: (item[1].get("sequence", 0), item[0])
    ):
        exchange = completed_state.get(request_id) or pending.get(request_id)
        request = exchange.get("request") if isinstance(exchange, dict) else None
        if record["status"] == "completed":
            if (
                not isinstance(exchange, dict)
                or not isinstance(request, dict)
                or exchange.get("response") != record["response"]
                or exchange.get("receipt") != record["receipt"]
            ):
                raise ProviderError("provider completed subtotal mismatch")
            completed[request_id] = {
                "request": request,
                "response": record["response"],
                "receipt": record["receipt"],
                "call_kind": exchange.get("call_kind", "explicit"),
            }
        else:
            unresolved.append(
                {
                    "request_id": request_id,
                    "sequence": record["sequence"],
                    "status": (
                        exchange.get("dispatch_state", record["status"])
                        if isinstance(exchange, dict)
                        else record["status"]
                    ),
                    "reservation_usd": (
                        exchange.get("reservation_usd")
                        if isinstance(exchange, dict)
                        else None
                    ),
                    "request_sha256": record["request_sha256"],
                    "record_sha256": record["record_sha256"],
                }
            )
    for request_id, exchange in sorted(pending.items()):
        if request_id in journal:
            continue
        raise ProviderError("provider unresolved request is not authenticated")
    partial_state = {
        "config": state.get("config", {}),
        "receipts": [
            exchange["receipt"]
            for exchange in sorted(
                completed.values(), key=lambda item: item["request"]["sequence"]
            )
        ],
        "model_exchanges": completed,
        "pending_model_exchanges": {},
    }
    reduced = _reduce_exchange_accounting(
        run, partial_state, binding=public, allow_empty=True
    )
    return {
        **reduced,
        "accounting_complete": False,
        "unresolved_requests": unresolved,
        "unknown_provider_spend": bool(unresolved),
    }


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
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
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


def _read_canonical(path: Path, label: str) -> dict[str, Any]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2_000_000:
                raise ProviderError(f"{label} is missing or unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(2_000_001)
        finally:
            os.close(descriptor)
        value = json.loads(raw)
        if len(raw) > 2_000_000 or raw != canonical_json_bytes(value) + b"\n":
            raise ProviderError(f"{label} is not canonical")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ProviderError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise ProviderError(f"{label} fields mismatch")
    return value


def _prior_journal_digest(
    binding: provider_config.ProviderBinding,
    request: dict[str, Any],
    record: dict[str, Any],
    status: str,
) -> str:
    body = {
        "schema": PROVIDER_JOURNAL_SCHEMA,
        "status": status,
        "run_id": binding.public["run_id"],
        "request_id": request["request_id"],
        "sequence": request["sequence"],
        "request_sha256": provider_config.canonical_sha256(request),
        "messages_sha256": record["messages_sha256"],
        "binding_sha256": binding.public["binding_sha256"],
        "response": None,
        "receipt": None,
    }
    signed = {**body, "auth": _sign(binding, body)}
    return provider_config.canonical_sha256(signed)


def validate_recovery_artifacts(
    run: dict[str, Any], state: dict[str, Any], *, binding: Any
) -> dict[str, Any]:
    """Validate public provider artifacts without consulting transient service state."""
    pinned = binding if isinstance(binding, provider_config.ProviderBinding) else None
    public = provider_config.validate_public_binding(
        pinned.public if pinned is not None else binding
    )
    if (
        run.get("provider_binding") != public
        or run.get("provider_binding_sha256") != public["binding_sha256"]
    ):
        raise ProviderError("provider binding recovery mismatch")

    journal_memory = run.get("provider_journal")
    if journal_memory is None:
        journal_memory = {}
    if not isinstance(journal_memory, dict) or any(
        not isinstance(request_id, str)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for request_id, digest in journal_memory.items()
    ):
        raise ProviderError("provider journal memory is invalid")

    requests: dict[str, dict[str, Any]] = {}
    for collection in (
        state.get("pending_model_exchanges"),
        state.get("model_exchanges"),
    ):
        if not isinstance(collection, dict):
            continue
        for exchange in collection.values():
            request = exchange.get("request") if isinstance(exchange, dict) else None
            if isinstance(request, dict) and isinstance(request.get("request_id"), str):
                requests[request["request_id"]] = request

    root = Path(run["evidence_dir"]) / "provider-journal"
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise ProviderError("provider journal path is unsafe")
    paths = sorted(root.glob("*.json")) if root.is_dir() else []
    if not paths and journal_memory:
        raise ProviderError("provider journal is missing")

    records: dict[str, dict[str, Any]] = {}
    seen_receipts: set[str] = set()
    seen_requests: set[str] = set()
    for path in paths:
        value = provider_config.exact_dict(
            _read_canonical(path, "provider journal"),
            _JOURNAL_FIELDS,
            "provider journal",
        )
        signed = {key: item for key, item in value.items() if key != "record_sha256"}
        body = {key: item for key, item in signed.items() if key != "auth"}
        request_id = value.get("request_id")
        expected_name = hashlib.sha256(str(request_id).encode("utf-8")).hexdigest()
        if (
            value.get("schema") != PROVIDER_JOURNAL_SCHEMA
            or value.get("run_id") != run.get("run_id")
            or value.get("binding_sha256") != public["binding_sha256"]
            or value.get("status") not in {"reserved", "dispatched", "completed"}
            or not isinstance(request_id, str)
            or request_id in records
            or path.name != f"{expected_name}.json"
            or value.get("record_sha256") != provider_config.canonical_sha256(signed)
            or not isinstance(value.get("request_sha256"), str)
            or not isinstance(value.get("messages_sha256"), str)
        ):
            raise ProviderError("provider journal identity mismatch")
        verify_signature(
            body, value["auth"], public["receipt_authentication"], "provider journal"
        )
        request = requests.get(request_id)
        if request is not None and (
            provider_config.canonical_sha256(request) != value["request_sha256"]
            or request.get("sequence") != value.get("sequence")
        ):
            raise ProviderError("provider journal request mismatch")
        complete = value["status"] == "completed"
        if complete != (
            isinstance(value.get("response"), dict)
            and isinstance(value.get("receipt"), dict)
        ) or (not complete and (value.get("response") is not None or value.get("receipt") is not None)):
            raise ProviderError("provider journal completion mismatch")
        if complete:
            response = value["response"]
            if any(
                response.get(name) != value.get(name)
                for name in ("run_id", "sequence", "request_id")
            ) or response.get("model_id") != public["model_id"]:
                raise ProviderError("provider journal response mismatch")
            validate_receipt(
                value["receipt"],
                binding=public,
                run_id=value["run_id"],
                sequence=value["sequence"],
                request_id=request_id,
                model_id=public["model_id"],
                request_sha256=value["request_sha256"],
                response_sha256=provider_config.canonical_sha256(response),
                seen_receipt_sha256=seen_receipts,
                seen_request_ids=seen_requests,
            )
            seen_receipts.add(value["receipt"]["receipt_sha256"])
            seen_requests.add(request_id)
        records[request_id] = value

    if not set(records).issubset(requests):
        raise ProviderError("provider journal is not bound to checkpoint state")

    pending = (
        state.get("pending_model_exchanges")
        if isinstance(state.get("pending_model_exchanges"), dict)
        else {}
    )
    completed = (
        state.get("model_exchanges")
        if isinstance(state.get("model_exchanges"), dict)
        else {}
    )
    if not set(journal_memory).issubset(records):
        raise ProviderError("provider journal memory changed")
    for request_id, record in records.items():
        checkpoint_exchange = completed.get(request_id) or pending.get(request_id)
        checkpoint_status = (
            "completed"
            if request_id in completed
            or (
                isinstance(checkpoint_exchange, dict)
                and isinstance(checkpoint_exchange.get("response"), dict)
                and isinstance(checkpoint_exchange.get("receipt"), dict)
            )
            else checkpoint_exchange.get("dispatch_state")
            if isinstance(checkpoint_exchange, dict)
            else None
        )
        allowed_statuses = {
            "reserved": {"reserved", "dispatched", "completed"},
            "dispatched": {"dispatched", "completed"},
            "ambiguous": {"dispatched", "completed"},
            "completed": {"completed"},
        }.get(checkpoint_status, set())
        if record["status"] not in allowed_statuses:
            raise ProviderError("provider journal recovery is not monotonic")
        remembered = journal_memory.get(request_id)
        if remembered is None:
            if checkpoint_status not in {"reserved", "dispatched", "ambiguous"}:
                raise ProviderError("provider journal memory changed")
        elif remembered != record["record_sha256"]:
            if pinned is None:
                raise ProviderError("provider journal memory changed")
            prior = {
                status: _prior_journal_digest(
                    pinned, requests[request_id], record, status
                )
                for status in ("reserved", "dispatched")
            }
            allowed_prior = {
                "reserved": {prior["reserved"]},
                "dispatched": {prior["reserved"], prior["dispatched"]},
                "ambiguous": {prior["reserved"], prior["dispatched"]},
                "completed": set(),
            }.get(checkpoint_status, set())
            if remembered not in allowed_prior:
                raise ProviderError("provider journal memory changed")

    preflight_path = Path(run["evidence_dir"]) / "provider-preflight.json"
    preflight_sha256 = run.get("provider_preflight_sha256")
    if preflight_sha256 is None:
        if preflight_path.exists():
            preflight = validate_preflight(preflight_path, expected_binding=public)
            preflight_sha256 = preflight["preflight_sha256"]
        else:
            first_completed = min(
                (
                    record
                    for record in records.values()
                    if record["status"] == "completed"
                ),
                key=lambda record: (record["sequence"], record["request_id"]),
                default=None,
            )
            if first_completed is None:
                preflight = None
            else:
                if pinned is None:
                    raise ProviderError("provider preflight identity is missing")
                request = requests[first_completed["request_id"]]
                write_preflight(
                    pinned,
                    run,
                    request,
                    first_completed["response"],
                    first_completed["receipt"],
                )
                preflight = validate_preflight(
                    preflight_path, expected_binding=public
                )
                preflight_sha256 = preflight["preflight_sha256"]
    else:
        preflight = validate_preflight(preflight_path, expected_binding=public)
        if preflight.get("preflight_sha256") != preflight_sha256:
            raise ProviderError("provider preflight identity mismatch")
    completed_state = {
        request_id
        for request_id, exchange in {
            **(
                state.get("pending_model_exchanges")
                if isinstance(state.get("pending_model_exchanges"), dict)
                else {}
            ),
            **(
                state.get("model_exchanges")
                if isinstance(state.get("model_exchanges"), dict)
                else {}
            ),
        }.items()
        if isinstance(exchange, dict)
        and isinstance(exchange.get("response"), dict)
        and isinstance(exchange.get("receipt"), dict)
    }
    completed_records = {
        request_id
        for request_id, record in records.items()
        if record["status"] == "completed"
    }
    if not completed_state.issubset(completed_records):
        raise ProviderError("completed provider journal is missing")
    if preflight is not None:
        request_id = preflight["request"].get("request_id")
        record = records.get(request_id)
        if (
            not isinstance(record, dict)
            or record.get("status") != "completed"
            or record.get("response") != preflight["response"]
            or record.get("receipt") != preflight["receipt"]
        ):
            raise ProviderError("provider preflight journal binding mismatch")
    for request_id, record in records.items():
        if record["status"] != "completed":
            continue
        exchange = completed.get(request_id)
        if isinstance(exchange, dict):
            if (
                exchange.get("request") != requests[request_id]
                or exchange.get("response") != record["response"]
                or exchange.get("receipt") != record["receipt"]
            ):
                raise ProviderError("completed provider journal changed")
            continue
        exchange = pending.get(request_id)
        if not isinstance(exchange, dict):
            raise ProviderError("completed provider journal is unrelated")
        exchange["response"] = record["response"]
        exchange["receipt"] = record["receipt"]
        exchange["dispatch_state"] = "completed"
    run["provider_journal"] = {
        request_id: record["record_sha256"]
        for request_id, record in sorted(records.items())
    }
    if preflight is not None:
        run["provider_preflight_sha256"] = preflight_sha256
    return {"provider_binding": public, "provider_preflight": preflight, "journal": records}


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)
