"""Signed controller observations for subscription generations, never billing.

The existing provider binding key authenticates these observations. It does not
authenticate a provider invoice, establish a subscription dollar charge, or turn
SDK catalog prices into money spent. Reasoning is a subset of output tokens.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from . import provider_config, provider_messages, provider_receipts
from .contracts import canonical_json_bytes


ProviderError = provider_config.ProviderConfigError
SCHEMA = "autofv-subscription-usage-attestation/v1"
RECEIPT_SCHEMA = SCHEMA
CLASSIFICATION = "subscription_cost_unknown"
_SHA = re.compile(r"[0-9a-f]{64}")
_MAX_TOKENS = 2**53 - 1
_FIELDS = {
    "schema", "proxy_id", "route_id", "run_id", "sequence", "request_id",
    "model_id", "role", "conversation_id", "history_sha256", "request_sha256",
    "response_sha256", "continuation_sha256", "binding_sha256",
    "role_profile_sha256", "source_packet_sha256", "status", "usage",
    "raw_usage", "cost", "provider", "dispatch_accounting_complete",
    "monetary_cost_known", "auth", "receipt_sha256",
}


def _sha(value: Any) -> str:
    return provider_config.canonical_sha256(value)


def _public(binding: Any) -> dict[str, Any]:
    public = provider_config.validate_public_binding(
        binding.public if isinstance(binding, provider_config.ProviderBinding) else binding
    )
    if public.get("schema") != "autofv-provider-binding/v3":
        raise ProviderError("subscription accounting requires a v3 provider binding")
    return public


def normalize_usage(raw_usage: Any) -> dict[str, Any]:
    """Validate Pi's raw categories and explicitly convert their disjoint input."""
    required = {"input", "output", "cacheRead", "cacheWrite", "totalTokens"}
    if (not isinstance(raw_usage, dict)
        or not required <= set(raw_usage)
        or set(raw_usage) - required - {"reasoning"}):
        raise ProviderError("subscription raw usage fields mismatch")
    if any(type(value) is not int or not 0 <= value <= _MAX_TOKENS
           for value in raw_usage.values()):
        raise ProviderError("subscription raw usage is invalid")
    input_tokens = raw_usage["input"] + raw_usage["cacheRead"] + raw_usage["cacheWrite"]
    output_tokens = raw_usage["output"]
    if (raw_usage["totalTokens"] != input_tokens + output_tokens
        or raw_usage.get("reasoning", 0) > output_tokens):
        raise ProviderError("subscription usage total or reasoning subset mismatch")
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": raw_usage["cacheRead"],
        "cache_write_tokens": raw_usage["cacheWrite"],
        "output_tokens": output_tokens,
        "reasoning_tokens": raw_usage.get("reasoning"),
        "total_tokens": raw_usage["totalTokens"],
    }


def _request_identity(public: dict[str, Any], request: Any) -> dict[str, Any]:
    request = provider_config.exact_dict(request, {
        "schema", "run_id", "sequence", "batch_id", "request_id", "role", "model_id",
        "input_hashes", "prompt_sha256", "conversation_id", "history_sha256",
    }, "subscription request")
    required_hashes = {public["role_profile_sha256"], public["source_packet_sha256"],
                       public["runtime_identity_sha256"], request.get("history_sha256")}
    if (request.get("schema") != "autofv-model-request/v2"
        or request.get("run_id") != public["run_id"]
        or request.get("model_id") != public["model_id"]
        or request.get("role") not in public["role_profile"]["role_models"]
        or type(request.get("sequence")) is not int or request["sequence"] <= 0
        or any(not isinstance(request.get(key), str) or not request[key]
               or len(request[key]) > 512 for key in ("request_id", "role", "conversation_id"))
        or not isinstance(request.get("history_sha256"), str)
        or _SHA.fullmatch(request["history_sha256"]) is None
        or _SHA.fullmatch(request["conversation_id"]) is None
        or re.fullmatch(r"lane-" + request["conversation_id"][:16] + r"-[0-9]{3}", request["request_id"]) is None
        or not required_hashes <= set(request.get("input_hashes", []))):
        raise ProviderError("subscription request identity mismatch")
    return {key: request[key] for key in
            ("run_id", "sequence", "request_id", "model_id", "role", "conversation_id", "history_sha256")}


def build_receipt(
    binding: provider_config.ProviderBinding, request: dict[str, Any],
    response: dict[str, Any], raw_usage: dict[str, Any], continuation: dict[str, Any],
    *, provider_response_id: str | None = None, termination: str = "toolUse",
    observed_effort: str | None = None,
) -> dict[str, Any]:
    public = _public(binding)
    identity = _request_identity(public, request)
    # Validate private continuation before signing its digest. The retained public
    # attestation deliberately excludes native opaque reasoning items.
    from .pi_process import validate_continuation
    validate_continuation(continuation, request, response)
    if continuation["native"]["response_id"] != provider_response_id:
        raise ProviderError("subscription native response identity mismatch")
    if any(response.get(key) != identity[key]
           for key in ("run_id", "sequence", "request_id", "model_id", "role")):
        raise ProviderError("subscription response identity mismatch")
    if (provider_response_id is not None and
        (not isinstance(provider_response_id, str) or not provider_response_id
         or len(provider_response_id) > 512)):
        raise ProviderError("subscription provider response identity is invalid")
    if termination not in {"stop", "toolUse"} or observed_effort not in {None, "xhigh"}:
        raise ProviderError("subscription terminal observation is invalid")
    body = {
        "schema": SCHEMA, "proxy_id": public["proxy_id"], "route_id": public["route_id"],
        **identity,
        "request_sha256": _sha(request), "response_sha256": _sha(response),
        "continuation_sha256": _sha(continuation), "binding_sha256": public["binding_sha256"],
        "role_profile_sha256": public["role_profile_sha256"],
        "source_packet_sha256": public["source_packet_sha256"],
        "status": "ok", "usage": normalize_usage(raw_usage),
        "raw_usage": copy.deepcopy(raw_usage),
        "cost": {"amount": None, "currency": "USD", "basis": CLASSIFICATION},
        "provider": {
            "provider": "openai", "api": "openai-responses",
            "response_id": provider_response_id,
            "runtime_identity_sha256": public["runtime_identity_sha256"],
            "requested_effort": "xhigh", "observed_effort": observed_effort,
            "requested_tool_choice": "required", "termination": termination,
            "parameter_observation": ("provider reported effort" if observed_effort is not None
                                      else "requested; effort not independently reported"),
            "attestation_kind": "controller_usage_observation",
            "quota_status": "reported_usage; remaining_quota_unknown",
        },
        "dispatch_accounting_complete": True, "monetary_cost_known": False,
    }
    auth = provider_receipts._sign(binding, body)
    signed = {**body, "auth": auth}
    receipt = {**signed, "receipt_sha256": _sha(signed)}
    provider_messages.scan_response(receipt, binding)
    validate_receipt(receipt, binding=public, **{key: identity[key] for key in
                     ("run_id", "sequence", "request_id", "model_id")},
                     request_sha256=_sha(request), response_sha256=_sha(response),
                     seen_receipt_sha256=set(), request=request, continuation=continuation)
    return receipt


def validate_receipt(
    receipt: Any, *, binding: Any, run_id: str, sequence: int, request_id: str,
    model_id: str, request_sha256: str, response_sha256: str,
    seen_receipt_sha256: set[str] | frozenset[str],
    seen_request_ids: set[str] | frozenset[str] = frozenset(),
    request: dict[str, Any] | None = None, continuation: dict[str, Any] | None = None,
) -> None:
    """Authenticate the observation and return no monetary amount (unknown)."""
    public = _public(binding)
    receipt = provider_config.exact_dict(receipt, _FIELDS, "subscription attestation")
    expected = {
        "schema": SCHEMA, "proxy_id": public["proxy_id"], "route_id": public["route_id"],
        "run_id": run_id, "sequence": sequence, "request_id": request_id,
        "model_id": model_id, "request_sha256": request_sha256,
        "response_sha256": response_sha256, "binding_sha256": public["binding_sha256"],
        "role_profile_sha256": public["role_profile_sha256"],
        "source_packet_sha256": public["source_packet_sha256"],
        "status": "ok", "dispatch_accounting_complete": True,
        "monetary_cost_known": False,
        "cost": {"amount": None, "currency": "USD", "basis": CLASSIFICATION},
    }
    if (any(receipt.get(key) != value for key, value in expected.items())
        or receipt["dispatch_accounting_complete"] is not True
        or receipt["monetary_cost_known"] is not False
        or run_id != public["run_id"] or model_id != public["model_id"]
        or type(sequence) is not int or sequence <= 0):
        raise ProviderError("subscription attestation identity mismatch")
    if receipt["receipt_sha256"] in seen_receipt_sha256 or request_id in seen_request_ids:
        raise ProviderError("duplicate subscription attestation")
    for key in ("request_sha256", "response_sha256", "continuation_sha256", "history_sha256", "receipt_sha256"):
        if not isinstance(receipt[key], str) or _SHA.fullmatch(receipt[key]) is None:
            raise ProviderError("subscription attestation digest is invalid")
    if canonical_json_bytes(receipt["usage"]) != canonical_json_bytes(normalize_usage(receipt["raw_usage"])):
        raise ProviderError("subscription normalized usage mismatch")
    provider = provider_config.exact_dict(receipt["provider"], {
        "provider", "api", "response_id", "runtime_identity_sha256", "requested_effort",
        "observed_effort", "requested_tool_choice", "termination", "parameter_observation",
        "attestation_kind", "quota_status",
    }, "subscription provider observation")
    expected_provider = {
        "provider": "openai", "api": "openai-responses",
        "runtime_identity_sha256": public["runtime_identity_sha256"],
        "requested_effort": "xhigh", "requested_tool_choice": "required",
        "attestation_kind": "controller_usage_observation",
        "quota_status": "reported_usage; remaining_quota_unknown",
        "parameter_observation": ("provider reported effort" if provider["observed_effort"] is not None
                                  else "requested; effort not independently reported"),
    }
    if (any(provider.get(key) != value for key, value in expected_provider.items())
        or provider["observed_effort"] not in {None, "xhigh"}
        or provider["termination"] not in {"stop", "toolUse"}
        or (provider["response_id"] is not None and
            (not isinstance(provider["response_id"], str) or not provider["response_id"]
             or len(provider["response_id"]) > 512))):
        raise ProviderError("subscription provider observation mismatch")
    if request is not None:
        identity = _request_identity(public, request)
        if _sha(request) != request_sha256 or any(receipt[key] != value for key, value in identity.items()):
            raise ProviderError("subscription attestation request binding mismatch")
    if continuation is not None:
        if _sha(continuation) != receipt["continuation_sha256"]:
            raise ProviderError("subscription continuation digest mismatch")
        if request is not None:
            from .pi_process import validate_continuation
            validate_continuation(continuation, request)
        if continuation["native"]["response_id"] != provider["response_id"]:
            raise ProviderError("subscription native response identity mismatch")
    signed = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    body = {key: value for key, value in signed.items() if key != "auth"}
    if receipt["receipt_sha256"] != _sha(signed):
        raise ProviderError("subscription attestation hash mismatch")
    provider_receipts.verify_signature(body, receipt["auth"], public["receipt_authentication"],
                                       "subscription attestation")
    return None


validate_attestation = validate_receipt


def reduce_accounting(
    run: dict[str, Any], state: dict[str, Any], *, binding: Any,
    allow_incomplete: bool = False, require_private: bool = True,
) -> dict[str, Any]:
    """Reduce authenticated dispatch evidence separately from unknown money."""
    from . import subscription_journal
    public = _public(binding)
    recovery = subscription_journal.validate_recovery_artifacts(
        run, state, binding=binding, require_private=require_private)
    journal = recovery["journal"]
    exchanges = state.get("model_exchanges", {})
    pending = state.get("pending_model_exchanges", {})
    if not isinstance(exchanges, dict) or not isinstance(pending, dict):
        raise ProviderError("subscription exchange collection mismatch")
    accepted, unresolved = [], []
    totals = {"input": 0, "output": 0, "total": 0}
    raw_totals = {key: 0 for key in ("input", "output", "cacheRead", "cacheWrite", "totalTokens")}
    seen_receipts: set[str] = set()
    seen_requests: set[str] = set()
    for request_id, record in sorted(journal.items(), key=lambda item: item[1]["invocation"]):
        if record["status"] != "completed":
            unresolved.append({
                "request_id": request_id, "sequence": record["request"]["sequence"],
                "status": "dispatched", "call_kind": "explicit", "reservation_usd": None,
                "request": copy.deepcopy(record["request"]),
                "request_sha256": record["request_sha256"],
                "record_sha256": record["record_sha256"], "usage": None,
            })
            continue
        exchange = exchanges.get(request_id) or pending.get(request_id)
        if exchange is not None and any(exchange.get(key) != record[key]
                                        for key in ("request", "response", "receipt")):
            raise ProviderError("subscription completed exchange mismatch")
        if exchange is None and not allow_incomplete:
            raise ProviderError("subscription completed exchange is missing")
        request, response, receipt = record["request"], record["response"], record["receipt"]
        validate_receipt(receipt, binding=public, run_id=run["run_id"], sequence=request["sequence"],
                         request_id=request_id, model_id=request["model_id"], request_sha256=_sha(request),
                         response_sha256=_sha(response), seen_receipt_sha256=seen_receipts,
                         seen_request_ids=seen_requests, request=request)
        seen_receipts.add(receipt["receipt_sha256"])
        seen_requests.add(request_id)
        for target, source in (("input", "input_tokens"), ("output", "output_tokens"), ("total", "total_tokens")):
            totals[target] += receipt["usage"][source]
        for key in raw_totals:
            raw_totals[key] += receipt["raw_usage"][key]
        accepted.append({"request": copy.deepcopy(request), "response": copy.deepcopy(response),
                         "receipt": copy.deepcopy(receipt),
                         "call_kind": exchange.get("call_kind", "explicit") if exchange else "explicit"})
    if set(exchanges) - seen_requests:
        raise ProviderError("subscription exchange has no completed journal record")
    state_receipts = state.get("receipts", [])
    if not isinstance(state_receipts, list) or state_receipts != [exchanges[key]["receipt"]
            for key in sorted(exchanges, key=lambda key: exchanges[key]["request"]["sequence"])]:
        raise ProviderError("subscription receipt set mismatch")
    if unresolved and not allow_incomplete:
        raise ProviderError("subscription dispatch outcome is unresolved")
    invocation_limit = public["grant"]["max_invocations"]
    usage = {"requests": len(accepted), "tokens": totals, "raw_tokens": raw_totals,
             "cost_usd": None, "attestation_kind": "controller_usage_observation"}
    return {
        "classification": CLASSIFICATION, "requests": len(accepted), "tokens": totals,
        "cost": None, "accounting": {"subscription": usage}, "model_exchanges": accepted,
        "accounting_complete": not unresolved, "dispatch_accounting_complete": not unresolved,
        # The invocation grant is finite, but supplies no monetary ceiling.
        "monetary_cost_known": False, "accounting_bounded": False,
        "unresolved_requests": unresolved, "unknown_provider_spend": True,
        "reported_spend_known": False, "invocation_limit": invocation_limit,
        "invocations_used": len(journal), "invocations_remaining": invocation_limit - len(journal),
        "subscription_journal": recovery["summary"],
        "subscription_journal_sha256": recovery["summary"]["record_sha256"],
    }


def reduce_incomplete_accounting(run: dict[str, Any], state: dict[str, Any], *, binding: Any,
                                 require_private: bool = True) -> dict[str, Any]:
    return reduce_accounting(run, state, binding=binding, allow_incomplete=True,
                             require_private=require_private)
