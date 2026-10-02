"""Frozen, opt-in OpenRouter FVS routing and bounded pricing policy.

This is selection policy, never spend authorization. Legacy bindings do not use it.
"""
from __future__ import annotations

import copy
import hashlib
from decimal import Decimal
from typing import Any

from .contracts import ContractError, canonical_json_bytes

PROFILE_ID = "autofv-fvs-sol-sonnet/v1"
AUTHOR = "openai/gpt-6.1-sol"
REVIEWER = "anthropic/claude-sonnet-5.5"
REVIEW_ROLES = frozenset({"spec_reviewer", "proof_reviewer"})
ROLE_MODELS = {
    role: REVIEWER if role in REVIEW_ROLES else AUTHOR
    for role in ("scout", "dependency_planner", "specifier", "spec_reviewer",
                 "prover", "proof_reviewer", "repair", "verification_adviser")
}


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def profile() -> dict[str, Any]:
    return {
        "schema": PROFILE_ID,
        "adapter": "autofv-bounded-fc/v1",
        "role_models": dict(ROLE_MODELS),
        "parameters": {
            "reasoning": {"effort": "xhigh", "exclude": True},
            "stream": False, "timeout_seconds": 30,
            "work_max_output_tokens": 16384, "review_max_output_tokens": 8192,
        },
        "models": {
            AUTHOR: {
                "provider": "openai", "observed_provider": "OpenAI",
                "ignored_endpoints": ["openai/fast", "openai/flex"],
                "tool_choice": "required", "max_output_tokens": 16384,
                "tiers": [
                    {"min_input_tokens": 0, "input": "2", "cached": "0.10",
                     "write_lower": "2.50", "write_upper": "2.50", "output": "10"},
                    {"min_input_tokens": 272000, "input": "4", "cached": "0.20",
                     "write_lower": "5", "write_upper": "5", "output": "15"},
                ],
            },
            REVIEWER: {
                "provider": "anthropic", "observed_provider": "Anthropic",
                "ignored_endpoints": [],
                "tool_choice": "auto", "max_output_tokens": 8192,
                "tiers": [
                    {"min_input_tokens": 0, "input": "2", "cached": "0.20",
                     "write_lower": "2.50", "write_upper": "4", "output": "10"},
                ],
            },
        },
        "routing": {"allow_fallbacks": False, "require_parameters": True},
        "context_bytes": 262144,
        "max_review_rounds": 3,
        "max_proof_attempts": 3,
    }


def validate_profile(value: Any) -> dict[str, Any]:
    if value != profile() or canonical_json_bytes(value) != canonical_json_bytes(profile()):
        raise ContractError("FVS role/parameter/pricing profile drift")
    return copy.deepcopy(value)


def enabled(config: dict[str, Any]) -> bool:
    return config.get("schema") == "autofv-run/v2"


def model_for(config: dict[str, Any], role: str) -> str:
    if not enabled(config):
        return config["model"]
    if config.get("role_profile") != PROFILE_ID or config.get("model") != AUTHOR:
        raise ContractError("FVS run profile mismatch")
    try:
        return ROLE_MODELS[role]
    except KeyError as exc:
        raise ContractError("FVS request role is not in the frozen role table") from exc


def binding_model(binding: dict[str, Any], role: str) -> str:
    if binding.get("schema") != "autofv-provider-binding/v2":
        return binding["model_id"]
    validate_profile(binding["role_profile"])
    try:
        return ROLE_MODELS[role]
    except KeyError as exc:
        raise ContractError("FVS provider request role mismatch") from exc


def model_policy(binding: dict[str, Any], model: str) -> dict[str, Any]:
    validate_profile(binding["role_profile"])
    try:
        return copy.deepcopy(binding["role_profile"]["models"][model])
    except KeyError as exc:
        raise ContractError("FVS provider model mismatch") from exc


def pricing_bounds(model: str, usage: dict[str, int]) -> tuple[Decimal, Decimal]:
    """Output includes billed reasoning. Cache TTL is unknown, not inferred."""
    policy = profile()["models"][model]
    tier = max((t for t in policy["tiers"] if usage["input_tokens"] >= t["min_input_tokens"]),
               key=lambda t: t["min_input_tokens"])
    uncached = usage["input_tokens"] - usage["cached_input_tokens"] - usage["cache_write_tokens"]
    if uncached < 0 or usage["reasoning_tokens"] > usage["output_tokens"]:
        raise ContractError("FVS usage categories overlap or exceed totals")
    base = (Decimal(uncached) * Decimal(tier["input"])
            + Decimal(usage["cached_input_tokens"]) * Decimal(tier["cached"])
            + Decimal(usage["output_tokens"]) * Decimal(tier["output"]))
    return tuple((base + Decimal(usage["cache_write_tokens"]) * Decimal(tier[key]))
                 / Decimal(1000000) for key in ("write_lower", "write_upper"))


def reservation(model: str, input_ceiling: int) -> Decimal:
    policy = profile()["models"][model]
    # The byte ceiling is not an observed token count. Reserve every applicable tier.
    tiers = [t for t in policy["tiers"] if t["min_input_tokens"] <= input_ceiling]
    input_rate = max(Decimal(t[key]) for t in tiers
                     for key in ("input", "cached", "write_upper"))
    output_rate = max(Decimal(t["output"]) for t in tiers)
    return (Decimal(input_ceiling) * input_rate
            + Decimal(policy["max_output_tokens"]) * output_rate) / Decimal(1000000)


def requested_routing(model: str) -> dict[str, Any]:
    policy = profile()["models"][model]
    # Base provider slugs also match variants. Exclude the frozen known variants;
    # selection must reject any additional eligible endpoint before dispatch.
    return {"only": [policy["provider"]], "ignore": list(policy["ignored_endpoints"]),
            "allow_fallbacks": False, "require_parameters": True}
