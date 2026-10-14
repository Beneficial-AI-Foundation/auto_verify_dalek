"""Closed runtime selection for the frozen API and opt-in Pi FVS profiles.

Selection is never authorization. No credentials, account discovery, or live
entitlement inference takes place here. Pi keeps the methodology and fresh
reviews, but is an explicitly different, OpenAI-only experiment profile.
"""
from __future__ import annotations

import copy
from typing import Any

from .contracts import ContractError, _exact_dict, _sha256, canonical_json_bytes
from . import fvs_profile

PI_PROFILE_ID = "autofv-fvs-pi-openai/v1"
PI_MODEL = "gpt-6.1-sol"
PI_BINDING_SCHEMA = "autofv-provider-binding/v3"
METHODOLOGY = "fvs-fc/v1"
PI_PACKAGES = {
    "@earendil-works/pi-ai": "1.2.0",
    "@earendil-works/pi-coding-agent": "1.2.0",
}


def is_pi(config: dict[str, Any]) -> bool:
    return config.get("schema") == "autofv-run/v3"


def profile() -> dict[str, Any]:
    """Return the sole Pi role policy; model entitlement remains unverified."""
    return {
        "schema": PI_PROFILE_ID,
        "methodology": METHODOLOGY,
        "adapter": "autofv-bounded-fc/v1",
        "role_runtime": "deepagents",
        "model_backend": "pi-model-runtime",
        "accounting_class": "subscription_cost_unknown",
        "role_models": {role: PI_MODEL for role in fvs_profile.ROLE_MODELS},
        "parameters": {
            "provider": "openai", "api": "openai-responses",
            "requested_effort": "xhigh", "tool_choice": "required",
            "stream": True, "timeout_seconds": 120,
            "server_output_token_cap": None,
        },
        "routing": {"allow_fallbacks": False},
        "runtime": {"protocol_version": 1, "packages": dict(PI_PACKAGES)},
        "limits": {
            "max_concurrent_generations": 1,
            "invocation_limit_source": "run_config.max_invocations",
            "deadline_source": "original_absolute_deadline",
            "remote_cancellation": "best_effort",
        },
        "context_bytes": 262144,
        "max_review_rounds": 3,
        "max_proof_attempts": 3,
    }


def validate_profile(value: Any) -> dict[str, Any]:
    expected = profile()
    if value != expected or canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ContractError("Pi role/runtime profile drift")
    return copy.deepcopy(value)


def resolve(config: dict[str, Any]) -> dict[str, Any]:
    """Resolve only the two named FVS families; never accept arbitrary models."""
    if is_pi(config):
        if config.get("role_profile") != PI_PROFILE_ID or config.get("model") != PI_MODEL:
            raise ContractError("Pi run role/model profile mismatch")
        return profile()
    if config.get("schema") == "autofv-run/v2":
        if (config.get("role_profile") != fvs_profile.PROFILE_ID
                or config.get("model") != fvs_profile.AUTHOR):
            raise ContractError("FVS run role/model profile mismatch")
        return fvs_profile.profile()
    raise ContractError("runtime profile requires an explicit FVS run version")


def profile_sha256(config: dict[str, Any]) -> str:
    return fvs_profile.digest(resolve(config))


def model_for(config: dict[str, Any], role: str) -> str:
    if config.get("schema") == "autofv-run/v1":
        return config["model"]
    selected = resolve(config)
    try:
        return selected["role_models"][role]
    except (KeyError, TypeError) as exc:
        raise ContractError("runtime role is not in the frozen role table") from exc


def validate_runtime_identity(value: Any) -> dict[str, Any]:
    identity = _exact_dict(value, {
        "schema", "protocol_version", "node_sha256", "bridge_sha256",
        "package_lock_sha256", "packages",
    }, "Pi runtime identity")
    if (identity["schema"] != "autofv-pi-runtime-identity/v1"
            or type(identity["protocol_version"]) is not int
            or identity["protocol_version"] != 1
            or identity["packages"] != PI_PACKAGES
            or canonical_json_bytes(identity["packages"]) != canonical_json_bytes(PI_PACKAGES)):
        raise ContractError("Pi runtime package/protocol identity drift")
    for key in ("node_sha256", "bridge_sha256", "package_lock_sha256"):
        _sha256(identity[key], "Pi runtime " + key)
    return copy.deepcopy(identity)


def role_identity(role: str, runtime_identity_sha256: str) -> dict[str, Any]:
    if not isinstance(role, str) or role not in fvs_profile.ROLE_MODELS:
        raise ContractError("Pi runtime role is not in the frozen role table")
    _sha256(runtime_identity_sha256, "Pi runtime identity hash")
    selected = profile()
    return {
        "role_profile": PI_PROFILE_ID,
        "role_profile_sha256": fvs_profile.digest(selected),
        "runtime_identity_sha256": runtime_identity_sha256,
        "role_runtime": "deepagents", "model_backend": "pi-model-runtime",
        "provider": "openai", "api": "openai-responses", "model_id": PI_MODEL,
        "requested_effort": "xhigh", "tool_choice": "required",
        "server_output_token_cap": None,
        "accounting_class": "subscription_cost_unknown",
    }


def validate_role_identity(value: Any, role: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("Pi role runtime identity must be an object")
    expected = role_identity(role, value.get("runtime_identity_sha256"))
    if value != expected or canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ContractError("Pi role runtime identity drift")
    return copy.deepcopy(value)


def identity_hashes(value: dict[str, Any]) -> set[str]:
    return {value["role_profile_sha256"], value["runtime_identity_sha256"],
            fvs_profile.digest(value)}


def validate_binding_profile(binding: dict[str, Any]) -> dict[str, Any]:
    """Validate public profile identity, never establish runtime authorization."""
    if not isinstance(binding, dict) or binding.get("schema") != PI_BINDING_SCHEMA:
        raise ContractError("Pi requires its distinct provider binding")
    selected = validate_profile(binding.get("role_profile"))
    if binding.get("role_profile_sha256") != fvs_profile.digest(selected):
        raise ContractError("Pi provider profile hash drift")
    identity = validate_runtime_identity(binding.get("runtime_identity"))
    if binding.get("runtime_identity_sha256") != fvs_profile.digest(identity):
        raise ContractError("Pi provider runtime hash drift")
    return selected
