"""Fresh, hash-bound evidence gate for deterministic external-run preflight."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError,
    HEX_SHA256,
    _read_json,
    canonical_json_bytes,
)


DETERMINISTIC_PREFLIGHT_CASES = (
    "linear_dependency_chain",
    "shared_helper_convergence",
    "same_file_serialization",
    "immediate_consumer_release",
    "cycle_rejection",
    "stale_binding_reverification",
    "undeclared_dependency_rejected",
    "candidate_trust_scope_rejected",
    "budget_receipt_reconciliation",
    "honest_terminal_labels",
)
DETERMINISTIC_PREFLIGHT_GATES = (
    "tool_schema_equality",
    "secret_scan",
    "symlink_scan",
    "spoiler_scan",
    "fixed_egress_path",
    "provider_identity",
    "candidate_scope",
    "distinct_terminal_verifier",
)
_IDENTITY_FIELDS = frozenset(
    {
        "image_digest",
        "runtime_sha256",
        "native_decide_policy_sha256",
        "tool_schema_sha256",
        "provider_identity_sha256",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "schema",
        "readiness",
        "suite_sha256",
        "cases",
        "gates",
        "identities",
        "zero_secret_scan_sha256",
        "source_head",
        "completed_at_unix",
        "preflight_sha256",
    }
)
_MAX_BYTES = 256_000


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise ContractError(f"{label} must be a SHA-256 digest")
    return value


def _evidence(
    value: Any, expected_names: tuple[str, ...], label: str
) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != set(expected_names):
        raise ContractError(f"{label} evidence set is incomplete")
    return {
        name: {
            "status": "green",
            "evidence_sha256": _digest(value[name], f"{label} {name}"),
        }
        for name in expected_names
    }


def _validate(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
        raise ContractError("deterministic preflight fields mismatch")
    if record["schema"] != "autofv-deterministic-preflight/v1":
        raise ContractError("deterministic preflight schema mismatch")
    if record["readiness"] != "ready":
        raise ContractError("deterministic preflight is not green")
    _digest(record["suite_sha256"], "suite digest")
    _digest(record["zero_secret_scan_sha256"], "zero-secret scan digest")
    if (
        not isinstance(record["source_head"], str)
        or re.fullmatch(r"[0-9a-f]{40}", record["source_head"]) is None
    ):
        raise ContractError("deterministic preflight source HEAD is invalid")
    if type(record["completed_at_unix"]) is not int or record["completed_at_unix"] < 0:
        raise ContractError("deterministic preflight timestamp is invalid")
    identities = record["identities"]
    if not isinstance(identities, dict) or set(identities) != _IDENTITY_FIELDS:
        raise ContractError("deterministic preflight identities mismatch")
    image = identities["image_digest"]
    if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise ContractError("deterministic preflight image identity is invalid")
    for name in _IDENTITY_FIELDS - {"image_digest"}:
        _digest(identities[name], f"preflight identity {name}")
    for name, expected in (
        ("cases", DETERMINISTIC_PREFLIGHT_CASES),
        ("gates", DETERMINISTIC_PREFLIGHT_GATES),
    ):
        entries = record[name]
        if not isinstance(entries, dict) or set(entries) != set(expected):
            raise ContractError(f"deterministic preflight {name} are incomplete")
        for item_name, item in entries.items():
            if (
                not isinstance(item, dict)
                or set(item) != {"status", "evidence_sha256"}
                or item["status"] != "green"
            ):
                raise ContractError(f"deterministic preflight {name} are not green")
            _digest(item["evidence_sha256"], f"{name} {item_name}")
    body = {key: value for key, value in record.items() if key != "preflight_sha256"}
    expected_digest = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    if not hmac.compare_digest(
        _digest(record["preflight_sha256"], "preflight digest"), expected_digest
    ):
        raise ContractError("deterministic preflight digest mismatch")
    return record


def write_deterministic_preflight(
    path: str | Path,
    *,
    suite_sha256: str,
    case_evidence: dict[str, str],
    gate_evidence: dict[str, str],
    identities: dict[str, str],
    zero_secret_scan_sha256: str,
    source_head: str,
    completed_at_unix: int,
) -> dict[str, Any]:
    """Atomically emit a bounded, hash-bound green preflight record."""
    destination = Path(path)
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        raise ContractError("deterministic preflight destination is unsafe")
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise ContractError("deterministic preflight parent is unavailable") from exc
    body = {
        "schema": "autofv-deterministic-preflight/v1",
        "readiness": "ready",
        "suite_sha256": _digest(suite_sha256, "suite digest"),
        "cases": _evidence(case_evidence, DETERMINISTIC_PREFLIGHT_CASES, "case"),
        "gates": _evidence(gate_evidence, DETERMINISTIC_PREFLIGHT_GATES, "gate"),
        "identities": dict(identities),
        "zero_secret_scan_sha256": _digest(
            zero_secret_scan_sha256, "zero-secret scan digest"
        ),
        "source_head": source_head,
        "completed_at_unix": completed_at_unix,
    }
    record = {
        **body,
        "preflight_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
    }
    record = _validate(record)
    raw = canonical_json_bytes(record) + b"\n"
    if len(raw) > _MAX_BYTES:
        raise ContractError("deterministic preflight exceeds its size bound")
    temporary = parent / f".{destination.name}.{secrets.token_hex(8)}.tmp"
    try:
        temporary.write_bytes(raw)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return record


def require_deterministic_preflight(
    path: str | Path,
    *,
    expected_identities: dict[str, str],
    expected_source_head: str,
    now_unix: int,
    max_age_seconds: int,
) -> dict[str, Any]:
    """Fail closed unless the local preflight is exact, green, and fresh."""
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > _MAX_BYTES:
        raise ContractError("deterministic preflight record is unavailable or unsafe")
    try:
        raw = source.read_bytes()
        record = _read_json(source, "deterministic preflight")
    except OSError as exc:
        raise ContractError("deterministic preflight record is unreadable") from exc
    if raw != canonical_json_bytes(record) + b"\n":
        raise ContractError("deterministic preflight is not canonical")
    record = _validate(record)
    if record["identities"] != expected_identities:
        raise ContractError("deterministic preflight identity is stale")
    if record["source_head"] != expected_source_head:
        raise ContractError("deterministic preflight source HEAD is stale")
    if type(now_unix) is not int or type(max_age_seconds) is not int or max_age_seconds < 0:
        raise ContractError("deterministic preflight freshness policy is invalid")
    age = now_unix - record["completed_at_unix"]
    if age < 0 or age > max_age_seconds:
        raise ContractError("deterministic preflight is stale")
    return record
