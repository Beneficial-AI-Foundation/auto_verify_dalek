"""Fresh, hash-bound evidence gate for deterministic external-run preflight."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError,
    _read_json,
    canonical_json_bytes,
)
from . import provider_receipts
from .preflight_evidence import (
    APPLICABILITY as _APPLICABILITY,
    CHECK_OUTCOME_SCHEMA,
    DETERMINISTIC_PREFLIGHT_CASES,
    DETERMINISTIC_PREFLIGHT_GATES,
    EVIDENCE_KINDS as _EVIDENCE_KINDS,
    IDENTITY_FIELDS as _IDENTITY_FIELDS,
    MAX_BYTES as _MAX_BYTES,
    RETAINED_SUITE_SCHEMA,
    digest as _digest,
    named_check_evidence,
    read_artifact as _artifact,
    validate_retained_suite as _validate_retained_suite,
    write_check_outcome,
    write_retained_suite_result,
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
PROVIDER_AUTHORIZATION_SCHEMA = "autofv-provider-authorization/v1"
_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "binding_sha256",
        "preflight_path",
        "suite_artifact_path",
        "preflight_sha256",
        "suite_sha256",
        "identities_sha256",
        "source_head",
        "max_age_seconds",
        "loaded_at_unix",
        "auth",
    }
)


def _evidence(
    value: Any, expected_names: tuple[str, ...], label: str, suite_sha256: str
) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != set(expected_names):
        raise ContractError(f"{label} evidence set is incomplete")
    result = {}
    for name in expected_names:
        entry = value[name]
        fields = {
            "check_id",
            "status",
            "evidence_kind",
            "applicability",
            "suite_sha256",
            "artifact_sha256",
        }
        if not isinstance(entry, dict) or set(entry) != fields:
            raise ContractError(f"{label} {name} evidence fields mismatch")
        if (
            not isinstance(entry["check_id"], str)
            or not entry["check_id"]
            or not entry["check_id"].rsplit("::", 1)[-1].endswith(name)
            or entry["status"] != "passed"
            or entry["evidence_kind"] not in _EVIDENCE_KINDS
            or entry["applicability"] not in _APPLICABILITY
            or entry["suite_sha256"] != suite_sha256
        ):
            raise ContractError(f"{label} {name} evidence is not applicable")
        _digest(entry["artifact_sha256"], f"{label} {name} artifact")
        body = dict(entry)
        result[name] = {
            **body,
            "evidence_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
        }
    return result


def _validate(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
        raise ContractError("deterministic preflight fields mismatch")
    if record["schema"] != "autofv-deterministic-preflight/v3":
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
                or set(item)
                != {
                    "status",
                    "check_id",
                    "evidence_kind",
                    "applicability",
                    "suite_sha256",
                    "artifact_sha256",
                    "evidence_sha256",
                }
                or item["status"] != "passed"
                or item["evidence_kind"] not in _EVIDENCE_KINDS
                or item["applicability"] not in _APPLICABILITY
                or item["suite_sha256"] != record["suite_sha256"]
            ):
                raise ContractError(f"deterministic preflight {name} are not green")
            _digest(item["evidence_sha256"], f"{name} {item_name}")
            evidence_body = {
                key: value for key, value in item.items() if key != "evidence_sha256"
            }
            if item["evidence_sha256"] != hashlib.sha256(
                canonical_json_bytes(evidence_body)
            ).hexdigest():
                raise ContractError(f"deterministic preflight {name} evidence mismatch")
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
        "schema": "autofv-deterministic-preflight/v3",
        "readiness": "ready",
        "suite_sha256": _digest(suite_sha256, "suite digest"),
        "cases": _evidence(
            case_evidence, DETERMINISTIC_PREFLIGHT_CASES, "case", suite_sha256
        ),
        "gates": _evidence(
            gate_evidence, DETERMINISTIC_PREFLIGHT_GATES, "gate", suite_sha256
        ),
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
    expected_suite_sha256: str,
    now_unix: int,
    max_age_seconds: int,
    required_applicability: str | None = None,
    required_evidence_kind: str | None = None,
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
    if record["suite_sha256"] != _digest(
        expected_suite_sha256, "expected suite digest"
    ):
        raise ContractError("deterministic preflight suite evidence is stale")
    if record["identities"] != expected_identities:
        raise ContractError("deterministic preflight identity is stale")
    if record["source_head"] != expected_source_head:
        raise ContractError("deterministic preflight source HEAD is stale")
    if type(now_unix) is not int or type(max_age_seconds) is not int or max_age_seconds < 0:
        raise ContractError("deterministic preflight freshness policy is invalid")
    age = now_unix - record["completed_at_unix"]
    if age < 0 or age > max_age_seconds:
        raise ContractError("deterministic preflight is stale")
    if required_applicability is not None:
        if required_applicability not in _APPLICABILITY or any(
            item["applicability"] != required_applicability
            for group in (record["cases"], record["gates"])
            for item in group.values()
        ):
            raise ContractError("deterministic preflight evidence is not applicable")
    if required_evidence_kind is not None:
        if required_evidence_kind not in _EVIDENCE_KINDS or any(
            item["evidence_kind"] != required_evidence_kind
            for group in (record["cases"], record["gates"])
            for item in group.values()
        ):
            raise ContractError("deterministic preflight evidence is not applicable")
    return record


def _current_provider_identities(
    run: dict[str, Any], provider_binding: dict[str, Any]
) -> dict[str, str]:
    if not isinstance(provider_binding, dict):
        raise ContractError("provider preflight binding is unavailable")
    identities = {
        "image_digest": run.get("image_digest"),
        "runtime_sha256": run.get("worker_inventory_sha256"),
        "native_decide_policy_sha256": run.get("native_decide_policy_sha256"),
        "tool_schema_sha256": provider_binding.get("tool_schema_sha256"),
        "provider_identity_sha256": provider_binding.get("binding_sha256"),
    }
    image = identities["image_digest"]
    if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise ContractError("provider preflight image identity is unavailable")
    for name in _IDENTITY_FIELDS - {"image_digest"}:
        _digest(identities[name], f"provider preflight identity {name}")
    return identities


def load_provider_evidence(
    run: dict[str, Any],
    provider_binding: dict[str, Any],
    *,
    preflight_path: str | Path,
    suite_artifact_path: str | Path,
    max_age_seconds: int,
    now_unix: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate sealed evidence and build the exact body the provider signs."""
    now = int(time.time()) if now_unix is None else now_unix
    if type(now) is not int or type(max_age_seconds) is not int or max_age_seconds < 0:
        raise ContractError("provider preflight freshness policy is invalid")
    preflight_source, _ = _artifact(preflight_path, "provider preflight record")
    identities = _current_provider_identities(run, provider_binding)
    source_head = run.get("base_commit")
    if not isinstance(source_head, str) or re.fullmatch(r"[0-9a-f]{40}", source_head) is None:
        raise ContractError("provider preflight source identity is unavailable")
    suite, suite_source, suite_raw = _validate_retained_suite(
        suite_artifact_path,
        expected_identities=identities,
        expected_source_head=source_head,
    )
    suite_sha256 = hashlib.sha256(suite_raw).hexdigest()
    record = require_deterministic_preflight(
        preflight_source,
        expected_identities=identities,
        expected_source_head=source_head,
        expected_suite_sha256=suite_sha256,
        now_unix=now,
        max_age_seconds=max_age_seconds,
        required_applicability="applicable_sealed_runtime",
        required_evidence_kind="sealed_runtime",
    )
    if record["completed_at_unix"] != suite["completed_at_unix"] or any(
        record[group][name][field] != suite[group][name][suite_field]
        for group in ("cases", "gates")
        for name in record[group]
        for field, suite_field in (
            ("check_id", "check_id"),
            ("status", "status"),
            ("evidence_kind", "execution_class"),
            ("applicability", "applicability"),
            ("artifact_sha256", "artifact_sha256"),
        )
    ):
        raise ContractError("provider preflight record does not match retained suite")
    body = {
        "schema": PROVIDER_AUTHORIZATION_SCHEMA,
        "run_id": provider_binding.get("run_id"),
        "binding_sha256": provider_binding.get("binding_sha256"),
        "preflight_path": str(preflight_source),
        "suite_artifact_path": str(suite_source),
        "preflight_sha256": record["preflight_sha256"],
        "suite_sha256": suite_sha256,
        "identities_sha256": hashlib.sha256(
            canonical_json_bytes(identities)
        ).hexdigest(),
        "source_head": source_head,
        "max_age_seconds": max_age_seconds,
        "loaded_at_unix": now,
    }
    if not isinstance(body["run_id"], str) or not body["run_id"]:
        raise ContractError("provider preflight run identity is unavailable")
    _digest(body["binding_sha256"], "provider preflight binding identity")
    return body, record


def authorize_provider_action(
    run: dict[str, Any], provider_binding: dict[str, Any]
) -> dict[str, Any]:
    """Revalidate the signed evidence binding immediately before provider spend."""
    authorization = run.get("deterministic_preflight")
    if not isinstance(authorization, dict) or set(authorization) != _AUTHORIZATION_FIELDS:
        raise ContractError(
            "provider action requires deterministic preflight signed authorization"
        )
    signed = {key: value for key, value in authorization.items() if key != "auth"}
    provider_receipts.verify_signature(
        signed,
        authorization["auth"],
        provider_binding.get("receipt_authentication"),
        "provider preflight authorization",
    )
    identities = _current_provider_identities(run, provider_binding)
    source_head = run.get("base_commit")
    expected = {
        "schema": PROVIDER_AUTHORIZATION_SCHEMA,
        "run_id": run.get("run_id"),
        "binding_sha256": provider_binding.get("binding_sha256"),
        "identities_sha256": hashlib.sha256(
            canonical_json_bytes(identities)
        ).hexdigest(),
        "source_head": source_head,
    }
    if any(signed.get(name) != value for name, value in expected.items()):
        raise ContractError("provider preflight authorization identity is stale")
    suite, suite_source, suite_raw = _validate_retained_suite(
        signed["suite_artifact_path"],
        expected_identities=identities,
        expected_source_head=source_head,
    )
    if (
        str(suite_source) != signed["suite_artifact_path"]
        or hashlib.sha256(suite_raw).hexdigest() != signed["suite_sha256"]
    ):
        raise ContractError("provider preflight suite evidence is stale")
    record = require_deterministic_preflight(
        signed["preflight_path"],
        expected_identities=identities,
        expected_source_head=source_head,
        expected_suite_sha256=signed["suite_sha256"],
        now_unix=int(time.time()),
        max_age_seconds=signed["max_age_seconds"],
        required_applicability="applicable_sealed_runtime",
        required_evidence_kind="sealed_runtime",
    )
    if (
        record["preflight_sha256"] != signed["preflight_sha256"]
        or record["completed_at_unix"] != suite["completed_at_unix"]
        or any(
            record[group][name][field] != suite[group][name][suite_field]
            for group in ("cases", "gates")
            for name in record[group]
            for field, suite_field in (
                ("check_id", "check_id"),
                ("status", "status"),
                ("evidence_kind", "execution_class"),
                ("applicability", "applicability"),
                ("artifact_sha256", "artifact_sha256"),
            )
        )
    ):
        raise ContractError("provider preflight authorization evidence is stale")
    run["deterministic_preflight_sha256"] = record["preflight_sha256"]
    run["deterministic_suite_sha256"] = record["suite_sha256"]
    return record


def authorize_external_action(run: dict[str, Any]) -> dict[str, Any]:
    """Mandatory authorization immediately before any authenticated provider action."""
    provider_binding = run.get("provider_binding")
    if not isinstance(provider_binding, dict):
        raise ContractError(
            "external action requires deterministic preflight and authenticated provider binding"
        )
    return authorize_provider_action(run, provider_binding)
