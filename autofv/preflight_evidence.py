"""Canonical retained preflight-suite and per-check evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from .contracts import ContractError, HEX_SHA256, canonical_json_bytes


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
IDENTITY_FIELDS = frozenset(
    {
        "image_digest",
        "runtime_sha256",
        "native_decide_policy_sha256",
        "tool_schema_sha256",
        "provider_identity_sha256",
    }
)
MAX_BYTES = 256_000
EVIDENCE_KINDS = frozenset({"unittest", "static_policy", "sealed_runtime"})
APPLICABILITY = frozenset({"simulated_static", "applicable_sealed_runtime"})
CHECK_OUTCOME_SCHEMA = "autofv-check-outcome/v2"
RETAINED_SUITE_SCHEMA = "autofv-retained-suite/v1"
_OUTCOME_STATUSES = frozenset({"passed", "failed", "error", "skipped"})
_OUTCOME_ORIGINS = frozenset({"trusted_runner", "synthetic_fixture"})
_OUTCOME_FIELDS = frozenset(
    {
        "schema",
        "check_name",
        "check_id",
        "status",
        "required",
        "origin",
        "execution_class",
        "applicability",
        "identities",
        "source_head",
        "outcome_sha256",
    }
)
_SUITE_FIELDS = frozenset(
    {
        "schema",
        "status",
        "cases",
        "gates",
        "identities",
        "source_head",
        "completed_at_unix",
        "suite_sha256",
    }
)


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise ContractError(f"{label} must be a SHA-256 digest")
    return value


def validated_identities(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != IDENTITY_FIELDS:
        raise ContractError(f"{label} identities mismatch")
    image = value["image_digest"]
    if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise ContractError(f"{label} image identity is invalid")
    for name in IDENTITY_FIELDS - {"image_digest"}:
        digest(value[name], f"{label} identity {name}")
    return dict(value)


def _write_canonical(path: str | Path, value: dict[str, Any], label: str) -> None:
    destination = Path(path)
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        raise ContractError(f"{label} destination is unsafe")
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise ContractError(f"{label} parent is unavailable") from exc
    raw = canonical_json_bytes(value) + b"\n"
    if len(raw) > MAX_BYTES:
        raise ContractError(f"{label} exceeds its size bound")
    temporary = parent / f".{destination.name}.{secrets.token_hex(8)}.tmp"
    try:
        temporary.write_bytes(raw)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _validate_check_outcome(
    value: Any, *, expected_name: str | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _OUTCOME_FIELDS:
        raise ContractError("retained check outcome fields mismatch")
    body = {key: item for key, item in value.items() if key != "outcome_sha256"}
    if (
        value["schema"] != CHECK_OUTCOME_SCHEMA
        or value["status"] not in _OUTCOME_STATUSES
        or value["required"] is not True
        or value["origin"] not in _OUTCOME_ORIGINS
        or value["execution_class"] not in EVIDENCE_KINDS
        or value["applicability"] not in APPLICABILITY
        or not isinstance(value["check_name"], str)
        or not value["check_name"]
        or not isinstance(value["check_id"], str)
        or not value["check_id"]
        or not value["check_id"].rsplit("::", 1)[-1].endswith(
            value["check_name"]
        )
        or (expected_name is not None and value["check_name"] != expected_name)
        or value["outcome_sha256"]
        != hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    ):
        raise ContractError("retained check outcome is invalid")
    validated_identities(value["identities"], "retained check outcome")
    if not isinstance(value["source_head"], str) or re.fullmatch(
        r"[0-9a-f]{40}", value["source_head"]
    ) is None:
        raise ContractError("retained check outcome source identity is invalid")
    return value


def write_check_outcome(
    path: str | Path,
    *,
    check_name: str,
    check_id: str,
    status: str,
    origin: str,
    execution_class: str,
    applicability: str,
    identities: dict[str, str],
    source_head: str,
) -> dict[str, Any]:
    """Retain one structured named outcome; callers cannot supply its digest."""
    body = {
        "schema": CHECK_OUTCOME_SCHEMA,
        "check_name": check_name,
        "check_id": check_id,
        "status": status,
        "required": True,
        "origin": origin,
        "execution_class": execution_class,
        "applicability": applicability,
        "identities": dict(identities),
        "source_head": source_head,
    }
    outcome = {
        **body,
        "outcome_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
    }
    outcome = _validate_check_outcome(outcome, expected_name=check_name)
    _write_canonical(path, outcome, "retained check outcome")
    return outcome


def named_check_evidence(
    check_id: str,
    artifact: bytes,
    *,
    suite_sha256: str,
    evidence_kind: str,
    applicability: str,
) -> dict[str, str]:
    """Create evidence from one named check and its actual retained output bytes."""
    if not isinstance(check_id, str) or not check_id or "case:" in check_id:
        raise ContractError("deterministic preflight check id is invalid")
    if not isinstance(artifact, bytes) or not artifact:
        raise ContractError("deterministic preflight artifact is empty")
    if evidence_kind not in EVIDENCE_KINDS or applicability not in APPLICABILITY:
        raise ContractError("deterministic preflight evidence classification is invalid")
    try:
        outcome = json.loads(artifact)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContractError("deterministic preflight outcome is invalid") from exc
    if artifact != canonical_json_bytes(outcome) + b"\n":
        raise ContractError("deterministic preflight outcome is not canonical")
    outcome = _validate_check_outcome(outcome)
    if (
        outcome["check_id"] != check_id
        or outcome["status"] != "passed"
        or outcome["execution_class"] != evidence_kind
        or outcome["applicability"] != applicability
    ):
        raise ContractError("deterministic preflight outcome is not green")
    return {
        "check_id": check_id,
        "status": outcome["status"],
        "evidence_kind": outcome["execution_class"],
        "applicability": outcome["applicability"],
        "suite_sha256": digest(suite_sha256, "evidence suite digest"),
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
    }


def read_artifact(path: str | Path, label: str) -> tuple[Path, bytes]:
    source = Path(path)
    try:
        if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_BYTES:
            raise ContractError(f"{label} is unavailable or unsafe")
        resolved = source.resolve(strict=True)
        raw = source.read_bytes()
    except OSError as exc:
        raise ContractError(f"{label} is unreadable") from exc
    if not raw:
        raise ContractError(f"{label} is empty")
    return resolved, raw


def _outcome_reference(
    suite_parent: Path, path: str | Path, name: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved, raw = read_artifact(path, f"retained check artifact {name}")
    try:
        relative = resolved.relative_to(suite_parent)
    except ValueError as exc:
        raise ContractError("retained check artifact escapes the suite directory") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ContractError("retained check artifact path is invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContractError("retained check artifact is unreadable") from exc
    if raw != canonical_json_bytes(value) + b"\n":
        raise ContractError("retained check artifact is not canonical")
    outcome = _validate_check_outcome(value, expected_name=name)
    reference = {
        "check_id": outcome["check_id"],
        "status": outcome["status"],
        "required": outcome["required"],
        "origin": outcome["origin"],
        "execution_class": outcome["execution_class"],
        "applicability": outcome["applicability"],
        "artifact_path": relative.as_posix(),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "artifact_size": len(raw),
        "outcome_sha256": outcome["outcome_sha256"],
    }
    return reference, outcome


def write_retained_suite_result(
    path: str | Path,
    *,
    case_outcomes: dict[str, str | Path],
    gate_outcomes: dict[str, str | Path],
    identities: dict[str, str],
    source_head: str,
    completed_at_unix: int,
) -> dict[str, Any]:
    """Build a retained suite only from canonical per-check artifacts."""
    destination = Path(path)
    try:
        suite_parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise ContractError("retained suite parent is unavailable") from exc
    expected_identities = validated_identities(identities, "retained suite")
    if not isinstance(source_head, str) or re.fullmatch(r"[0-9a-f]{40}", source_head) is None:
        raise ContractError("retained suite source identity is invalid")
    if type(completed_at_unix) is not int or completed_at_unix < 0:
        raise ContractError("retained suite timestamp is invalid")
    groups = {}
    outcomes = []
    for label, paths, expected_names in (
        ("cases", case_outcomes, DETERMINISTIC_PREFLIGHT_CASES),
        ("gates", gate_outcomes, DETERMINISTIC_PREFLIGHT_GATES),
    ):
        if not isinstance(paths, dict) or set(paths) != set(expected_names):
            raise ContractError(f"retained suite {label} are incomplete")
        references = {}
        for name in expected_names:
            reference, outcome = _outcome_reference(suite_parent, paths[name], name)
            if (
                outcome["identities"] != expected_identities
                or outcome["source_head"] != source_head
            ):
                raise ContractError("retained suite check identity mismatch")
            references[name] = reference
            outcomes.append(outcome)
        groups[label] = references
    status = "passed" if all(item["status"] == "passed" for item in outcomes) else "failed"
    body = {
        "schema": RETAINED_SUITE_SCHEMA,
        "status": status,
        "cases": groups["cases"],
        "gates": groups["gates"],
        "identities": expected_identities,
        "source_head": source_head,
        "completed_at_unix": completed_at_unix,
    }
    suite = {
        **body,
        "suite_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
    }
    _write_canonical(destination, suite, "retained suite")
    return suite


def validate_retained_suite(
    path: str | Path,
    *,
    expected_identities: dict[str, str],
    expected_source_head: str,
) -> tuple[dict[str, Any], Path, bytes]:
    """Reopen a suite and require every referenced outcome to authorize spend."""
    source, raw = read_artifact(path, "retained suite")
    try:
        suite = json.loads(raw)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContractError("retained suite is unreadable") from exc
    if raw != canonical_json_bytes(suite) + b"\n":
        raise ContractError("retained suite is not canonical")
    if not isinstance(suite, dict) or set(suite) != _SUITE_FIELDS:
        raise ContractError("retained suite fields mismatch")
    body = {key: value for key, value in suite.items() if key != "suite_sha256"}
    if (
        suite["schema"] != RETAINED_SUITE_SCHEMA
        or suite["status"] != "passed"
        or suite["suite_sha256"]
        != hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        or suite["identities"] != expected_identities
        or suite["source_head"] != expected_source_head
        or type(suite["completed_at_unix"]) is not int
        or suite["completed_at_unix"] < 0
    ):
        raise ContractError("retained suite identity or status mismatch")
    reference_fields = {
        "check_id",
        "status",
        "required",
        "origin",
        "execution_class",
        "applicability",
        "artifact_path",
        "artifact_sha256",
        "artifact_size",
        "outcome_sha256",
    }
    for label, expected_names in (
        ("cases", DETERMINISTIC_PREFLIGHT_CASES),
        ("gates", DETERMINISTIC_PREFLIGHT_GATES),
    ):
        references = suite[label]
        if not isinstance(references, dict) or set(references) != set(expected_names):
            raise ContractError(f"retained suite {label} are incomplete")
        for name in expected_names:
            reference = references[name]
            if not isinstance(reference, dict) or set(reference) != reference_fields:
                raise ContractError("retained suite check reference fields mismatch")
            relative = Path(reference["artifact_path"])
            if relative.is_absolute() or not relative.parts or any(
                part in {"", ".", ".."} for part in relative.parts
            ):
                raise ContractError("retained suite check path is invalid")
            artifact_path = source.parent / relative
            resolved, artifact_raw = read_artifact(
                artifact_path, f"retained check artifact {name}"
            )
            try:
                resolved.relative_to(source.parent)
            except ValueError as exc:
                raise ContractError("retained suite check path escapes") from exc
            if (
                len(artifact_raw) != reference["artifact_size"]
                or hashlib.sha256(artifact_raw).hexdigest()
                != reference["artifact_sha256"]
            ):
                raise ContractError("retained suite check artifact mismatch")
            try:
                outcome_value = json.loads(artifact_raw)
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                raise ContractError("retained suite check artifact is unreadable") from exc
            if artifact_raw != canonical_json_bytes(outcome_value) + b"\n":
                raise ContractError("retained suite check artifact is not canonical")
            outcome = _validate_check_outcome(outcome_value, expected_name=name)
            expected_reference = {
                "check_id": outcome["check_id"],
                "status": outcome["status"],
                "required": outcome["required"],
                "origin": outcome["origin"],
                "execution_class": outcome["execution_class"],
                "applicability": outcome["applicability"],
                "artifact_path": reference["artifact_path"],
                "artifact_sha256": hashlib.sha256(artifact_raw).hexdigest(),
                "artifact_size": len(artifact_raw),
                "outcome_sha256": outcome["outcome_sha256"],
            }
            if (
                reference != expected_reference
                or outcome["identities"] != expected_identities
                or outcome["source_head"] != expected_source_head
                or outcome["status"] != "passed"
                or outcome["required"] is not True
                or outcome["origin"] != "trusted_runner"
                or outcome["execution_class"] != "sealed_runtime"
                or outcome["applicability"] != "applicable_sealed_runtime"
            ):
                raise ContractError("retained suite check is not provider-applicable")
    return suite, source, raw
