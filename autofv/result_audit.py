"""Fail-closed validation for retained smoke and full-run artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from .contracts import ContractError, canonical_json_bytes, load_toolchain_lock
from .evidence import FILE_LOCATIONS, SHA256
from . import result_summary


OUTCOMES = {
    "success",
    "budget_exhausted",
    "verification_failed",
    "infrastructure_failed",
    "invalid_target",
    "invalid_config",
    "contract_inconclusive",
}


class AuditError(RuntimeError):
    """Retained evidence is incomplete, noncanonical, or mismatched."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_bytes(value: Any) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _read(path: Path, label: str) -> tuple[Any, bytes]:
    if path.is_symlink() or not path.is_file():
        raise AuditError(f"{label} is missing or unsafe")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"{label} is not valid JSON") from exc
    if raw != _file_bytes(value):
        raise AuditError(f"{label} is not canonical")
    return value, raw


def _terminal_and_groups(result: dict[str, Any], *, smoke: bool) -> None:
    if (
        not isinstance(result.get("attempt_id"), str)
        or not isinstance(result.get("run_id"), str)
        or result.get("outcome") not in OUTCOMES
        or not isinstance(result.get("termination_reason"), str)
        or not result["termination_reason"]
        or result["outcome"] == result["termination_reason"]
    ):
        raise AuditError("retained terminal classification mismatch")
    if smoke and result["outcome"] != "success":
        raise AuditError("smoke attempt was not successful")
    groups = {
        "target_states": dict,
        "verified_counts": dict,
        "block_chains": dict,
        "contract_history": dict,
        "calls": dict,
        "timing_seconds": dict,
        "accounting": dict,
    }
    if any(not isinstance(result.get(name), kind) for name, kind in groups.items()):
        raise AuditError("retained result audit fields mismatch")


def _validate_counts(
    result: dict[str, Any], probe: Any, *, smoke: bool
) -> None:
    if not isinstance(probe, dict) or not isinstance(
        probe.get("selected_nodes"), list
    ):
        raise AuditError("retained selected-node graph evidence mismatch")
    selected = probe["selected_nodes"]
    if (
        any(not isinstance(node, str) for node in selected)
        or len(selected) != len(set(selected))
        or set(result["target_states"]) != set(selected)
        or any(
            result.get(name) != probe.get(name)
            for name in (
                "probe_rust_sha256",
                "probe_aeneas_sha256",
                "graph_sha256",
            )
        )
    ):
        raise AuditError("target state node universe mismatch")
    accepted = {
        node
        for node, target in result["target_states"].items()
        if isinstance(target, dict) and target.get("status") == "accepted"
    }
    frozen = result.get("frozen_targets")
    if (
        not isinstance(frozen, list)
        or len(frozen) != len(set(frozen))
        or not set(frozen).issubset(selected)
    ):
        raise AuditError("retained frozen target set mismatch")
    expected = {
        "targets": len(accepted.intersection(frozen)),
        "declarations": len(accepted),
        "closure": len(accepted.intersection(selected)),
    }
    # The Phase 1 verifier is all-or-nothing: the PASS report accepted below
    # cannot authorize a result that marks any selected declaration unaccepted.
    if accepted != set(selected) or result["verified_counts"] != expected or (
        smoke and any(value < 1 for value in expected.values())
    ):
        raise AuditError("retained verifier counts mismatch")


def _validate_accounting(result: dict[str, Any], evidence: Any) -> None:
    if not isinstance(evidence, list) or not evidence:
        raise AuditError("retained accounting provenance mismatch")
    exchanges = {}
    receipts = []
    for exchange in evidence:
        request = exchange.get("request") if isinstance(exchange, dict) else None
        receipt = exchange.get("receipt") if isinstance(exchange, dict) else None
        request_id = request.get("request_id") if isinstance(request, dict) else None
        if not isinstance(request_id, str) or request_id in exchanges:
            raise AuditError("retained model exchange evidence mismatch")
        exchanges[request_id] = exchange
        receipts.append(receipt)
    try:
        lock = load_toolchain_lock()
    except (ContractError, OSError) as exc:
        raise AuditError("retained accounting lock is invalid") from exc
    if result.get("toolchain_lock_sha256") != _sha(canonical_json_bytes(lock)):
        raise AuditError("retained accounting lock mismatch")
    try:
        reduced = result_summary.reduce_accounting(
            {
                "run_id": result["run_id"],
                "cost_classification": result.get("cost_classification"),
                "lock": lock,
            },
            {
                "config": {"model": result.get("model_id")},
                "receipts": receipts,
                "model_exchanges": exchanges,
                "pending_model_exchanges": {},
                "estimated_accounting": result["accounting"].get("estimated"),
            },
        )
    except result_summary.SummaryError as exc:
        raise AuditError("retained accounting authentication failed") from exc
    if (
        result["accounting"] != reduced["accounting"]
        or result.get("tokens") != reduced["tokens"]
        or result.get("cost_usd") != f"{reduced['cost']:.6f}"
        or result.get("proxy_requests") != reduced["requests"]
    ):
        raise AuditError("retained accounting totals mismatch")


def _validate_l0_links(
    result: dict[str, Any],
    run_root: Path,
    validate_l0: Callable[[Any], Any],
) -> dict[str, Any]:
    link = result.get("l0_receipt")
    if not isinstance(link, dict) or link.get("path") != "evidence/l0.json":
        raise AuditError("retained L0 link mismatch")
    receipt, raw = _read(run_root / "evidence" / "l0.json", "L0 receipt")
    validate_l0(receipt)
    expected_link = {
        "path": "evidence/l0.json",
        "sha256": _sha(raw),
        "size": len(raw),
        "type": "application/json",
    }
    if (
        link != expected_link
        or result.get("l0_receipt_sha256") != receipt.get("receipt_sha256")
        or receipt.get("attempt_id") != result["attempt_id"]
        or receipt.get("run_id") != result["run_id"]
        or receipt.get("complete") is not True
    ):
        raise AuditError("retained L0 identity mismatch")
    sources = {}
    for item in receipt["items"]:
        value, item_raw = _read(
            run_root / item["location"], f"L0 {item['name']} evidence"
        )
        if (
            item.get("status") != "present"
            or item.get("sha256") != _sha(item_raw)
            or item.get("size") != len(item_raw)
            or value is None
        ):
            raise AuditError(f"retained L0 {item['name']} link mismatch")
        sources[item["name"]] = value
    return sources


def _validate_verifier(result: dict[str, Any], run_root: Path) -> None:
    verifier, _ = _read(
        run_root / FILE_LOCATIONS["verifier"], "verifier report"
    )
    if not isinstance(verifier, dict):
        raise AuditError("verifier report shape mismatch")
    body = {key: value for key, value in verifier.items() if key != "report_sha256"}
    checks = verifier.get("checks")
    accepted_commit = result.get("accepted_commit")
    if (
        verifier.get("schema") != "autofv-verifier-report/v1"
        or verifier.get("run_id") != result["run_id"]
        or verifier.get("verdict") != "PASS"
        or verifier.get("report_sha256") != _sha(canonical_json_bytes(body))
        or result.get("verifier_report_sha256") != verifier.get("report_sha256")
        or not isinstance(accepted_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", accepted_commit) is None
        or verifier.get("accepted_commit") != accepted_commit
        or not isinstance(checks, dict)
        or any(
            checks.get(name) is not True
            for name in ("clean_build", "target_closure", "holes")
        )
    ):
        raise AuditError("retained verifier binding mismatch")
    if (
        result.get("scored") is not True
        or result.get("evidence_level") != verifier.get("evidence_level")
    ):
        raise AuditError("retained evidence classification mismatch")


def _validate_retained(
    path: str | Path,
    *,
    smoke: bool,
    validate_l0: Callable[[Any], Any],
) -> dict[str, Any]:
    result, retained_raw = _read(Path(path), "retained result")
    if not isinstance(result, dict) or result.get("schema") != "autofv-result/v1":
        raise AuditError("retained result schema mismatch")
    _terminal_and_groups(result, smoke=smoke)
    run_root = Path(result.get("run_root", ""))
    if not run_root.is_absolute() or run_root.is_symlink() or not run_root.is_dir():
        raise AuditError("retained run root mismatch")
    sources = _validate_l0_links(result, run_root, validate_l0)
    _validate_counts(result, sources.get("probe"), smoke=smoke)
    _validate_accounting(result, sources.get("model_receipt"))
    run_result, run_raw = _read(run_root / "result.json", "run result")
    if run_result != result or run_raw != retained_raw:
        raise AuditError("retained result does not match run result")
    _validate_verifier(result, run_root)
    claim = result.get("claim")
    expected = "supported" if result["outcome"] == "success" else "withheld"
    if not isinstance(claim, dict) or claim.get("status") != expected:
        raise AuditError("retained claim classification mismatch")
    return result


def validate_smoke_audit(
    path: str | Path, validate_l0: Callable[[Any], Any]
) -> dict[str, Any]:
    return _validate_retained(path, smoke=True, validate_l0=validate_l0)


def _review_inventory(review: dict[str, Any]) -> tuple[set[str], set[str]]:
    covered: set[str] = set()
    approved: set[str] = set()
    entries = review.get("fingerprints")
    if not isinstance(entries, list):
        raise AuditError("contract review fingerprint inventory mismatch")
    for entry in entries:
        if isinstance(entry, str):
            fingerprint, decision = entry, "approved"
        elif isinstance(entry, dict):
            fingerprint = entry.get("fingerprint")
            decision = entry.get("decision", entry.get("status"))
        else:
            raise AuditError("contract review fingerprint entry mismatch")
        if (
            not isinstance(fingerprint, str)
            or SHA256.fullmatch(fingerprint) is None
            or fingerprint in covered
            or decision not in {"approved", "approve", "withheld", "withhold"}
        ):
            raise AuditError("contract review fingerprint decision mismatch")
        covered.add(fingerprint)
        if decision in {"approved", "approve"}:
            approved.add(fingerprint)
    return covered, approved


def validate_full_audit(
    path: str | Path,
    contract_review_path: str | Path,
    validate_l0: Callable[[Any], Any],
) -> dict[str, Any]:
    result = _validate_retained(path, smoke=False, validate_l0=validate_l0)
    review, _ = _read(Path(contract_review_path), "contract semantic review")
    if (
        not isinstance(review, dict)
        or review.get("schema") != "autofv-contract-semantic-review/v1"
        or review.get("status") != "approved"
        or review.get("accepted_commit") != result["accepted_commit"]
    ):
        raise AuditError("contract semantic review binding mismatch")
    frozen = set(result["frozen_targets"])
    final = {
        target["contract_fingerprint"]
        for node, target in result["target_states"].items()
        if node not in frozen
        and isinstance(target, dict)
        and target.get("status") == "accepted"
        and isinstance(target.get("contract_fingerprint"), str)
    }
    history = result["contract_history"]
    inventory = set(history.get("invalidated_fingerprints", []))
    for revision in history.get("revision_lineage", []):
        if isinstance(revision, dict):
            inventory.update(
                value
                for value in (
                    revision.get("old_fingerprint"),
                    revision.get("new_fingerprint"),
                )
                if isinstance(value, str)
            )
    inventory.update(final)
    covered, approved = _review_inventory(review)
    if covered != inventory or approved != final:
        raise AuditError("contract semantic review fingerprint mismatch")
    return result
