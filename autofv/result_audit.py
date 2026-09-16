"""Fail-closed validation for retained smoke and full-run artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from .contracts import ContractError, canonical_json_bytes, load_toolchain_lock
from .evidence import FILE_LOCATIONS, SHA256, authenticate_provider_evidence
from . import (
    provider_config,
    provider_receipts,
    result_summary,
    terminal_verifier,
    verifier as report_verifier,
)


OUTCOMES = {
    "success",
    "unverified",
    "false_spec",
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
    verified = result["verified_counts"]
    if result.get("outcome") == "success":
        invalid = accepted != set(selected) or verified != expected
    else:
        invalid = verified != {"targets": 0, "declarations": 0, "closure": 0}
    if invalid or (smoke and any(value < 1 for value in expected.values())):
        raise AuditError("retained verifier counts mismatch")


def _validate_accounting(
    result: dict[str, Any], evidence: Any, run_root: Path
) -> None:
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
    run = {
        "run_id": result["run_id"],
        "run_root": str(run_root),
        "evidence_dir": str(run_root / "evidence"),
        "lock": lock,
        "fixed_proxy_sha256": result.get("fixed_proxy_sha256"),
        "proxy_policy_sha256": result.get("proxy_policy_sha256"),
        "provider_binding": result.get("provider_binding"),
        "provider_binding_sha256": result.get("provider_binding_sha256"),
        "provider_preflight_sha256": result.get("provider_preflight_sha256"),
        "provider_journal": result.get("provider_journal"),
        "image_digest": result.get("image_digest"),
        "control_bundle_sha256": result.get("control_bundle_sha256"),
        "native_decide_policy_sha256": result.get(
            "native_decide_policy_sha256"
        ),
        "worker_inventory_sha256": result.get("worker_inventory_sha256"),
    }
    state = {
        "config": {"model": result.get("model_id")},
        "receipts": receipts,
        "model_exchanges": exchanges,
        "pending_model_exchanges": {},
        "estimated_accounting": result["accounting"].get("estimated"),
    }
    try:
        provider_evidence = authenticate_provider_evidence(run)
        if provider_evidence is not None:
            if (
                result.get("provider_evidence") != provider_evidence
                or result.get("provider_journal_sha256")
                != provider_evidence["provider_journal_sha256"]
            ):
                raise AuditError("retained provider evidence summary mismatch")
            reduced = provider_receipts.reduce_accounting(
                run, state, binding=provider_evidence["provider_binding"]
            )
        else:
            if any(
                result.get(name) is not None
                for name in (
                    "provider_evidence",
                    "provider_binding",
                    "provider_binding_sha256",
                    "provider_preflight_sha256",
                    "provider_journal",
                    "provider_journal_sha256",
                )
            ):
                raise AuditError("retained provider evidence is incomplete")
            route = lock.get("fixed_proxy")
            run["cost_classification"] = (
                route.get("cost_classification")
                if isinstance(route, dict)
                else None
            )
            reduced = result_summary.reduce_accounting(run, state)
    except (provider_config.ProviderConfigError, result_summary.SummaryError) as exc:
        raise AuditError("retained accounting authentication failed") from exc
    legacy_synthetic = provider_evidence is None
    observed_complete = result.get(
        "accounting_complete", True if legacy_synthetic else None
    )
    observed_unresolved = result.get(
        "unresolved_provider_requests", [] if legacy_synthetic else None
    )
    observed_unknown = result.get(
        "unknown_provider_spend", False if legacy_synthetic else None
    )
    if (
        result.get("cost_classification") != reduced["classification"]
        or result["accounting"] != reduced["accounting"]
        or observed_complete != reduced.get("accounting_complete", True)
        or observed_unresolved != reduced.get("unresolved_requests", [])
        or observed_unknown != reduced.get("unknown_provider_spend", False)
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
    report, _ = _read(
        run_root / FILE_LOCATIONS["verifier"], "verifier report"
    )
    if not isinstance(report, dict):
        raise AuditError("verifier report shape mismatch")
    accepted_commit = result.get("accepted_commit")
    expected = {
        "invocation_id": result.get("verifier_invocation_id"),
        "snapshot_sha256": result.get("snapshot_sha256"),
        "manifest_sha256": result.get("manifest_sha256"),
        "probe_rust_sha256": result.get("probe_rust_sha256"),
        "probe_aeneas_sha256": result.get("probe_aeneas_sha256"),
        "graph_sha256": result.get("graph_sha256"),
        "image_digest": result.get("image_digest"),
        "control_bundle_sha256": result.get("control_bundle_sha256"),
        "native_decide_policy_sha256": result.get(
            "native_decide_policy_sha256"
        ),
        "axiom_scope_sha256": result.get("axiom_scope_sha256"),
        "axiom_inventory_sha256": result.get("axiom_inventory_sha256"),
        "toolchain_lock_sha256": result.get("toolchain_lock_sha256"),
        "accepted_commit": accepted_commit,
        "accepted_tree_sha256": result.get("accepted_tree_sha256"),
        "bundle_sha256": result.get("verifier_bundle_sha256"),
        "reference_sha256": result.get("reference_sha256"),
    }
    run = {
        "run_id": result.get("run_id"),
        "agent_worker_id": result.get("agent_worker_id"),
        "snapshot_sha256": result.get("snapshot_sha256"),
    }
    terminal = report.get("terminal_status")
    common_invalid = (
        not isinstance(accepted_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", accepted_commit) is None
        or any(not isinstance(value, str) or not value for value in expected.values())
        or result.get("verifier_worker_id") != report.get("verifier_worker_id")
        or result.get("verifier_report_sha256") != report.get("report_sha256")
        or result.get("terminal_status") != terminal
        or result.get("native_decide_uses")
        != report.get("native_decide_uses")
        or result.get("accepted_native_decide_uses")
        != report.get("accepted_native_decide_uses")
        or result.get("hidden_native_decide_uses")
        != report.get("hidden_native_decide_uses")
        or result.get("preparation_manifest_sha256")
        != report.get("preparation_manifest_sha256")
        or result.get("preparation_tree_sha256")
        != report.get("preparation_tree_sha256")
        or (
            terminal in {"verified", "unverified", "false_spec"}
            and report.get("target_states_sha256")
            != _sha(canonical_json_bytes(result.get("target_states")))
        )
    )
    try:
        if (
            _sha(canonical_json_bytes(load_toolchain_lock()))
            != result.get("toolchain_lock_sha256")
        ):
            common_invalid = True
        if common_invalid:
            raise report_verifier.VerifierError("retained identity mismatch")
        report_verifier.validate_report(report, run, expected)
    except (ContractError, OSError, report_verifier.VerifierError) as exc:
        raise AuditError("retained verifier binding mismatch") from exc
    checks = report.get("checks")
    if result.get("outcome") == "success":
        terminal_invalid = (
            report.get("verdict") != "PASS"
            or terminal not in {None, "verified"}
            or any(
                checks.get(name) is not True
                for name in ("clean_build", "target_closure", "holes")
            )
        )
    else:
        terminal_invalid = (
            report.get("verdict") != "FAIL"
            or terminal not in {"unverified", "false_spec"}
            or (result.get("outcome") == "false_spec" and terminal != "false_spec")
        )
        if terminal == "false_spec":
            certificate = result.get("counterexample_certificate")
            certificate_sha256 = result.get("counterexample_certificate_sha256")
            terminal_invalid = terminal_invalid or (
                (
                    result.get("outcome") == "false_spec"
                    and result.get("termination_reason")
                    != "counterexample_confirmed"
                )
                or not isinstance(certificate, dict)
                or certificate.get("certificate_sha256") != certificate_sha256
                or report.get("counterexample_certificate_sha256")
                != certificate_sha256
            )
            if not terminal_invalid:
                try:
                    terminal_verifier.validate_counterexample_certificate(
                        certificate,
                        target_states=result["target_states"],
                        accepted_commit=accepted_commit,
                        toolchain_lock_sha256=result.get("toolchain_lock_sha256"),
                        confirmed_sha256=certificate_sha256,
                    )
                except RuntimeError:
                    terminal_invalid = True
    if terminal_invalid:
        raise AuditError("retained verifier binding mismatch")
    if (
        result.get("scored") is not True
        or result.get("evidence_level") != report.get("evidence_level")
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
    _validate_accounting(result, sources.get("model_receipt"), run_root)
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


def _contract_fingerprints(
    target_states: dict[str, Any],
    contract_history: dict[str, Any],
    frozen_targets: list[str],
) -> tuple[set[str], set[str]]:
    frozen = set(frozen_targets)
    current: set[str] = set()
    approved: set[str] = set()
    for node, target in target_states.items():
        if node in frozen or not isinstance(target, dict):
            continue
        fingerprint = target.get("contract_fingerprint")
        if isinstance(fingerprint, str):
            current.add(fingerprint)
            if target.get("status") == "accepted":
                approved.add(fingerprint)
    inventory = set(contract_history.get("invalidated_fingerprints", [])) | current
    for revision in contract_history.get("revision_lineage", []):
        if isinstance(revision, dict):
            inventory.update(
                value
                for value in (
                    revision.get("old_fingerprint"),
                    revision.get("new_fingerprint"),
                )
                if isinstance(value, str)
            )
    return inventory, approved


def validate_semantic_review(
    review: Any,
    *,
    accepted_commit: str,
    target_states: dict[str, Any],
    contract_history: dict[str, Any],
    frozen_targets: list[str],
    required_fingerprints: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Require a canonical review of every current and superseded fingerprint."""
    required = {
        "schema",
        "status",
        "accepted_commit",
        "fingerprints",
        "review_sha256",
    }
    if not isinstance(review, dict) or set(review) != required:
        raise AuditError("contract semantic review fields mismatch")
    body = {key: value for key, value in review.items() if key != "review_sha256"}
    if (
        review.get("schema") != "contract-semantic-review/v1"
        or review.get("status") != "approved"
        or review.get("accepted_commit") != accepted_commit
        or review.get("review_sha256") != _sha(canonical_json_bytes(body))
    ):
        raise AuditError("contract semantic review binding mismatch")
    inventory, expected_approved = _contract_fingerprints(
        target_states, contract_history, frozen_targets
    )
    if any(SHA256.fullmatch(value) is None for value in required_fingerprints):
        raise AuditError("contract semantic review authoritative fingerprint mismatch")
    inventory.update(required_fingerprints)
    expected_approved.update(required_fingerprints)
    covered, approved = _review_inventory(review)
    if covered != inventory or approved != expected_approved:
        raise AuditError("contract semantic review fingerprint mismatch")
    return review


def semantic_review_scope(
    *,
    contracts: dict[str, Any],
    recovered_ids: list[str],
    target_states: dict[str, Any],
    frozen_targets: list[str],
    contract_history: dict[str, Any],
) -> dict[str, Any]:
    """Derive the exact review inventory and reject missing helper metadata."""
    def valid_fingerprint(value: Any) -> bool:
        return isinstance(value, str) and SHA256.fullmatch(value) is not None

    recovered = {
        record.get("model_fingerprint")
        for name, record in contracts.items()
        if name in recovered_ids
        and isinstance(record, dict)
        and isinstance(record.get("model_fingerprint"), str)
    }
    generated_ids = [node for node in target_states if node not in set(frozen_targets)]
    generated = {
        target.get("contract_fingerprint")
        for node, target in target_states.items()
        if node in generated_ids
        and isinstance(target, dict)
        and isinstance(target.get("contract_fingerprint"), str)
    }
    invalidated = contract_history.get("invalidated_fingerprints", [])
    revisions = contract_history.get("revision_lineage", [])
    revised = {
        node: target.get("contract_revision")
        for node, target in target_states.items()
        if isinstance(target, dict)
        and type(target.get("contract_revision")) is int
        and target["contract_revision"] > 0
    }

    def valid_revision_history() -> bool:
        if not isinstance(revisions, list):
            return False
        if any(
            not isinstance(revision, dict)
            or revision.get("node") not in revised
            or type(revision.get("revision")) is not int
            or revision["revision"] <= 0
            or not valid_fingerprint(revision.get("old_fingerprint"))
            or not valid_fingerprint(revision.get("new_fingerprint"))
            for revision in revisions
        ):
            return False
        for node, final_revision in revised.items():
            entries = sorted(
                (revision for revision in revisions if revision["node"] == node),
                key=lambda revision: revision["revision"],
            )
            if [entry["revision"] for entry in entries] != list(
                range(1, final_revision + 1)
            ):
                return False
            if any(
                left["new_fingerprint"] != right["old_fingerprint"]
                for left, right in zip(entries, entries[1:])
            ):
                return False
            if (
                not entries
                or entries[-1]["new_fingerprint"]
                != target_states[node].get("contract_fingerprint")
            ):
                return False
        return True

    required = bool(
        recovered_ids or generated_ids or invalidated or revisions or revised
    )
    valid = (
        all(
            name in contracts
            and isinstance(contracts[name], dict)
            and valid_fingerprint(contracts[name].get("model_fingerprint"))
            for name in recovered_ids
        )
        and all(
            isinstance(target_states.get(node), dict)
            and valid_fingerprint(
                target_states[node].get("contract_fingerprint")
            )
            for node in generated_ids
        )
        and isinstance(invalidated, list)
        and all(valid_fingerprint(value) for value in invalidated)
        and {
            revision["old_fingerprint"]
            for revision in revisions
            if isinstance(revision, dict)
            and "old_fingerprint" in revision
        }
        <= set(invalidated)
        and valid_revision_history()
        and (not required or bool(recovered | generated))
    )
    return {
        "recovered_fingerprints": recovered,
        "generated_fingerprints": generated,
        "required": required,
        "valid": bool(valid),
    }


def validate_full_audit(
    path: str | Path,
    contract_review_path: str | Path,
    validate_l0: Callable[[Any], Any],
) -> dict[str, Any]:
    result = _validate_retained(path, smoke=False, validate_l0=validate_l0)
    review, _ = _read(Path(contract_review_path), "contract semantic review")
    recovered = result.get("sets", {}).get("recovered_internal_specs", {})
    final_fingerprints = result["contract_history"].get("final_fingerprints", [])
    if (
        not isinstance(recovered, dict)
        or not isinstance(recovered.get("ids"), list)
        or not isinstance(final_fingerprints, list)
        or (recovered["ids"] and not final_fingerprints)
    ):
        raise AuditError("retained recovered contract fingerprint evidence missing")
    validate_semantic_review(
        review,
        accepted_commit=result["accepted_commit"],
        target_states=result["target_states"],
        contract_history=result["contract_history"],
        frozen_targets=result["frozen_targets"],
        required_fingerprints=set(final_fingerprints),
    )
    return result
