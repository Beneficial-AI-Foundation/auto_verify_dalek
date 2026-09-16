"""Canonical result records and append-only attempt persistence."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from . import (
    provider_config,
    provider_receipts,
    result_audit,
    result_summary,
    terminal_verifier,
    worker,
)
from .contracts import canonical_json_bytes
from .evidence import (
    EXCLUSIONS,
    FILE_LOCATIONS,
    ISOLATION_ASSUMPTIONS,
    PERSISTED_SOURCE_ITEMS,
    REQUIRED_L0_ITEMS,
    SHA256,
    authenticate_provider_evidence,
    assess_evidence,
    render_claim,
    render_l0,
    source_values,
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
DEFAULT_ATTEMPT_LEDGER = Path(tempfile.gettempdir()) / "autofv-attempts.jsonl"


class ResultError(RuntimeError):
    """A result, evidence receipt, or attempt ledger failed closed."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_file_bytes(value: Any) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _reduce_accounting(
    run: dict[str, Any],
    state: dict[str, Any],
    *,
    outcome: str,
    private_reconciliation: bool = False,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    incomplete = outcome == "infrastructure_failed"
    provider_evidence = authenticate_provider_evidence(
        run, allow_missing_preflight=incomplete
    )
    if provider_evidence is not None:
        reducer = (
            provider_receipts.reduce_incomplete_accounting
            if incomplete
            else provider_receipts.reduce_accounting
        )
        accounting_binding = provider_evidence["provider_binding"]
        if (
            private_reconciliation
            and incomplete
            and run.get("provider_preflight_sha256") is None
        ):
            pinned = provider_config.provider_binding(run)
            if pinned is not None:
                accounting_binding = pinned
        reduced = reducer(
            run,
            state,
            binding=accounting_binding,
        )
        provider_evidence = authenticate_provider_evidence(
            run,
            allow_missing_preflight=(
                incomplete and run.get("provider_preflight_sha256") is None
            ),
        )
        return reduced, provider_evidence
    normalized = dict(run)
    route = run.get("lock", {}).get("fixed_proxy")
    normalized["cost_classification"] = (
        route.get("cost_classification") if isinstance(route, dict) else None
    )
    return result_summary.reduce_accounting(normalized, state), None


def reconcile_provider_finalization(
    run: dict[str, Any], state: dict[str, Any], *, outcome: str
) -> None:
    """Reconcile durable provider state while private process state still exists."""
    _reduce_accounting(
        run, state, outcome=outcome, private_reconciliation=True
    )


def default_attempt_identity() -> dict[str, str]:
    return {
        "attempt_id": f"attempt-{secrets.token_hex(16)}",
        "attempt_ledger": str(DEFAULT_ATTEMPT_LEDGER),
    }


def new_attempt_identity(target: str | Path | None = None) -> dict[str, str]:
    identity = default_attempt_identity()
    configured = os.environ.get("AUTOFV_ATTEMPT_LEDGER")
    ledger = Path(configured) if configured else DEFAULT_ATTEMPT_LEDGER
    if not ledger.is_absolute():
        raise ResultError("AUTOFV_ATTEMPT_LEDGER must be an absolute path")
    if ledger.is_symlink():
        raise ResultError("AUTOFV_ATTEMPT_LEDGER must not be a symlink")
    if target is not None:
        try:
            source = Path(target).expanduser().resolve(strict=False)
            resolved_ledger = ledger.expanduser().resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ResultError("AUTOFV_ATTEMPT_LEDGER path resolution failed") from exc
        if resolved_ledger == source or resolved_ledger.is_relative_to(source):
            raise ResultError("AUTOFV_ATTEMPT_LEDGER overlaps input repository")
    identity["attempt_ledger"] = str(ledger)
    return identity


def validate_output_root(
    target: str | Path, output_root: str | Path | None
) -> Path:
    """Resolve an attempt parent without allowing writes inside the input."""
    requested_source = Path(target).expanduser()
    requested = (
        Path(output_root).expanduser()
        if output_root is not None
        else Path(tempfile.gettempdir())
    )
    if requested_source.is_symlink() or requested.is_symlink():
        raise ResultError("run paths must not be symlinks")
    try:
        source = requested_source.resolve(strict=False)
        parent = requested.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ResultError("run path resolution failed") from exc
    if parent == source or parent.is_relative_to(source):
        raise ResultError("output root overlaps input repository")
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise ResultError("output root is not a safe directory")
    return parent


def allocate_attempt(
    identity: dict[str, str],
    *,
    target: str | Path,
    run_config: str | Path,
    output_root: str | Path | None = None,
) -> dict[str, Any]:
    parent = validate_output_root(target, output_root)
    parent.mkdir(parents=True, exist_ok=True)
    short_id = identity["attempt_id"].removeprefix("attempt-")[:8]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    repo_name = Path(target).expanduser().resolve(strict=False).name or "repository"
    root = parent / f"{repo_name}-autofv-{timestamp}-{short_id}"
    created = False
    try:
        root.mkdir(mode=0o700)
        created = True
        for name in ("accepted", "evidence", "logs", "export"):
            (root / name).mkdir()
    except OSError as exc:
        if created:
            shutil.rmtree(root, ignore_errors=True)
        raise ResultError("attempt root allocation failed") from exc
    return {
        **identity,
        "run_id": identity["attempt_id"],
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
        "execution_tier": None,
        "cost_classification": None,
        "requested_target": str(target),
        "requested_run_config": str(run_config),
        "events": ["attempt_started"],
    }


def snapshot_input(run: dict[str, Any], target: str | Path) -> None:
    """Copy a validated input repository into the run-owned accepted tree."""
    source = Path(target).resolve(strict=True)
    if not source.is_dir() or source.is_symlink():
        raise ResultError("input repository is not a safe directory")
    for path in source.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ResultError("input repository contains an unsafe file kind")

    root = Path(run["run_root"]).resolve(strict=True)
    accepted = root / "accepted"
    stage = root / ".accepted.tmp"
    try:
        shutil.copytree(source, stage)
        accepted.rmdir()
        os.replace(stage, accepted)
    except OSError as exc:
        shutil.rmtree(stage, ignore_errors=True)
        raise ResultError("accepted repository snapshot failed") from exc


def bind_prepared_run(
    allocation: dict[str, Any], prepared: dict[str, Any]
) -> dict[str, Any]:
    """Bind worker preparation metadata to the durable attempt root."""
    root = Path(allocation["run_root"])
    previous_root = Path(prepared["run_root"])
    previous_evidence = previous_root / "evidence"
    evidence_transferred = False
    if previous_root != root and previous_evidence.is_dir():
        try:
            shutil.copytree(
                previous_evidence, root / "evidence", dirs_exist_ok=True
            )
            evidence_transferred = True
        except OSError as exc:
            raise ResultError("worker evidence transfer failed") from exc
    if (
        previous_root != root
        and prepared.get("execution_tier") == "sealed_runsc"
        and evidence_transferred
    ):
        try:
            shutil.rmtree(previous_root)
        except OSError as exc:
            raise ResultError("worker staging cleanup failed") from exc
    prepared.update(
        {
            "attempt_id": allocation["attempt_id"],
            "attempt_ledger": allocation["attempt_ledger"],
            "run_root": str(root),
            "evidence_dir": str(root / "evidence"),
            "requested_target": allocation["requested_target"],
            "requested_run_config": allocation["requested_run_config"],
        }
    )
    return prepared


def materialize_accepted(run: dict[str, Any]) -> None:
    """Replace the input snapshot with the exact exported accepted Git commit."""
    root = Path(run["run_root"]).resolve(strict=True)
    bundle = root / "export" / "accepted" / "repository.bundle"
    accepted = root / "accepted"
    stage = root / ".accepted-repository.tmp"
    backup = root / ".accepted-input.tmp"
    expected = (run.get("accepted") or {}).get("accepted_commit")
    if not bundle.is_file() or bundle.is_symlink() or not isinstance(expected, str):
        raise ResultError("accepted repository export is incomplete")
    try:
        stage.mkdir()
        for command in (
            ("git", "-C", str(stage), "init", "--quiet"),
            (
                "git",
                "-C",
                str(stage),
                "fetch",
                "--quiet",
                "--no-tags",
                str(bundle),
                "HEAD",
            ),
            (
                "git",
                "-C",
                str(stage),
                "checkout",
                "--quiet",
                "--detach",
                "FETCH_HEAD",
            ),
        ):
            subprocess.run(command, check=True, capture_output=True)
        head = subprocess.run(
            ("git", "-C", str(stage), "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if head != expected:
            raise ResultError("accepted repository commit mismatch")
        os.replace(accepted, backup)
        try:
            os.replace(stage, accepted)
        except OSError:
            os.replace(backup, accepted)
            raise
        shutil.rmtree(backup)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ResultError("accepted repository materialization failed") from exc
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def render_attempt(
    run: dict[str, Any],
    state: dict[str, Any],
    *,
    outcome: str,
    reason: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if outcome not in OUTCOMES or not isinstance(reason, str) or not reason:
        raise ResultError("attempt outcome or termination reason is invalid")
    report = state.get("verifier_report", {})
    terminal_false_spec = (
        isinstance(report, dict) and report.get("terminal_status") == "false_spec"
    )
    certificate = (
        state.get("counterexample_certificate") if terminal_false_spec else None
    )
    if outcome == "false_spec":
        if reason != "counterexample_confirmed" or not terminal_false_spec:
            raise ResultError("false_spec termination reason is invalid")
    if terminal_false_spec:
        try:
            if not isinstance(report, dict):
                raise ResultError("false_spec verifier report is invalid")
            report_body = {
                key: value for key, value in report.items() if key != "report_sha256"
            }
            target_states = state.get("target_states", {})
            accepted = state.get("accepted") or run.get("accepted") or {}
            if (
                report.get("schema") != "autofv-verifier-report/v1"
                or report.get("report_sha256") != _sha(canonical_json_bytes(report_body))
                or report.get("run_id") != run.get("run_id")
                or report.get("accepted_commit") != accepted.get("accepted_commit")
                or report.get("verdict") != "FAIL"
                or report.get("evidence_level") != "L0"
                or report.get("terminal_status") != "false_spec"
                or report.get("target_states") != target_states
                or report.get("target_states_sha256")
                != _sha(canonical_json_bytes(target_states))
            ):
                raise ResultError("false_spec verifier report is invalid")
            terminal_verifier.validate_counterexample_certificate(
                certificate,
                target_states=target_states,
                accepted_commit=accepted["accepted_commit"],
                toolchain_lock_sha256=_sha(canonical_json_bytes(run["lock"])),
                confirmed_sha256=report.get("counterexample_certificate_sha256"),
            )
        except (KeyError, RuntimeError) as exc:
            raise ResultError("false_spec certificate is invalid") from exc
    if not isinstance(run.get("attempt_id"), str) or not run["attempt_id"]:
        run["attempt_id"] = run.get("run_id") or f"attempt-{secrets.token_hex(16)}"
    run.setdefault("attempt_ledger", str(Path(run["run_root"]) / "attempts.jsonl"))
    if "result_emitted" not in run.setdefault("events", []):
        run["events"].append("result_emitted")

    sources = source_values(run, state)
    receipt = render_l0(run, state)
    assessment = assess_evidence(receipt, report)
    graph = state.get("graph") if isinstance(state.get("graph"), dict) else {}
    accepted = state.get("accepted") or run.get("accepted") or {}
    contracts = state.get("contracts", {}).get("frozen", {})
    frozen_targets = graph.get("frozen_targets", [])
    selected_nodes = graph.get("selected_nodes", [])
    accepted_nodes = state.get("accepted_nodes", [])
    internal = set(accepted_nodes) - set(frozen_targets)
    native_uses = (
        report.get("native_decide_uses", state.get("native_decide_uses", []))
        if isinstance(report, dict)
        else state.get("native_decide_uses", [])
    )
    accepted_native_uses = (
        report.get("accepted_native_decide_uses", [])
        if isinstance(report, dict)
        else []
    )
    hidden_native_uses = (
        report.get("hidden_native_decide_uses", [])
        if isinstance(report, dict)
        else []
    )
    assumptions = (
        report.get(
            "compiler_assumptions", state.get("compiler_assumptions", [])
        )
        if isinstance(report, dict)
        else state.get("compiler_assumptions", [])
    )
    try:
        reduced_accounting, provider_evidence = _reduce_accounting(
            run, state, outcome=outcome
        )
        cost = reduced_accounting["cost"]
        tokens = reduced_accounting["tokens"]
        model_summary = result_summary.model_summary(state)
    except (provider_config.ProviderConfigError, result_summary.SummaryError) as exc:
        raise ResultError(str(exc)) from exc
    input_evidence = sources["input"] if isinstance(sources["input"], dict) else {}
    image_evidence = sources["image"] if isinstance(sources["image"], dict) else {}
    runtime_evidence = (
        sources["runtime"] if isinstance(sources["runtime"], dict) else {}
    )
    network_evidence = (
        sources["network"] if isinstance(sources["network"], dict) else {}
    )
    network_policy = (
        network_evidence.get("policy")
        if isinstance(network_evidence.get("policy"), dict)
        else {}
    )
    probe_evidence = sources["probe"] if isinstance(sources["probe"], dict) else {}
    tool_evidence = sources["tool"] if isinstance(sources["tool"], dict) else {}
    verifier_evidence = report if isinstance(report, dict) else {}
    verifier_item = next(
        (item for item in receipt["items"] if item["name"] == "verifier"), {}
    )
    verifier_bound = verifier_item.get("status") == "present" and outcome == "success"
    try:
        generic = result_summary.render_generic_summary(
            run,
            state,
            report if isinstance(report, dict) else {},
            verifier_bound=verifier_bound,
            accounting=reduced_accounting["accounting"],
        )
    except result_summary.SummaryError as exc:
        raise ResultError(str(exc)) from exc
    review = state.get("contract_semantic_review")
    supplied_specs = set(
        graph.get("supplied_specs", {}).values()
        if isinstance(graph.get("supplied_specs"), dict)
        else []
    )
    recovered_ids = sorted(set(contracts) - supplied_specs)
    history = generic["contract_history"]
    review_scope = result_audit.semantic_review_scope(
        contracts=contracts,
        recovered_ids=recovered_ids,
        target_states=generic["target_states"],
        frozen_targets=frozen_targets,
        contract_history=history,
    )
    recovered_fingerprints = review_scope["recovered_fingerprints"]
    history["final_fingerprints"] = sorted(recovered_fingerprints)
    review_required = review_scope["required"]
    metadata_valid = review_scope["valid"]
    review_valid = not review_required and metadata_valid
    if review_required and metadata_valid:
        try:
            result_audit.validate_semantic_review(
                review,
                accepted_commit=accepted.get("accepted_commit"),
                target_states=generic["target_states"],
                contract_history=history,
                frozen_targets=frozen_targets,
                required_fingerprints=recovered_fingerprints,
            )
            review_valid = True
        except result_audit.AuditError:
            review_valid = False
    if reduced_accounting.get("accounting_complete") is False:
        assessment = {
            "level": None,
            "scored": False,
            "missing": ["provider_accounting_unresolved"],
        }
    elif not review_valid and assessment.get("level") == "L4":
        assessment = {**assessment, "level": "L3"}
    claim = render_claim(assessment, run, state, outcome=outcome)
    target_ids = list(frozen_targets) if isinstance(frozen_targets, list) else []
    supplied_ids = list(target_ids)
    l0_raw = _json_file_bytes(receipt)
    result = {
        "schema": "autofv-result/v1",
        "attempt_id": run["attempt_id"],
        "run_id": run["run_id"],
        "run_root": run["run_root"],
        "attempt_ledger": run["attempt_ledger"],
        "execution_tier": run.get("execution_tier"),
        "cost_classification": reduced_accounting["classification"],
        "provider_evidence": copy.deepcopy(provider_evidence),
        "provider_binding": (
            copy.deepcopy(provider_evidence["provider_binding"])
            if provider_evidence is not None
            else None
        ),
        "provider_binding_sha256": (
            provider_evidence["provider_binding_sha256"]
            if provider_evidence is not None
            else None
        ),
        "provider_preflight_sha256": (
            provider_evidence["provider_preflight_sha256"]
            if provider_evidence is not None
            else None
        ),
        "provider_journal": (
            copy.deepcopy(provider_evidence["provider_journal"])
            if provider_evidence is not None
            else None
        ),
        "provider_journal_sha256": (
            provider_evidence["provider_journal_sha256"]
            if provider_evidence is not None
            else None
        ),
        "accounting_complete": reduced_accounting.get("accounting_complete", True),
        "unresolved_provider_requests": copy.deepcopy(
            reduced_accounting.get("unresolved_requests", [])
        ),
        "unknown_provider_spend": reduced_accounting.get(
            "unknown_provider_spend", False
        ),
        "outcome": outcome,
        "termination_reason": reason,
        "termination_detail": state.get("termination_detail"),
        "counterexample_certificate": copy.deepcopy(certificate),
        "counterexample_certificate_sha256": (
            certificate.get("certificate_sha256")
            if isinstance(certificate, dict)
            else None
        ),
        "terminal_status": (
            report.get("terminal_status") if isinstance(report, dict) else None
        ),
        "preparation_manifest_sha256": (
            report.get("preparation_manifest_sha256")
            if isinstance(report, dict)
            else None
        ),
        "preparation_tree_sha256": (
            report.get("preparation_tree_sha256")
            if isinstance(report, dict)
            else None
        ),
        "reference_sha256": (
            report.get("reference_sha256") if isinstance(report, dict) else None
        ),
        "axiom_inventory_sha256": (
            report.get("axiom_inventory_sha256")
            if isinstance(report, dict)
            else None
        ),
        "axiom_scope_sha256": (
            report.get("axiom_scope_sha256")
            if isinstance(report, dict)
            else None
        ),
        "verifier_invocation_id": (
            report.get("invocation_id") if isinstance(report, dict) else None
        ),
        "agent_worker_id": (
            report.get("agent_worker_id") if isinstance(report, dict) else None
        ),
        "verifier_worker_id": (
            report.get("verifier_worker_id") if isinstance(report, dict) else None
        ),
        "verifier_bundle_sha256": (
            report.get("bundle_sha256") if isinstance(report, dict) else None
        ),
        "contract_semantic_review_sha256": (
            review.get("review_sha256") if review_valid and isinstance(review, dict) else None
        ),
        "contract_semantic_review_status": (
            "approved"
            if review_required and review_valid
            else "not_required"
            if not review_required
            else "withheld"
        ),
        **generic,
        "frozen_targets": frozen_targets,
        "sets": {
            "T": {"ids": target_ids, "size": len(target_ids)},
            "S": {"ids": supplied_ids, "size": len(supplied_ids)},
            "W": {"ids": [], "size": 0},
            "recovered_internal_specs": {
                "ids": recovered_ids if review_valid else [],
                "size": len(recovered_ids) if review_valid else 0,
            },
        },
        "targets_total": len(frozen_targets),
        "targets_specified_baseline": len(frozen_targets),
        "targets_verified_baseline": 0,
        "targets_verified_final": (
            len(frozen_targets) if outcome == "success" else 0
        ),
        "internal_functions_discovered": max(
            0, len(selected_nodes) - len(frozen_targets)
        ),
        "internal_specs_accepted": (
            len(contracts) if isinstance(contracts, dict) else 0
        ),
        "internal_proofs_accepted": len(internal),
        "model_id": state.get("config", {}).get("model"),
        "model_attempts": model_summary["attempts"],
        "model_retries": model_summary["retries"],
        "prompt_sha256": model_summary["prompt_sha256"],
        "proxy_requests": reduced_accounting["requests"],
        "tokens": tokens,
        "cost_usd": f"{cost:.6f}",
        "wall_seconds": f"{Decimal(state.get('wall_seconds_used', 0)):.6f}",
        "finalization_reserve_seconds": (
            f"{Decimal(state.get('finalization_reserve_seconds', 0)):.6f}"
        ),
        "receipt_rejections": state.get("receipt_rejections", []),
        "native_decide_policy": (
            run.get("native_decide_policy") if image_evidence else None
        ),
        "native_decide_policy_sha256": image_evidence.get(
            "native_decide_policy_sha256"
        ),
        "native_decide_uses": native_uses,
        "accepted_native_decide_uses": accepted_native_uses,
        "hidden_native_decide_uses": hidden_native_uses,
        "compiler_assumptions": assumptions,
        "snapshot_sha256": input_evidence.get("snapshot_sha256"),
        "manifest_sha256": input_evidence.get("manifest_sha256"),
        "probe_rust_sha256": probe_evidence.get("probe_rust_sha256"),
        "probe_aeneas_sha256": probe_evidence.get("probe_aeneas_sha256"),
        "graph_sha256": probe_evidence.get("graph_sha256"),
        "image_digest": image_evidence.get("image_digest"),
        "control_bundle_sha256": image_evidence.get("control_bundle_sha256"),
        "toolchain_lock_sha256": (
            _sha(canonical_json_bytes(run["lock"])) if tool_evidence else None
        ),
        "fixed_proxy_sha256": network_evidence.get("fixed_proxy_sha256"),
        "proxy_policy_sha256": network_evidence.get("proxy_policy_sha256"),
        "upstream_policy_sha256": network_policy.get("upstream_policy_sha256"),
        "egress_policy_sha256": network_policy.get("policy_sha256"),
        "worker_inventory_sha256": runtime_evidence.get("inventory_sha256"),
        "accepted_commit": (
            verifier_evidence.get("accepted_commit")
            if verifier_bound
            else accepted.get("accepted_commit")
        ),
        "accepted_tree_sha256": (
            verifier_evidence.get("accepted_tree_sha256")
            if verifier_bound
            else accepted.get("accepted_tree_sha256")
        ),
        "sorry_counts": {
            "before": verifier_evidence.get("sorry_count_before"),
            "after": verifier_evidence.get("sorry_count_after"),
        },
        "check_outcomes": verifier_evidence.get("checks", {}),
        "lanes": state.get("lanes", run.get("lanes", [])),
        "lane_intervals": state.get(
            "lane_intervals", run.get("lane_intervals", {})
        ),
        "candidate_receipts": state.get(
            "candidate_receipts", run.get("candidate_receipts", [])
        ),
        "processed_candidate_sha256": state.get(
            "processed_candidate_sha256",
            run.get("processed_candidate_sha256", []),
        ),
        "accepted_sequence": state.get(
            "accepted_sequence", run.get("accepted_sequence", [])
        ),
        "verifier_report_sha256": (
            report.get("report_sha256") if isinstance(report, dict) else None
        ),
        "export_manifest_sha256": run.get("export_receipt", {}).get(
            "manifest_sha256"
        ),
        "disposal_sha256": run.get("disposal_receipt", {}).get(
            "disposal_sha256"
        ),
        "evidence_level": assessment["level"],
        "scored": assessment["scored"],
        "missing_evidence": assessment["missing"],
        "l0_receipt_sha256": receipt["receipt_sha256"],
        "l0_receipt": {
            "path": "evidence/l0.json",
            "sha256": _sha(l0_raw),
            "size": len(l0_raw),
            "type": "application/json",
        },
        "claim": claim,
        "isolation_assumptions": list(ISOLATION_ASSUMPTIONS),
        "exclusions": list(EXCLUSIONS),
        "events": list(run["events"]),
    }
    return result, receipt


def validate_l0(receipt: Any) -> dict[str, Any]:
    required = {
        "schema",
        "attempt_id",
        "run_id",
        "items",
        "complete",
        "missing",
        "receipt_sha256",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise ResultError("L0 receipt fields mismatch")
    if receipt.get("schema") != "autofv-evidence-l0/v1":
        raise ResultError("L0 receipt schema mismatch")
    items = receipt.get("items")
    if not isinstance(items, list) or [
        item.get("name") for item in items if isinstance(item, dict)
    ] != list(REQUIRED_L0_ITEMS):
        raise ResultError("L0 receipt item set mismatch")
    item_fields = {
        "name",
        "run_id",
        "event",
        "status",
        "sha256",
        "size",
        "type",
        "location",
    }
    if any(not isinstance(item, dict) or set(item) != item_fields for item in items):
        raise ResultError("L0 receipt item fields mismatch")
    if not isinstance(receipt.get("attempt_id"), str) or not receipt["attempt_id"]:
        raise ResultError("L0 receipt attempt identity mismatch")
    if not isinstance(receipt.get("run_id"), str) or not receipt["run_id"]:
        raise ResultError("L0 receipt run identity mismatch")
    if any(item["run_id"] != receipt["run_id"] for item in items):
        raise ResultError("L0 receipt run identity mismatch")
    for item in items:
        if item["location"] != FILE_LOCATIONS[item["name"]]:
            raise ResultError(f"L0 receipt {item['name']} location mismatch")
        if item["status"] not in {"present", "missing"}:
            raise ResultError("L0 receipt item status mismatch")
        if item["status"] == "present" and not (
            isinstance(item["event"], str)
            and isinstance(item["sha256"], str)
            and SHA256.fullmatch(item["sha256"])
            and type(item["size"]) is int
            and item["size"] >= 0
            and item["type"] == "application/json"
        ):
            raise ResultError(f"L0 receipt {item['name']} evidence mismatch")
    missing = [item["name"] for item in items if item["status"] != "present"]
    if receipt.get("missing") != missing or receipt.get("complete") != (not missing):
        raise ResultError("L0 receipt completeness mismatch")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != _sha(canonical_json_bytes(body)):
        raise ResultError("L0 receipt hash mismatch")
    return receipt


def validate_smoke_audit(path: str | Path) -> dict[str, Any]:
    """Fail closed unless a retained smoke result proves verified progress."""
    try:
        return result_audit.validate_smoke_audit(path, validate_l0)
    except result_audit.AuditError as exc:
        raise ResultError(str(exc)) from exc


def validate_full_audit(
    path: str | Path, contract_review_path: str | Path
) -> dict[str, Any]:
    """Validate retained full-run evidence and its exact semantic review."""
    try:
        return result_audit.validate_full_audit(
            path, contract_review_path, validate_l0
        )
    except result_audit.AuditError as exc:
        raise ResultError(str(exc)) from exc


def _atomic_write_once(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
            raise ResultError(f"attempt artifact replacement refused: {path.name}")
        return
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
                raise ResultError(
                    f"attempt artifact replacement refused: {path.name}"
                )
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def persist_l0_sources(run: dict[str, Any], state: dict[str, Any]) -> None:
    """Persist the small reviewable values indexed by the L0 receipt."""
    values = source_values(run, state)
    root = Path(run["run_root"])
    for name in PERSISTED_SOURCE_ITEMS:
        value = values[name]
        if value is not None:
            _atomic_write_once(root / FILE_LOCATIONS[name], _json_file_bytes(value))


def _append_attempt(
    run: dict[str, Any],
    result: dict[str, Any],
    receipt: dict[str, Any],
    final_scan: dict[str, Any],
) -> Path:
    ledger = Path(run["attempt_ledger"])
    ledger.parent.mkdir(parents=True, exist_ok=True)
    result_raw = _json_file_bytes(result)
    l0_raw = _json_file_bytes(receipt)
    body = {
        "schema": "autofv-attempt/v1",
        "attempt_id": run["attempt_id"],
        "run_id": run["run_id"],
        "outcome": result["outcome"],
        "termination_reason": result["termination_reason"],
        "evidence_level": result["evidence_level"],
        "scored": result["scored"],
        "result": {
            "path": str(Path(run["run_root"]) / "result.json"),
            "sha256": _sha(result_raw),
            "size": len(result_raw),
            "type": "application/json",
        },
        "l0": {
            "path": str(Path(run["run_root"]) / "evidence" / "l0.json"),
            "sha256": _sha(l0_raw),
            "size": len(l0_raw),
            "type": "application/json",
        },
        "final_scan": {
            "path": str(
                Path(run["run_root"]) / "evidence" / "final-result-scan.json"
            ),
            "sha256": _sha(_json_file_bytes(final_scan)),
            "size": len(_json_file_bytes(final_scan)),
            "type": "application/json",
        },
    }
    record = {**body, "record_sha256": _sha(canonical_json_bytes(body))}
    raw = _json_file_bytes(record)
    with ledger.open("a+b") as output:
        fcntl.flock(output.fileno(), fcntl.LOCK_EX)
        output.seek(0)
        for line in output:
            try:
                existing = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ResultError("attempt ledger is corrupt") from exc
            if existing.get("attempt_id") == run["attempt_id"]:
                if existing != record:
                    raise ResultError("attempt ledger replacement refused")
                return ledger
        output.seek(0, os.SEEK_END)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return ledger


def persist_attempt(
    run: dict[str, Any], result: dict[str, Any], receipt: dict[str, Any]
) -> Path:
    validate_l0(receipt)
    expected_l0 = _json_file_bytes(receipt)
    if (
        result.get("attempt_id") != run.get("attempt_id")
        or receipt.get("attempt_id") != run.get("attempt_id")
        or result.get("run_id") != run.get("run_id")
        or receipt.get("run_id") != run.get("run_id")
        or result.get("l0_receipt_sha256") != receipt.get("receipt_sha256")
        or result.get("l0_receipt")
        != {
            "path": "evidence/l0.json",
            "sha256": _sha(expected_l0),
            "size": len(expected_l0),
            "type": "application/json",
        }
    ):
        raise ResultError("result and L0 receipt identity mismatch")
    root = Path(run["run_root"])
    result_raw = _json_file_bytes(result)
    final_scan = worker.scan_artifacts(
        {"result.json": result_raw, "evidence/l0.json": expected_l0},
        run.get("artifact_scan_markers", ()),
    )
    _atomic_write_once(root / "evidence" / "l0.json", expected_l0)
    _atomic_write_once(root / "result.json", result_raw)
    _atomic_write_once(
        root / "evidence" / "final-result-scan.json",
        _json_file_bytes(final_scan),
    )
    return _append_attempt(run, result, receipt, final_scan)


def persist_verifier_report(run: dict[str, Any], report: Any) -> Path | None:
    if not isinstance(report, dict):
        return None
    path = Path(run["run_root"]) / "evidence" / "verifier.json"
    _atomic_write_once(path, _json_file_bytes(report))
    return path


def invalidate_verifier_evidence(
    run: dict[str, Any], state: dict[str, Any]
) -> None:
    """Archive evidence tied to a replaced agent worker before reverification."""
    report = state.get("verifier_report")
    if not isinstance(report, dict):
        return
    digest = report.get("report_sha256")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        digest = _sha(canonical_json_bytes(report))
    root = Path(run["run_root"])
    history = root / "evidence" / "history" / digest
    for relative in (
        "evidence/verifier.json",
        "evidence/l0/build.json",
        "evidence/l0/replay.json",
    ):
        source = root / relative
        if not source.exists():
            continue
        if source.is_symlink() or not source.is_file():
            raise ResultError("stale verifier evidence is not a regular file")
        _atomic_write_once(history / source.name, source.read_bytes())
        source.unlink()
    state.pop("verifier_report", None)
    state.pop("verifier_invocation_id", None)
    state.pop("verifier_axiom_inventory_sha256", None)
    run["events"] = [
        event
        for event in run.get("events", [])
        if event
        not in {
            "clean_verifier:PASS",
            "clean_verifier:INCOMPLETE",
            "clean_verifier:FALSE_SPEC",
        }
    ]
    run["events"].append("verifier_invalidated:worker_recreated")
