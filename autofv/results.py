"""Canonical result records and append-only attempt persistence."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from . import worker
from .contracts import canonical_json_bytes
from .evidence import (
    EXCLUSIONS,
    FILE_LOCATIONS,
    ISOLATION_ASSUMPTIONS,
    PERSISTED_SOURCE_ITEMS,
    REQUIRED_L0_ITEMS,
    SHA256,
    assess_evidence,
    render_claim,
    render_l0,
    source_values,
)


OUTCOMES = {
    "success",
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


def default_attempt_identity() -> dict[str, str]:
    return {
        "attempt_id": f"attempt-{secrets.token_hex(16)}",
        "attempt_ledger": str(DEFAULT_ATTEMPT_LEDGER),
    }


def new_attempt_identity() -> dict[str, str]:
    identity = default_attempt_identity()
    configured = os.environ.get("AUTOFV_ATTEMPT_LEDGER")
    ledger = Path(configured) if configured else DEFAULT_ATTEMPT_LEDGER
    if not ledger.is_absolute():
        raise ResultError("AUTOFV_ATTEMPT_LEDGER must be an absolute path")
    identity["attempt_ledger"] = str(ledger)
    return identity


def allocate_attempt(
    identity: dict[str, str],
    *,
    target: str | Path,
    run_config: str | Path,
) -> dict[str, Any]:
    root = Path(tempfile.mkdtemp(prefix=f"{identity['attempt_id']}-"))
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


def _decimal_cost(receipts: Any) -> Decimal:
    total = Decimal("0.000000")
    if not isinstance(receipts, list):
        return total
    try:
        for receipt in receipts:
            total += Decimal(receipt["cost"]["amount"])
    except (KeyError, TypeError, InvalidOperation) as exc:
        raise ResultError("accepted model receipt cost is invalid") from exc
    return total


def _tokens(receipts: Any) -> dict[str, int]:
    totals = {"input": 0, "output": 0, "total": 0}
    if not isinstance(receipts, list):
        return totals
    fields = (
        ("input", "input_tokens"),
        ("output", "output_tokens"),
        ("total", "total_tokens"),
    )
    for receipt in receipts:
        usage = receipt.get("usage", {}) if isinstance(receipt, dict) else {}
        for target, source in fields:
            value = usage.get(source)
            if type(value) is int and value >= 0:
                totals[target] += value
    return totals


def _model_summary(state: dict[str, Any]) -> dict[str, Any]:
    exchanges = state.get("model_exchanges")
    accepted = list(exchanges.values()) if isinstance(exchanges, dict) else []
    rejections = state.get("receipt_rejections")
    rejected = rejections if isinstance(rejections, list) else []
    request_ids = [
        item.get("request", {}).get("request_id")
        for item in accepted
        if isinstance(item, dict)
    ] + [
        item.get("request_id") for item in rejected if isinstance(item, dict)
    ]
    request_ids = [item for item in request_ids if isinstance(item, str)]
    prompts = [
        item.get("request", {}).get("prompt_sha256")
        for item in accepted
        if isinstance(item, dict)
    ]
    return {
        "attempts": len(request_ids),
        "retries": len(request_ids) - len(set(request_ids)),
        "prompt_sha256": [item for item in prompts if isinstance(item, str)],
    }


def render_attempt(
    run: dict[str, Any],
    state: dict[str, Any],
    *,
    outcome: str,
    reason: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if outcome not in OUTCOMES or not isinstance(reason, str) or not reason:
        raise ResultError("attempt outcome or termination reason is invalid")
    if not isinstance(run.get("attempt_id"), str) or not run["attempt_id"]:
        run["attempt_id"] = run.get("run_id") or f"attempt-{secrets.token_hex(16)}"
    run.setdefault("attempt_ledger", str(Path(run["run_root"]) / "attempts.jsonl"))
    if "result_emitted" not in run.setdefault("events", []):
        run["events"].append("result_emitted")

    sources = source_values(run, state)
    receipt = render_l0(run, state)
    report = state.get("verifier_report", {})
    assessment = assess_evidence(receipt, report)
    claim = render_claim(assessment, run, state, outcome=outcome)
    graph = state.get("graph") if isinstance(state.get("graph"), dict) else {}
    accepted = state.get("accepted") or run.get("accepted") or {}
    contracts = state.get("contracts", {}).get("frozen", {})
    frozen_targets = graph.get("frozen_targets", [])
    selected_nodes = graph.get("selected_nodes", [])
    accepted_nodes = state.get("accepted_nodes", [])
    internal = set(accepted_nodes) - set(frozen_targets)
    receipts = state.get("receipts", [])
    native_uses = (
        report.get("native_decide_uses", state.get("native_decide_uses", []))
        if isinstance(report, dict)
        else state.get("native_decide_uses", [])
    )
    assumptions = (
        report.get(
            "compiler_assumptions", state.get("compiler_assumptions", [])
        )
        if isinstance(report, dict)
        else state.get("compiler_assumptions", [])
    )
    cost = _decimal_cost(receipts)
    tokens = _tokens(receipts)
    model_summary = _model_summary(state)
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
    verifier_bound = verifier_item.get("status") == "present"
    target_ids = list(frozen_targets) if isinstance(frozen_targets, list) else []
    supplied_ids = list(target_ids)
    recovered_ids = sorted(contracts) if isinstance(contracts, dict) else []
    l0_raw = _json_file_bytes(receipt)
    result = {
        "schema": "autofv-result/v1",
        "attempt_id": run["attempt_id"],
        "run_id": run["run_id"],
        "run_root": run["run_root"],
        "attempt_ledger": run["attempt_ledger"],
        "execution_tier": run.get("execution_tier"),
        "cost_classification": run.get("cost_classification"),
        "outcome": outcome,
        "termination_reason": reason,
        "termination_detail": state.get("termination_detail"),
        "frozen_targets": frozen_targets,
        "sets": {
            "T": {"ids": target_ids, "size": len(target_ids)},
            "S": {"ids": supplied_ids, "size": len(supplied_ids)},
            "W": {"ids": [], "size": 0},
            "recovered_internal_specs": {
                "ids": recovered_ids,
                "size": len(recovered_ids),
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
        "proxy_requests": len(receipts) if isinstance(receipts, list) else 0,
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
    run["events"] = [
        event for event in run.get("events", []) if event != "clean_verifier:PASS"
    ]
    run["events"].append("verifier_invalidated:worker_recreated")
