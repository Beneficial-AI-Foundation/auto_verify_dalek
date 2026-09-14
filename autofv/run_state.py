"""Run budgets, durable checkpoints, and restart recovery."""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, TypedDict

from . import results, worker
from .contracts import (
    BudgetExhausted,
    ContractError,
    DECIMAL_USD,
    _read_json,
    _text,
    canonical_json_bytes,
)

CHECKPOINT_SCHEMA = "autofv-checkpoint/v1"
CHECKPOINT_RUN_FIELDS = (
    "attempt_id",
    "attempt_ledger",
    "run_id",
    "run_root",
    "project_dir",
    "evidence_dir",
    "volume",
    "agent_worker_id",
    "execution_tier",
    "cost_classification",
    "snapshot_sha256",
    "manifest_sha256",
    "image_digest",
    "control_bundle_sha256",
    "native_decide_policy",
    "native_decide_policy_sha256",
    "worker_inventory",
    "worker_inventory_sha256",
    "scored_container_receipt",
    "fixed_proxy_sha256",
    "proxy_model_id",
    "proxy_base",
    "proxy_firewall",
    "proxy_network",
    "proxy_relay",
    "proxy_client_identity_sha256",
    "proxy_policy_sha256",
    "proxy_policy_receipt",
    "upstream_policy_sha256",
    "upstream_policy_receipt",
    "egress_policy_sha256",
    "egress_receipt",
    "artifact_scan_receipt",
    "export_receipt",
    "disposal_receipt",
    "base_commit",
    "events",
)
CHECKPOINT_STATE_FIELDS = (
    "graph",
    "contracts",
    "receipts",
    "accepted",
    "working",
    "result",
    "verifier_report",
    "verifier_invocation_id",
    "lanes",
    "lane_intervals",
    "candidate_receipts",
    "processed_candidate_sha256",
    "accepted_sequence",
    "accepted_nodes",
    "proof_patch_sha256",
    "pending_model_exchanges",
    "model_exchanges",
    "inflight_transition",
    "receipt_rejections",
    "compiler_assumptions",
    "l0_receipt",
    "wall_seconds_used",
    "finalization_reserve_seconds",
)

class _RunState(TypedDict, total=False):
    run: dict[str, Any]
    manifest: dict[str, Any]
    config: dict[str, Any]
    run_round: Any
    graph: dict[str, Any]
    contracts: dict[str, Any]
    receipts: list[dict[str, Any]]
    cost: Decimal
    accepted: dict[str, Any]
    result: dict[str, Any]
    verifier_report: dict[str, Any]
    verifier_invocation_id: str
    termination_detail: str | dict[str, str]
    lanes: list[dict[str, Any]]
    lane_intervals: dict[str, dict[str, int]]
    candidate_receipts: list[dict[str, Any]]
    processed_candidate_sha256: list[str]
    accepted_sequence: list[dict[str, Any]]
    accepted_nodes: list[str]
    proof_patch_sha256: dict[str, str]
    receipt_rejections: list[dict[str, Any]]
    compiler_assumptions: list[dict[str, str]]
    l0_receipt: dict[str, Any]
    working: dict[str, Any]
    pending_model_exchanges: dict[str, dict[str, Any]]
    model_exchanges: dict[str, dict[str, Any]]
    inflight_transition: dict[str, Any]
    wall_seconds_used: Decimal
    finalization_reserve_seconds: Decimal
    wall_started_monotonic_ns: int
    checkpoint_sequence: int
    checkpoint_enabled: bool
    recovery_source: str
    _accept_lock: Any


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _node_update(state: _RunState, **values: Any) -> dict[str, Any]:
    """Return mutable runtime channels that LangGraph does not infer from mutation."""
    for name in (
        "checkpoint_sequence",
        "wall_seconds_used",
        "wall_started_monotonic_ns",
        "pending_model_exchanges",
        "model_exchanges",
        "receipt_rejections",
    ):
        if name in state:
            values[name] = state[name]
    return values


def _finalization_reserve(config: dict[str, Any]) -> Decimal:
    return min(Decimal("5.000000"), Decimal(config["max_wall_seconds"]) / 10)


def _charge_wall(state: _RunState) -> Decimal:
    now = time.monotonic_ns()
    started = state.get("wall_started_monotonic_ns")
    state["wall_started_monotonic_ns"] = now
    used = Decimal(state.get("wall_seconds_used", Decimal("0.000000")))
    if started is not None:
        if now < started:
            raise ContractError("monotonic clock moved backwards")
        used += Decimal(now - started) / Decimal(1_000_000_000)
    state["wall_seconds_used"] = used
    return used


def _check_wall_budget(state: _RunState) -> None:
    used = _charge_wall(state)
    config = state.get("config", {})
    if "max_wall_seconds" not in config:
        return
    limit = Decimal(config["max_wall_seconds"])
    reserve = Decimal(
        state.get("finalization_reserve_seconds", _finalization_reserve(config))
    )
    if used >= limit - reserve:
        raise BudgetExhausted("wall_seconds", limit, used)


def _check_budget(state: _RunState) -> None:
    _check_wall_budget(state)
    config = state.get("config", {})
    if "max_cost_usd" not in config:
        return
    cost = Decimal(state.get("cost", Decimal("0.000000")))
    limit = Decimal(config["max_cost_usd"])
    if cost >= limit:
        raise BudgetExhausted("cost_usd", limit, cost)


def _checkpoint_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return f"{value:.6f}"
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _checkpoint_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_checkpoint_value(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ContractError(f"checkpoint value is not serializable: {type(value).__name__}")


def _checkpoint_identities(run: dict[str, Any]) -> dict[str, Any]:
    identities = {
        name: run[name]
        for name in (
            "attempt_id",
            "attempt_ledger",
            "run_id",
            "snapshot_sha256",
            "manifest_sha256",
            "image_digest",
            "control_bundle_sha256",
            "native_decide_policy_sha256",
            "volume",
            "base_commit",
        )
        if name in run
    }
    lock = run.get("lock")
    if isinstance(lock, dict):
        identities["toolchain_lock_sha256"] = _canonical_sha256(lock)
    for name in ("probe_rust_sha256", "probe_aeneas_sha256", "graph_sha256"):
        if name in run:
            identities[name] = run[name]
    return identities


def _checkpoint_config_sha256(config: dict[str, Any]) -> str:
    return _canonical_sha256(_checkpoint_value(config))


def _checkpoint_payload(state: _RunState, transition: str, sequence: int) -> dict[str, Any]:
    run = state["run"]
    identities = _checkpoint_identities(run)
    identities["run_config_sha256"] = _checkpoint_config_sha256(state["config"])
    graph = state.get("graph", {})
    for name in ("probe_rust_sha256", "probe_aeneas_sha256", "graph_sha256"):
        if name in graph:
            identities[name] = graph[name]
    body = {
        "schema": CHECKPOINT_SCHEMA,
        "complete": True,
        "checkpoint_sequence": sequence,
        "event_sequence": sequence,
        "event_id": f"checkpoint-{sequence:08d}",
        "transition": _text(transition, "checkpoint transition"),
        "identities": identities,
        "run": {
            name: _checkpoint_value(run[name])
            for name in CHECKPOINT_RUN_FIELDS
            if name in run
        },
        "state": {
            name: _checkpoint_value(state[name])
            for name in CHECKPOINT_STATE_FIELDS
            if name in state
        },
        "cost_usd_used": f"{state.get('cost', Decimal('0.000000')):.6f}",
    }
    return {**body, "content_sha256": _canonical_sha256(body)}


def _write_checkpoint(state: _RunState, transition: str) -> Path:
    """Durably replace one complete checkpoint without trusting directory order."""
    sequence = int(state.get("checkpoint_sequence", 0)) + 1
    state["checkpoint_sequence"] = sequence
    payload = _checkpoint_payload(state, transition, sequence)
    directory = Path(state["run"]["run_root"]) / "checkpoints"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{sequence:08d}.json"
    temporary = directory / f".{sequence:08d}.tmp"
    with temporary.open("wb") as output:
        output.write(canonical_json_bytes(payload) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, destination)
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return destination


def _valid_checkpoint(
    value: Any, expected_identities: dict[str, Any]
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if set(value) != {
        "schema",
        "complete",
        "checkpoint_sequence",
        "event_sequence",
        "event_id",
        "transition",
        "identities",
        "run",
        "state",
        "cost_usd_used",
        "content_sha256",
    }:
        return None
    content_hash = value.get("content_sha256")
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    if (
        value.get("schema") != CHECKPOINT_SCHEMA
        or value.get("complete") is not True
        or type(value.get("checkpoint_sequence")) is not int
        or value["checkpoint_sequence"] <= 0
        or value.get("event_sequence") != value["checkpoint_sequence"]
        or value.get("event_id")
        != f"checkpoint-{value['checkpoint_sequence']:08d}"
        or not isinstance(content_hash, str)
        or not hmac.compare_digest(content_hash, _canonical_sha256(body))
        or not isinstance(value.get("identities"), dict)
        or not isinstance(value.get("run"), dict)
        or not isinstance(value.get("state"), dict)
        or not isinstance(value.get("cost_usd_used"), str)
        or DECIMAL_USD.fullmatch(value["cost_usd_used"]) is None
    ):
        return None
    identities, run = value["identities"], value["run"]
    if any(
        identities.get(name) != run.get(name)
        for name in (
            "attempt_id",
            "attempt_ledger",
            "run_id",
            "snapshot_sha256",
            "manifest_sha256",
            "image_digest",
            "control_bundle_sha256",
            "native_decide_policy_sha256",
            "volume",
            "base_commit",
        )
    ):
        return None
    if any(value["identities"].get(key) != item for key, item in expected_identities.items()):
        return None
    return value


def _load_checkpoint(
    run_root: str | Path, expected_identities: dict[str, Any]
) -> dict[str, Any]:
    valid: dict[int, dict[str, Any]] = {}
    for path in (Path(run_root) / "checkpoints").glob("*.json"):
        try:
            candidate = _valid_checkpoint(_read_json(path, "checkpoint"), expected_identities)
        except ContractError:
            continue
        if candidate is None:
            continue
        try:
            checkpoint_root = Path(candidate["run"]["run_root"]).resolve(strict=True)
        except (KeyError, OSError, TypeError):
            continue
        if checkpoint_root != Path(run_root).resolve(strict=True):
            continue
        sequence = candidate["checkpoint_sequence"]
        previous = valid.get(sequence)
        if previous is not None and previous["content_sha256"] != candidate["content_sha256"]:
            raise ContractError(f"conflicting checkpoint sequence {sequence}")
        valid[sequence] = candidate
    if not valid:
        raise ContractError("no complete hash-valid compatible checkpoint")
    return valid[max(valid)]


def _resume_record_matches(observed: dict[str, Any], expected: dict[str, Any]) -> bool:
    return bool(
        observed.get("valid")
        and observed.get("accepted_commit") == expected.get("accepted_commit")
        and observed.get("accepted_tree_sha256")
        == expected.get("accepted_tree_sha256")
    )


def _recover_checkpoint_state(
    state: _RunState,
    run: dict[str, Any],
    manifest: dict[str, Any],
) -> _RunState:
    accepted = state.get("accepted")
    working = state.get("working") or accepted
    observed = worker.inspect_resume_state(run, manifest)
    inflight = state.pop("inflight_transition", None)
    if isinstance(inflight, dict) and inflight.get("kind") == "candidate_accept":
        digest = inflight.get("candidate_sha256")
        processed = state.setdefault("processed_candidate_sha256", [])
        if digest in processed:
            processed.remove(digest)
        for lane in state.get("lanes", []):
            if lane.get("node") == inflight.get("node"):
                lane["status"] = "interrupted"
                lane["requeueable"] = True
    if isinstance(working, dict) and _resume_record_matches(observed, working):
        source = "working"
    else:
        if not isinstance(accepted, dict) or not {
            "accepted_commit",
            "accepted_tree_sha256",
        } <= accepted.keys():
            raise ContractError("checkpoint has no restorable accepted state")
        observed = worker.restore_accepted(run, accepted, manifest)
        if not _resume_record_matches(observed, accepted):
            raise ContractError("restored accepted state did not match checkpoint")
        state["working"] = dict(accepted)
        source = "accepted"
    for lane in state.get("lanes", []):
        if lane.get("status") in {"preparing", "running"}:
            lane["status"] = "interrupted"
            lane["requeueable"] = True
    state["recovery_source"] = source
    event = f"resumed:{source}"
    if event not in run.setdefault("events", []):
        run["events"].append(event)
    _write_checkpoint(state, event)
    return state


def _restore_checkpoint(
    checkpoint: dict[str, Any],
    *,
    manifest: dict[str, Any],
    config: dict[str, Any],
    lock: dict[str, Any],
    run_round: Any,
) -> _RunState:
    """Reattach trusted runtime objects and recover working state or accepted Git."""
    run = dict(checkpoint["run"])
    run["lock"] = lock
    run["manifest"] = manifest
    state: _RunState = dict(checkpoint["state"])
    state.update(
        {
            "run": run,
            "manifest": manifest,
            "config": config,
            "run_round": run_round,
            "cost": Decimal(checkpoint["cost_usd_used"]),
            "wall_seconds_used": Decimal(
                state.get("wall_seconds_used", "0.000000")
            ),
            "finalization_reserve_seconds": Decimal(
                state.get(
                    "finalization_reserve_seconds", _finalization_reserve(config)
                )
            ),
            "checkpoint_sequence": checkpoint["checkpoint_sequence"],
            "_accept_lock": threading.Lock(),
        }
    )
    if isinstance(state.get("result"), dict):
        state["recovery_source"] = "terminal"
        return state
    previous_agent_worker_id = run.get("agent_worker_id")
    try:
        recovered = _recover_checkpoint_state(state, run, manifest)
        if run.get("agent_worker_id") != previous_agent_worker_id:
            results.invalidate_verifier_evidence(run, recovered)
            _write_checkpoint(recovered, "verifier_invalidated:worker_recreated")
        return recovered
    except BaseException as exc:
        if (
            run.get("execution_tier") == "sealed_runsc"
            and not run.get("worker_disposed")
        ):
            cleanup_error = None
            try:
                worker.dispose_run(run, interrupted=True)
            except BaseException as cleanup_exc:
                cleanup_error = cleanup_exc
                try:
                    worker.force_destroy_worker(run)
                except BaseException as destroy_exc:
                    raise ContractError(
                        "resume failed and forced worker destruction failed: "
                        f"{destroy_exc}"
                    ) from exc
            if cleanup_error is not None:
                raise ContractError(
                    "resume failed after forced worker destruction: "
                    f"{cleanup_error}"
                ) from exc
        raise


def _checkpoint_if_enabled(state: _RunState, transition: str) -> None:
    if state.get("checkpoint_enabled"):
        _write_checkpoint(state, transition)


def _event_once(run: dict[str, Any], event: str) -> None:
    if event not in run.setdefault("events", []):
        run["events"].append(event)


def _external_call(state: _RunState, transition: str, call) -> Any:
    _check_budget(state)
    _checkpoint_if_enabled(state, f"{transition}:before")
    try:
        value = call()
    except Exception:
        _charge_wall(state)
        _checkpoint_if_enabled(state, f"{transition}:failed")
        raise
    _charge_wall(state)
    _checkpoint_if_enabled(state, f"{transition}:after")
    return value
