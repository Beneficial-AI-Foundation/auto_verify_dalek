"""Run budgets, durable checkpoints, and restart recovery."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
import time
from functools import wraps
from decimal import Decimal
from pathlib import Path
from typing import Any, TypedDict

from . import evidence, provider_config, provider_receipts, results, worker, worker_proxy
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
    "input_root",
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
    "proxy_firewall",
    "proxy_network",
    "proxy_relay",
    "proxy_client_identity_sha256",
    "proxy_policy_sha256",
    "proxy_policy_receipt",
    "provider_binding",
    "provider_binding_sha256",
    "provider_preflight_sha256",
    "deterministic_preflight",
    "deterministic_preflight_sha256",
    "deterministic_suite_sha256",
    "provider_journal",
    "provider_transport_rebind",
    "upstream_policy_sha256",
    "upstream_policy_receipt",
    "egress_policy_sha256",
    "egress_receipt",
    "artifact_scan_receipt",
    "export_receipt",
    "disposal_receipt",
    "base_commit",
    "preparation_manifest",
    "verifier_reference",
    "events",
)
CHECKPOINT_STATE_FIELDS = (
    "graph",
    "contracts",
    "frozen_contract_baseline",
    "receipts",
    "accepted",
    "working",
    "result",
    "verifier_report",
    "verifier_invocation_id",
    "verifier_axiom_inventory_sha256",
    "counterexample_certificate",
    "contract_semantic_review",
    "lanes",
    "lane_intervals",
    "candidate_receipts",
    "processed_candidate_sha256",
    "accepted_sequence",
    "accepted_nodes",
    "proof_patch_sha256",
    "immutable_graph_sha256",
    "target_states",
    "preparation_defects",
    "invalidated_consumers",
    "block_chains",
    "file_owners",
    "release_events",
    "pending_model_exchanges",
    "model_exchanges",
    "role_progress",
    "role_tool_outcomes",
    "lane_snapshots",
    "lane_initialization",
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
    frozen_contract_baseline: dict[str, Any] | None
    receipts: list[dict[str, Any]]
    cost: Decimal
    accepted: dict[str, Any]
    result: dict[str, Any]
    verifier_report: dict[str, Any]
    verifier_invocation_id: str
    verifier_axiom_inventory_sha256: str
    counterexample_certificate: dict[str, Any]
    contract_semantic_review: dict[str, Any]
    termination_detail: str | dict[str, str]
    lanes: list[dict[str, Any]]
    lane_intervals: dict[str, dict[str, int]]
    candidate_receipts: list[dict[str, Any]]
    processed_candidate_sha256: list[str]
    accepted_sequence: list[dict[str, Any]]
    accepted_nodes: list[str]
    proof_patch_sha256: dict[str, str]
    immutable_graph_sha256: str
    target_states: dict[str, dict[str, Any]]
    preparation_defects: list[dict[str, Any]]
    invalidated_consumers: list[str]
    block_chains: dict[str, list[str]]
    file_owners: dict[str, str]
    release_events: list[dict[str, Any]]
    receipt_rejections: list[dict[str, Any]]
    compiler_assumptions: list[dict[str, str]]
    l0_receipt: dict[str, Any]
    working: dict[str, Any]
    pending_model_exchanges: dict[str, dict[str, Any]]
    model_exchanges: dict[str, dict[str, Any]]
    role_progress: dict[str, dict[str, Any]]
    role_tool_outcomes: dict[str, dict[str, Any]]
    lane_snapshots: dict[str, dict[str, Any]]
    lane_initialization: dict[str, Any]
    inflight_transition: dict[str, Any]
    wall_seconds_used: Decimal
    finalization_reserve_seconds: Decimal
    wall_started_monotonic_ns: int
    checkpoint_sequence: int
    checkpoint_enabled: bool
    recovery_source: str
    _accept_lock: Any
    _state_lock: Any


def _state_lock(state: _RunState):
    """One reentrant lock protects reservations, reductions and checkpoint snapshots."""
    return state.setdefault("_state_lock", threading.RLock())


def _serialized(method):
    @wraps(method)
    def locked(state, *args, **kwargs):
        with _state_lock(state):
            return method(state, *args, **kwargs)
    return locked


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
        "role_progress",
        "role_tool_outcomes",
        "lane_snapshots",
        "lane_initialization",
        "frozen_contract_baseline",
        "receipt_rejections",
        "immutable_graph_sha256",
        "target_states",
        "preparation_defects",
        "invalidated_consumers",
        "block_chains",
        "file_owners",
        "release_events",
    ):
        if name in state:
            values[name] = state[name]
    return values


def _finalization_reserve(config: dict[str, Any]) -> Decimal:
    return min(Decimal("5.000000"), Decimal(config["max_wall_seconds"]) / 10)


@_serialized
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
    if isinstance(run.get("provider_binding"), dict):
        identities["provider_binding_sha256"] = run.get(
            "provider_binding_sha256"
        )
    if isinstance(run.get("provider_preflight_sha256"), str):
        identities["provider_preflight_sha256"] = run[
            "provider_preflight_sha256"
        ]
    for name in (
        "deterministic_preflight_sha256",
        "deterministic_suite_sha256",
    ):
        if isinstance(run.get(name), str):
            identities[name] = run[name]
    journal = run.get("provider_journal")
    if isinstance(journal, dict):
        identities["provider_journal_sha256"] = _canonical_sha256(journal)
    for name in ("probe_rust_sha256", "probe_aeneas_sha256", "graph_sha256"):
        if name in run:
            identities[name] = run[name]
    preparation = run.get("preparation_manifest")
    if isinstance(preparation, dict):
        identities["preparation_manifest_sha256"] = preparation.get(
            "manifest_sha256"
        )
    reference = run.get("verifier_reference")
    if isinstance(reference, dict):
        identities["verifier_reference_path"] = reference.get("reference_path")
        identities["verifier_reference_sha256"] = reference.get(
            "reference_sha256"
        )
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


@_serialized
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
    binding = run.get("provider_binding")
    binding_sha256 = run.get("provider_binding_sha256")
    if (binding is None) != (binding_sha256 is None):
        return None
    if binding is not None:
        if (
            not isinstance(binding, dict)
            or not isinstance(binding_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", binding_sha256) is None
        ):
            return None
        try:
            public = provider_config.validate_public_binding(binding)
        except (KeyError, TypeError, provider_config.ProviderConfigError):
            return None
        if (
            public.get("binding_sha256") != binding_sha256
            or identities.get("provider_binding_sha256") != binding_sha256
        ):
            return None
    preflight_sha256 = run.get("provider_preflight_sha256")
    if preflight_sha256 is not None and (
        not isinstance(preflight_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", preflight_sha256) is None
        or identities.get("provider_preflight_sha256") != preflight_sha256
    ):
        return None
    journal = run.get("provider_journal")
    if journal is not None and (
        not isinstance(journal, dict)
        or any(
            not isinstance(request_id, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for request_id, digest in journal.items()
        )
        or identities.get("provider_journal_sha256") != _canonical_sha256(journal)
    ):
        return None
    preparation = run.get("preparation_manifest")
    reference = run.get("verifier_reference")
    if isinstance(preparation, dict) and (
        identities.get("preparation_manifest_sha256")
        != preparation.get("manifest_sha256")
    ):
        return None
    if isinstance(reference, dict) and (
        identities.get("verifier_reference_path") != reference.get("reference_path")
        or identities.get("verifier_reference_sha256")
        != reference.get("reference_sha256")
        or reference.get("preparation_manifest_sha256")
        != identities.get("preparation_manifest_sha256")
    ):
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


def _complete_acceptance_dependencies(state: _RunState, transition: dict[str, Any]) -> None:
    """Publish every scheduler consequence of the same accepted tree transition."""
    node = transition["node"]
    commit = transition["accepted"]["accepted_commit"]
    patch_hash = transition.get("patch_sha256")
    if patch_hash is not None:
        state.setdefault("proof_patch_sha256", {})[node] = patch_hash
    target = state.setdefault("target_states", {}).setdefault(node, {})
    target.update({"phase": "proof", "status": "accepted", "accepted_commit": commit})
    releases = state.setdefault("release_events", [])
    if not any(item.get("node") == node and item.get("accepted_commit") == commit for item in releases):
        releases.append({"sequence": len(releases) + 1, "node": node,
                         "accepted_commit": commit})
    for lane in state.get("lanes", []):
        if lane.get("node") == node:
            lane["status"] = "accepted"
            lane.pop("requeueable", None)
    owners = state.setdefault("file_owners", {})
    for path in [path for path, owner in owners.items() if owner == node]:
        owners.pop(path)
    _event_once(state["run"], f"candidate_{transition['status']}:{transition['request_id']}")


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
        accepted_transition = inflight.get("accepted")
        if isinstance(accepted_transition, dict) and _resume_record_matches(
            observed, accepted_transition
        ):
            processed = state.setdefault("processed_candidate_sha256", [])
            if digest not in processed:
                processed.append(digest)
            node = inflight.get("node")
            transition = {
                "sequence": len(state.setdefault("accepted_sequence", [])) + 1,
                "candidate_sha256": digest,
                "node": node,
                "status": inflight.get("status"),
                "base_commit": inflight.get("base_commit"),
                "previous_accepted_commit": inflight.get(
                    "previous_accepted_commit"
                ),
                "accepted_commit": accepted_transition["accepted_commit"],
            }
            transition["transition_sha256"] = _canonical_sha256(transition)
            if not any(
                item.get("candidate_sha256") == digest
                for item in state["accepted_sequence"]
            ):
                state["accepted_sequence"].append(transition)
            state["accepted"] = accepted_transition
            state["working"] = dict(accepted_transition)
            run["accepted"] = accepted_transition
            accepted_nodes = state.setdefault("accepted_nodes", [])
            if node not in accepted_nodes:
                accepted_nodes.append(node)
            if not any(
                item.get("candidate_sha256") == digest
                for item in state.setdefault("candidate_receipts", [])
            ):
                state["candidate_receipts"].append(
                    {
                        "candidate_sha256": digest,
                        "node": node,
                        "status": inflight.get("status"),
                        "reason": None,
                        "local_gate_receipt_sha256": inflight.get(
                            "local_gate_receipt_sha256"
                        ),
                        "accepted_commit": accepted_transition[
                            "accepted_commit"
                        ],
                    }
                )
            state.setdefault("run", run)
            _complete_acceptance_dependencies(state, inflight)
        else:
            processed = state.setdefault("processed_candidate_sha256", [])
            if digest in processed:
                processed.remove(digest)
            for lane in state.get("lanes", []):
                if lane.get("node") == inflight.get("node"):
                    lane["status"] = "interrupted"
                    lane["requeueable"] = True
    accepted = state.get("accepted")
    working = state.get("working") or accepted
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


def _provider_recovery_marked(
    run: dict[str, Any], state: _RunState, identities: dict[str, Any]
) -> bool:
    direct_marker = any(
        name in run
        for name in (
            "provider_binding",
            "provider_binding_sha256",
            "provider_preflight_sha256",
            "provider_journal",
        )
    ) or any(
        name in identities
        for name in (
            "provider_binding_sha256",
            "provider_preflight_sha256",
            "provider_journal_sha256",
        )
    )
    evidence_dir = run.get("evidence_dir")
    if isinstance(evidence_dir, str):
        retained = Path(evidence_dir)
        if "provider_transport_rebind" not in run:
            policy = evidence.validate_retained_provider_policy(run)
            if policy is not None:
                direct_marker = True
        if any(
            os.path.lexists(retained / relative)
            for relative in (
                "provider-preflight.json",
                "provider-journal",
            )
        ):
            direct_marker = True
    receipts = state.get("receipts")
    if isinstance(receipts, list) and any(
        isinstance(receipt, dict)
        and receipt.get("schema") == provider_receipts.PROVIDER_RECEIPT_SCHEMA
        for receipt in receipts
    ):
        direct_marker = True
    for name in ("pending_model_exchanges", "model_exchanges"):
        exchanges = state.get(name)
        if isinstance(exchanges, dict) and any(
            isinstance(exchange, dict)
            and isinstance(exchange.get("receipt"), dict)
            and exchange["receipt"].get("schema")
            == provider_receipts.PROVIDER_RECEIPT_SCHEMA
            for exchange in exchanges.values()
        ):
            direct_marker = True
    return direct_marker


def _validate_provider_recovery(
    run: dict[str, Any], state: _RunState, identities: dict[str, Any]
) -> bool:
    """Authenticate stable provider state before inspecting a recreated worker."""
    if not _provider_recovery_marked(run, state, identities):
        return False
    if not isinstance(run.get("provider_binding"), dict):
        raise ContractError("provider binding is missing from checkpoint")
    try:
        public = provider_config.validate_public_binding(run["provider_binding"])
        pinned = provider_config.provider_binding(run)
        if pinned is None or pinned.public != public:
            raise provider_config.ProviderConfigError(
                "provider binding is not process-pinned"
            )
        provider_receipts.validate_recovery_artifacts(run, state, binding=pinned)
    except (KeyError, TypeError, provider_config.ProviderConfigError) as exc:
        raise ContractError(f"provider binding recovery failed: {exc}") from exc
    return True


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
    provider_recovery = _validate_provider_recovery(
        run, state, checkpoint["identities"]
    )
    if isinstance(state.get("result"), dict):
        state["recovery_source"] = "terminal"
        return state
    rebind_transport = (
        provider_recovery and worker_proxy.has_retained_provider_transport(run)
    )
    previous_agent_worker_id = run.get("agent_worker_id")
    try:
        if rebind_transport:
            worker_proxy.prepare_provider_transport_rebind(run)
            _write_checkpoint(state, "provider_transport_rebind:intent")
        intent = run.get("provider_transport_rebind")
        rebind_phase = intent.get("phase") if isinstance(intent, dict) else None
        if rebind_transport and rebind_phase == "transport_restored":
            # A retained marker proves the last process completed restoration;
            # it does not prove that its listener or worker is still live. Roll
            # the authenticated transport into a fresh durable recovery cycle.
            worker_proxy.finish_provider_transport_rebind(run)
            worker_proxy.prepare_provider_transport_rebind(run)
            _write_checkpoint(
                state, "provider_transport_rebind:revalidation-intent"
            )
            rebind_phase = "intent"
        if rebind_transport and rebind_phase == "recreated_service_rebound":
            worker_proxy.rebind_provider_transport(run, worker_recreated=True)
            _write_checkpoint(state, "provider_transport_rebind:recreated-service")
            validation = run["provider_transport_rebind"].get("validation", {})
            run["proxy_policy_sha256"] = validation.get("proxy_policy_sha256")
            worker.force_destroy_worker(run)
            recovered = _recover_checkpoint_state(state, run, manifest)
        else:
            if rebind_transport:
                worker_proxy.rebind_provider_transport(run)
                _write_checkpoint(state, "provider_transport_rebind:service")
            recovered = _recover_checkpoint_state(state, run, manifest)
            if (
                rebind_transport
                and run.get("agent_worker_id") != previous_agent_worker_id
            ):
                worker_proxy.rebind_provider_transport(
                    run, worker_recreated=True
                )
                _write_checkpoint(
                    recovered, "provider_transport_rebind:recreated-service"
                )
                validation = run["provider_transport_rebind"].get(
                    "validation", {}
                )
                run["proxy_policy_sha256"] = validation.get(
                    "proxy_policy_sha256"
                )
                worker.force_destroy_worker(run)
                recovered = _recover_checkpoint_state(
                    recovered, run, manifest
                )
        if rebind_transport:
            worker_proxy.restore_provider_transport(run)
            _write_checkpoint(
                recovered, "provider_transport_rebind:restored"
            )
            worker_proxy.finish_provider_transport_rebind(run)
            _write_checkpoint(recovered, "provider_transport_rebind:complete")
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
