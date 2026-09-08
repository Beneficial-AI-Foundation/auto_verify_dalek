"""Stable entry point for one sealed AutoFV experiment.

Implementation lives behind four cohesive seams: contracts, durable run state,
model exchange, and the bounded diamond scheduler.
"""

from __future__ import annotations

import argparse
import secrets
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph

from . import probes, verifier, worker
from .contracts import (
    BudgetExhausted,
    ContractError,
    ContractInconclusive,
    DECIMAL_USD,
    HEX_SHA256,
    NATIVE_DECIDE_CRITERIA,
    TOOLCHAIN_LOCK,
    _absolute_path,
    _exact_dict,
    _read_json,
    _sha256,
    _text,
    canonical_json_bytes,
    evaluate_native_decide_policy,
    load_toolchain_lock,
    validate_native_decide_policy,
    validate_proxy_receipt,
    validate_run_config,
    validate_target,
)
from .diamond import (
    _agent_loop,
    _candidate_binding_is_current,
    _candidate_record,
    _checkpoint_candidate,
    _freeze,
    _lane_descriptors,
    _proof_ready_nodes,
    _repair_contracts,
    _statement_fingerprint,
    _statement_record,
    _worker_lane,
)
from .model import (
    _accept_model_exchange,
    _invoke_model,
    _model_envelope,
    _model_request,
    _parallel_model_requests,
    _prompt_sha256,
    _record_model_rejection,
    _validate_model_exchange,
    _validate_model_response,
    agentproc,
)
from .run_state import (
    CHECKPOINT_RUN_FIELDS,
    CHECKPOINT_SCHEMA,
    CHECKPOINT_STATE_FIELDS,
    _RunState,
    _canonical_sha256,
    _charge_wall,
    _check_budget,
    _check_wall_budget,
    _checkpoint_config_sha256,
    _checkpoint_identities,
    _checkpoint_if_enabled,
    _checkpoint_payload,
    _checkpoint_value,
    _event_once,
    _external_call,
    _finalization_reserve,
    _load_checkpoint,
    _node_update,
    _restore_checkpoint,
    _resume_record_matches,
    _valid_checkpoint,
    _write_checkpoint,
)

def _clean_verify(state: _RunState) -> dict[str, Any]:
    run, graph, accepted = state["run"], state["graph"], state["accepted"]
    invocation_id = state.setdefault(
        "verifier_invocation_id", f"verify-{secrets.token_hex(16)}"
    )
    expected = {
        "invocation_id": invocation_id,
        "snapshot_sha256": run["snapshot_sha256"],
        "manifest_sha256": run["manifest_sha256"],
        "probe_rust_sha256": graph["probe_rust_sha256"],
        "probe_aeneas_sha256": graph["probe_aeneas_sha256"],
        "graph_sha256": graph.get("graph_sha256", _canonical_sha256(graph)),
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run["control_bundle_sha256"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "accepted_commit": accepted["accepted_commit"],
        "accepted_tree_sha256": accepted["accepted_tree_sha256"],
    }
    if state.get("verifier_report", {}).get("verdict") == "PASS":
        report = verifier.validate_report(
            state["verifier_report"], run, expected
        )
        return _node_update(
            state,
            verifier_report=report,
            verifier_invocation_id=invocation_id,
        )
    verification_state = {
        "schema": "autofv-verifier-state/v1",
        "base_commit": run["base_commit"],
        "graph": graph,
        "accepted_nodes": sorted(state.get("accepted_nodes", [])),
        "frozen_contracts": state.get("contracts", {}).get("frozen", {}),
        "native_decide_uses": state.get("native_decide_uses", []),
        "compiler_assumptions": verifier.compiler_assumptions(run["lock"]),
    }
    _check_budget(state)
    _checkpoint_if_enabled(state, "verifier:before")
    try:
        run["verification_state"] = verification_state
        report = verifier.validate_report(
            verifier.verify_run(run, expected), run, expected
        )
    except Exception:
        _charge_wall(state)
        _checkpoint_if_enabled(state, "verifier:failed")
        raise
    finally:
        run.pop("verification_state", None)
    _charge_wall(state)
    state["verifier_report"] = report
    _event_once(run, "clean_verifier:PASS")
    _checkpoint_if_enabled(state, "verifier:after")
    return _node_update(
        state,
        verifier_report=report,
        verifier_invocation_id=invocation_id,
    )


def _build_graph():
    graph = StateGraph(_RunState)
    graph.add_node("freeze", _freeze)
    graph.add_node("agent", _agent_loop)
    graph.add_node("verify", _clean_verify)
    graph.add_edge(START, "freeze")
    graph.add_edge("freeze", "agent")
    graph.add_edge("agent", "verify")
    graph.add_edge("verify", END)
    return graph.compile()


_EXPERIMENT_GRAPH = _build_graph()


def _result(
    run: dict[str, Any], state: _RunState, *, outcome: str, reason: str
) -> dict[str, Any]:
    graph = state.get("graph", {})
    wall = _charge_wall(state)
    accepted = state.get("accepted", run.get("accepted", {}))
    report = state.get("verifier_report", {})
    frozen_contracts = state.get("contracts", {}).get("frozen", {})
    internal_nodes = set(state.get("accepted_nodes", [])) - set(
        graph.get("frozen_targets", [])
    )
    cost = sum(
        (Decimal(item["cost"]["amount"]) for item in state.get("receipts", [])),
        Decimal("0.000000"),
    )
    _event_once(run, "result_emitted")
    return {
        "schema": "autofv-result/v1",
        "run_id": run["run_id"],
        "execution_tier": run["execution_tier"],
        "cost_classification": run["cost_classification"],
        "outcome": outcome,
        "termination_reason": reason,
        "termination_detail": state.get("termination_detail"),
        "frozen_targets": graph.get("frozen_targets", []),
        "targets_total": len(graph.get("frozen_targets", [])),
        "targets_verified_final": 1 if outcome == "success" else 0,
        "internal_specs_accepted": len(frozen_contracts),
        "internal_proofs_accepted": len(internal_nodes),
        "proxy_requests": len(state.get("receipts", [])),
        "cost_usd": f"{cost:.6f}",
        "wall_seconds": f"{wall:.6f}",
        "finalization_reserve_seconds": (
            f"{state.get('finalization_reserve_seconds', Decimal('0')):.6f}"
        ),
        "receipt_rejections": state.get("receipt_rejections", []),
        "native_decide_policy": run["native_decide_policy"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "snapshot_sha256": run["snapshot_sha256"],
        "manifest_sha256": run["manifest_sha256"],
        "probe_rust_sha256": graph.get("probe_rust_sha256"),
        "probe_aeneas_sha256": graph.get("probe_aeneas_sha256"),
        "graph_sha256": graph.get("graph_sha256"),
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run["control_bundle_sha256"],
        "accepted_commit": accepted.get("accepted_commit"),
        "accepted_tree_sha256": accepted.get("accepted_tree_sha256"),
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
        "verifier_report_sha256": report.get("report_sha256"),
        "events": list(run["events"]),
    }


def _l0_receipt(run: dict[str, Any], state: _RunState, result: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": "autofv-evidence-l0/v1",
        "run_id": run["run_id"],
        "outcome": result["outcome"],
        "result_sha256": _canonical_sha256(result),
        "proxy_receipt_sha256": [
            item["receipt_sha256"] for item in state.get("receipts", [])
        ],
        "events": result["events"],
    }
    return {**body, "receipt_sha256": _canonical_sha256(body)}


def _resume_identities(
    target: Path,
    manifest: dict[str, Any],
    config: dict[str, Any],
    lock: dict[str, Any],
) -> dict[str, Any]:
    control_manifest, _ = worker._control_manifest(lock)
    return {
        "snapshot_sha256": worker.hash_tree(target),
        "manifest_sha256": _canonical_sha256(manifest),
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": control_manifest["bundle_sha256"],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "toolchain_lock_sha256": _canonical_sha256(lock),
        "run_config_sha256": _checkpoint_config_sha256(config),
    }


def run_experiment(
    target: str | Path,
    run_config: str | Path,
    *,
    run_round=agentproc.run_round,
    resume_from: str | Path | None = None,
) -> dict[str, Any]:
    """Run the bounded sealed tracer and reduce every post-allocation exit."""
    target_path, manifest = validate_target(target)
    _, config = validate_run_config(run_config)
    lock = load_toolchain_lock()
    policy = validate_native_decide_policy(lock)
    wall_started = time.monotonic_ns()
    preparation_failure = None
    if resume_from is not None:
        resume_root = _absolute_path(resume_from, "resume root", directory=True)
        checkpoint = _load_checkpoint(
            resume_root,
            _resume_identities(target_path, manifest, config, lock),
        )
        state = _restore_checkpoint(
            checkpoint,
            manifest=manifest,
            config=config,
            lock=lock,
            run_round=run_round,
        )
        run = state["run"]
    else:
        try:
            run = worker.prepare_run(target_path, manifest, lock)
        except worker.WorkerError as exc:
            if exc.run is None:
                raise
            run = exc.run
            preparation_failure = exc
        run.update(
            {
                "lock": lock,
                "manifest": manifest,
                "native_decide_policy": policy["selection"],
                "native_decide_policy_sha256": lock[
                    "native_decide_policy_sha256"
                ],
            }
        )
        accepted = run.get("accepted") or {"accepted_commit": run.get("base_commit")}
        state = {
            "run": run,
            "manifest": manifest,
            "config": config,
            "run_round": run_round,
            "receipts": [],
            "cost": Decimal("0.000000"),
            "accepted": accepted,
            "working": dict(accepted),
            "pending_model_exchanges": {},
            "model_exchanges": {},
            "receipt_rejections": [],
            "wall_seconds_used": Decimal("0.000000"),
            "finalization_reserve_seconds": _finalization_reserve(config),
        }
    state["wall_started_monotonic_ns"] = wall_started
    state.setdefault("receipt_rejections", [])
    state.setdefault("wall_seconds_used", Decimal("0.000000"))
    state.setdefault("finalization_reserve_seconds", _finalization_reserve(config))
    _charge_wall(state)
    state["checkpoint_enabled"] = bool(run.get("run_root"))
    if resume_from is None:
        _checkpoint_if_enabled(state, "run:prepared")
    elif state.get("result"):
        result = state["result"]
        _checkpoint_if_enabled(state, "result:before-export")
        worker.persist_result(run, result, _l0_receipt(run, state, result))
        _checkpoint_if_enabled(state, "result:after-export")
        return result
    try:
        if preparation_failure is not None:
            raise preparation_failure
        for update in _EXPERIMENT_GRAPH.stream(state, stream_mode="updates"):
            for values in update.values():
                state.update(values)
        result = _result(run, state, outcome="success", reason="all_targets_verified")
    except KeyboardInterrupt:
        state["termination_detail"] = "controller interrupted"
        result = _result(run, state, outcome="failure", reason="interrupted")
    except BudgetExhausted as exc:
        state["termination_detail"] = exc.detail
        result = _result(
            run,
            state,
            outcome="budget_exhausted",
            reason=(
                "cost_budget_exhausted"
                if exc.kind == "cost_usd"
                else "wall_budget_exhausted"
            ),
        )
    except (ContractError, probes.ProbeError, worker.WorkerError, verifier.VerifierError) as exc:
        state["termination_detail"] = str(exc)[:1000]
        result = _result(
            run,
            state,
            outcome="failure",
            reason=(
                "infrastructure_failed"
                if exc is preparation_failure
                else "contract_inconclusive"
                if isinstance(exc, ContractInconclusive)
                else type(exc).__name__.removesuffix("Error").lower()
            ),
        )
    state["result"] = result
    _checkpoint_if_enabled(state, "result:before-export")
    worker.persist_result(run, result, _l0_receipt(run, state, result))
    _checkpoint_if_enabled(state, "result:after-export")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autofv")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--target", required=True)
    run.add_argument("--run-config", required=True)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    try:
        result = run_experiment(args.target, args.run_config)
    except ContractError as exc:
        parser.error(str(exc))
    print(canonical_json_bytes(result).decode("utf-8"))
    if result["outcome"] != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
