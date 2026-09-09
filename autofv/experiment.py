"""Stable entry point for one sealed AutoFV experiment.

Implementation lives behind five cohesive seams: contracts, durable run state,
model exchange, the bounded diamond scheduler, and result/evidence records.
"""

from __future__ import annotations

import argparse
import secrets
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph

from . import probes, results, verifier, worker
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


def _persist_unallocated_attempt(
    identity: dict[str, str],
    target: str | Path,
    run_config: str | Path,
    wall_started: int,
    *,
    outcome: str,
    reason: str,
    detail: Exception,
) -> dict[str, Any]:
    run = results.allocate_attempt(
        identity, target=target, run_config=run_config
    )
    state: _RunState = {
        "run": run,
        "config": {},
        "receipts": [],
        "receipt_rejections": [],
        "wall_seconds_used": Decimal("0.000000"),
        "finalization_reserve_seconds": Decimal("0.000000"),
        "wall_started_monotonic_ns": wall_started,
        "termination_detail": str(detail)[:1000],
    }
    _charge_wall(state)
    results.persist_l0_sources(run, state)
    result, receipt = results.render_attempt(
        run, state, outcome=outcome, reason=reason
    )
    results.persist_attempt(run, result, receipt)
    return result


def _persist_unallocated_interrupt(
    identity: dict[str, str],
    target: str | Path,
    run_config: str | Path,
    wall_started: int,
) -> dict[str, Any]:
    return _persist_unallocated_attempt(
        identity,
        target,
        run_config,
        wall_started,
        outcome="infrastructure_failed",
        reason="interrupted",
        detail=RuntimeError("controller interrupted"),
    )


def _finish_attempt(
    run: dict[str, Any],
    state: _RunState,
    *,
    outcome: str,
    reason: str,
) -> dict[str, Any]:
    interrupted = reason == "interrupted"

    def failed_finalization(exc: BaseException) -> None:
        nonlocal outcome, reason
        state["termination_detail"] = {
            "prior_outcome": outcome,
            "prior_reason": reason,
            "prior_detail": state.get("termination_detail"),
            "finalization_error": str(exc)[:1000],
        }
        outcome, reason = "infrastructure_failed", "finalization_failed"

    try:
        results.persist_verifier_report(run, state.get("verifier_report"))
        results.persist_l0_sources(run, state)
        _checkpoint_if_enabled(state, "result:before-export")
    except (Exception, KeyboardInterrupt) as exc:
        failed_finalization(exc)

    if (
        run.get("execution_tier") == "sealed_runsc"
        and run.get("base_commit")
        and not run.get("worker_disposed")
    ):
        try:
            worker.dispose_run(run, interrupted=interrupted)
        except (Exception, KeyboardInterrupt) as exc:
            failed_finalization(exc)

    try:
        _charge_wall(state)
    except (Exception, KeyboardInterrupt) as exc:
        failed_finalization(exc)
    result, receipt = results.render_attempt(
        run, state, outcome=outcome, reason=reason
    )
    state["result"] = result
    state["l0_receipt"] = receipt
    try:
        _checkpoint_if_enabled(state, "result:after-export")
    except (Exception, KeyboardInterrupt) as exc:
        failed_finalization(exc)
        result, receipt = results.render_attempt(
            run, state, outcome=outcome, reason=reason
        )
        state["result"] = result
        state["l0_receipt"] = receipt
    results.persist_attempt(run, result, receipt)
    return result


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
    """Run the bounded sealed tracer and persist every attempted run."""
    wall_started = time.monotonic_ns()
    try:
        identity = results.new_attempt_identity()
    except results.ResultError as exc:
        return _persist_unallocated_attempt(
            results.default_attempt_identity(),
            target,
            run_config,
            wall_started,
            outcome="invalid_config",
            reason="attempt_ledger_invalid",
            detail=exc,
        )
    try:
        target_path, manifest = validate_target(target)
    except KeyboardInterrupt:
        return _persist_unallocated_interrupt(
            identity, target, run_config, wall_started
        )
    except ContractError as exc:
        return _persist_unallocated_attempt(
            identity,
            target,
            run_config,
            wall_started,
            outcome="invalid_target",
            reason="target_invalid",
            detail=exc,
        )
    try:
        _, config = validate_run_config(run_config)
    except KeyboardInterrupt:
        return _persist_unallocated_interrupt(
            identity, target, run_config, wall_started
        )
    except ContractError as exc:
        return _persist_unallocated_attempt(
            identity,
            target,
            run_config,
            wall_started,
            outcome="invalid_config",
            reason="run_config_invalid",
            detail=exc,
        )
    try:
        lock = load_toolchain_lock()
        policy = validate_native_decide_policy(lock)
    except KeyboardInterrupt:
        return _persist_unallocated_interrupt(
            identity, target, run_config, wall_started
        )
    except ContractError as exc:
        return _persist_unallocated_attempt(
            identity,
            target,
            run_config,
            wall_started,
            outcome="infrastructure_failed",
            reason="toolchain_contract_invalid",
            detail=exc,
        )

    preparation_failure = None
    if resume_from is not None:
        try:
            resume_root = _absolute_path(
                resume_from, "resume root", directory=True
            )
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
        except KeyboardInterrupt:
            return _persist_unallocated_interrupt(
                identity, target, run_config, wall_started
            )
        except Exception as exc:
            return _persist_unallocated_attempt(
                identity,
                target,
                run_config,
                wall_started,
                outcome="infrastructure_failed",
                reason="resume_failed",
                detail=exc,
            )
    else:
        try:
            run = worker.prepare_run(target_path, manifest, lock)
        except KeyboardInterrupt:
            return _persist_unallocated_interrupt(
                identity, target, run_config, wall_started
            )
        except worker.WorkerError as exc:
            if exc.run is None:
                return _persist_unallocated_attempt(
                    identity,
                    target,
                    run_config,
                    wall_started,
                    outcome="infrastructure_failed",
                    reason="worker_preparation_failed",
                    detail=exc,
                )
            run = exc.run
            preparation_failure = exc
        except Exception as exc:
            return _persist_unallocated_attempt(
                identity,
                target,
                run_config,
                wall_started,
                outcome="infrastructure_failed",
                reason="worker_preparation_failed",
                detail=exc,
            )
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
        run.update(identity)
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
            "compiler_assumptions": verifier.compiler_assumptions(lock),
            "wall_seconds_used": Decimal("0.000000"),
            "finalization_reserve_seconds": _finalization_reserve(config),
        }
    run.setdefault("attempt_id", identity["attempt_id"])
    run.setdefault("attempt_ledger", identity["attempt_ledger"])
    state["wall_started_monotonic_ns"] = wall_started
    state.setdefault("receipt_rejections", [])
    state.setdefault("compiler_assumptions", verifier.compiler_assumptions(lock))
    state.setdefault("wall_seconds_used", Decimal("0.000000"))
    state.setdefault("finalization_reserve_seconds", _finalization_reserve(config))
    state["checkpoint_enabled"] = bool(run.get("run_root"))
    if resume_from is not None and state.get("result"):
        result = state["result"]
        receipt = state.get("l0_receipt")
        if not isinstance(receipt, dict):
            receipt = _read_json(
                Path(run["run_root"]) / "evidence" / "l0.json",
                "L0 receipt",
            )
        results.persist_attempt(run, result, receipt)
        return result
    try:
        _charge_wall(state)
        if resume_from is None:
            _checkpoint_if_enabled(state, "run:prepared")
        if preparation_failure is not None:
            raise preparation_failure
        for update in _EXPERIMENT_GRAPH.stream(state, stream_mode="updates"):
            for values in update.values():
                state.update(values)
        outcome, reason = "success", "all_targets_verified"
    except KeyboardInterrupt:
        state["termination_detail"] = "controller interrupted"
        outcome, reason = "infrastructure_failed", "interrupted"
    except BudgetExhausted as exc:
        state["termination_detail"] = exc.detail
        outcome = "budget_exhausted"
        reason = (
            "cost_budget_exhausted"
            if exc.kind == "cost_usd"
            else "wall_budget_exhausted"
        )
    except ContractInconclusive as exc:
        state["termination_detail"] = str(exc)[:1000]
        outcome, reason = "contract_inconclusive", "contract_inconclusive"
    except probes.ProbeError as exc:
        state["termination_detail"] = str(exc)[:1000]
        outcome, reason = "verification_failed", "probe_failed"
    except verifier.VerifierInfrastructureError as exc:
        state["termination_detail"] = str(exc)[:1000]
        outcome, reason = (
            "infrastructure_failed",
            "clean_verifier_infrastructure_failed",
        )
    except verifier.VerifierError as exc:
        state["termination_detail"] = str(exc)[:1000]
        outcome, reason = "verification_failed", "clean_verifier_failed"
    except worker.WorkerError as exc:
        state["termination_detail"] = str(exc)[:1000]
        outcome = "infrastructure_failed"
        if run.pop("preparation_interrupted", False):
            reason = "interrupted"
        else:
            reason = (
                "worker_preparation_failed"
                if exc is preparation_failure
                else "worker_failed"
            )
    except ContractError as exc:
        state["termination_detail"] = str(exc)[:1000]
        outcome, reason = "contract_inconclusive", "contract_invalid"
    except Exception as exc:
        state["termination_detail"] = str(exc)[:1000]
        outcome, reason = "infrastructure_failed", "controller_failed"
    try:
        return _finish_attempt(run, state, outcome=outcome, reason=reason)
    except (Exception, KeyboardInterrupt) as exc:
        detail = RuntimeError(
            f"final result persistence failed for {run.get('run_id')}: {exc}"
        )
        return _persist_unallocated_attempt(
            {
                "attempt_id": run["attempt_id"],
                "attempt_ledger": run["attempt_ledger"],
            },
            target,
            run_config,
            wall_started,
            outcome="infrastructure_failed",
            reason="finalization_failed",
            detail=detail,
        )


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
