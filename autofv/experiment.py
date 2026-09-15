"""Stable entry point for one sealed AutoFV experiment.

Implementation lives behind five cohesive seams: contracts, durable run state,
model exchange, the bounded diamond scheduler, and result/evidence records.
"""

from __future__ import annotations

import argparse
import os
import secrets
import tempfile
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph

from . import probes, results, terminal_run, verifier, worker
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
    return terminal_run.clean_verify(
        state,
        checkpoint=_checkpoint_if_enabled,
        charge_wall=_charge_wall,
    )


def _final_terminal_audit(state: _RunState) -> None:
    terminal_run.final_terminal_audit(state, verify=_clean_verify)


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
    output_root: str | Path | None = None,
    accepted_source: Path | None = None,
    existing_run: dict[str, Any] | None = None,
    existing_state: _RunState | None = None,
) -> dict[str, Any]:
    run = existing_run
    if run is None:
        run = results.allocate_attempt(
            identity,
            target=target,
            run_config=run_config,
            output_root=output_root,
        )
        if accepted_source is not None:
            results.snapshot_input(run, accepted_source)
    if existing_state is None:
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
    else:
        state = dict(existing_state)
        state.update(
            {
                "run": run,
                "wall_started_monotonic_ns": wall_started,
                "termination_detail": str(detail)[:1000],
            }
        )
    _charge_wall(state)
    results.persist_l0_sources(run, state)
    result, receipt = results.render_attempt(
        run, state, outcome=outcome, reason=reason
    )
    results.persist_attempt(run, result, receipt)
    return result


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
        and not run.get("worker_disposed")
    ):
        if not run.get("base_commit"):
            try:
                worker.force_destroy_worker(run)
                run["worker_disposed"] = True
            except BaseException as exc:
                failed_finalization(exc)
        else:
            try:
                worker.dispose_run(run, interrupted=interrupted)
                results.materialize_accepted(run)
            except (Exception, KeyboardInterrupt) as exc:
                try:
                    if not run.get("worker_disposed"):
                        worker.force_destroy_worker(run)
                        run["worker_disposed"] = True
                except BaseException as destroy_exc:
                    failed_finalization(
                        RuntimeError(
                            f"{exc}; forced worker destruction failed: {destroy_exc}"
                        )
                    )
                else:
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
    verifier_reference: str | Path | None = None,
) -> dict[str, Any]:
    control_manifest, _ = worker.control_manifest(lock)
    identities = {
        "snapshot_sha256": worker.hash_tree(target),
        "manifest_sha256": _canonical_sha256(manifest),
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": control_manifest["bundle_sha256"],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "toolchain_lock_sha256": _canonical_sha256(lock),
        "run_config_sha256": _checkpoint_config_sha256(config),
    }
    if verifier_reference is not None:
        reference = verifier.counterexample.external_reference_identity(
            verifier_reference
        )
        identities.update(
            {
                "verifier_reference_path": reference["reference_path"],
                "verifier_reference_sha256": reference["reference_sha256"],
            }
        )
    return identities


def run_experiment(
    target: str | Path,
    run_config: str | Path,
    *,
    output_root: str | Path | None = None,
    run_round=agentproc.run_round,
    resume_from: str | Path | None = None,
    verifier_reference: str | Path | None = None,
) -> dict[str, Any]:
    """Run the bounded sealed tracer and persist every attempted run."""
    wall_started = time.monotonic_ns()
    results.validate_output_root(target, output_root)
    try:
        identity = results.new_attempt_identity(target)
    except results.ResultError as exc:
        return _persist_unallocated_attempt(
            results.default_attempt_identity(),
            target,
            run_config,
            wall_started,
            outcome="invalid_config",
            reason="attempt_ledger_invalid",
            detail=exc,
            output_root=output_root,
        )
    target_path: Path | None = None
    durable_run: dict[str, Any] | None = None

    def persist_unallocated(
        outcome: str,
        reason: str,
        detail: Exception,
        *,
        existing_run: dict[str, Any] | None = None,
        existing_state: _RunState | None = None,
    ) -> dict[str, Any]:
        return _persist_unallocated_attempt(
            identity,
            target,
            run_config,
            wall_started,
            outcome=outcome,
            reason=reason,
            detail=detail,
            output_root=output_root,
            accepted_source=target_path,
            existing_run=existing_run,
            existing_state=existing_state,
        )

    try:
        target_path, manifest = validate_target(target)
    except KeyboardInterrupt:
        return persist_unallocated(
            "infrastructure_failed",
            "interrupted",
            RuntimeError("controller interrupted"),
        )
    except ContractError as exc:
        return persist_unallocated("invalid_target", "target_invalid", exc)
    try:
        _, config = validate_run_config(run_config)
    except KeyboardInterrupt:
        return persist_unallocated(
            "infrastructure_failed",
            "interrupted",
            RuntimeError("controller interrupted"),
        )
    except ContractError as exc:
        return persist_unallocated("invalid_config", "run_config_invalid", exc)
    try:
        lock = load_toolchain_lock()
        policy = validate_native_decide_policy(lock)
    except KeyboardInterrupt:
        return persist_unallocated(
            "infrastructure_failed",
            "interrupted",
            RuntimeError("controller interrupted"),
        )
    except ContractError as exc:
        return persist_unallocated(
            "infrastructure_failed", "toolchain_contract_invalid", exc
        )

    preparation_failure = None
    if resume_from is not None:
        try:
            resume_root = _absolute_path(
                resume_from, "resume root", directory=True
            )
            checkpoint = _load_checkpoint(
                resume_root,
                _resume_identities(
                    target_path,
                    manifest,
                    config,
                    lock,
                    verifier_reference,
                ),
            )
            state = _restore_checkpoint(
                checkpoint,
                manifest=manifest,
                config=config,
                lock=lock,
                run_round=run_round,
            )
            run = state["run"]
            durable_run = run
        except KeyboardInterrupt:
            return persist_unallocated(
                "infrastructure_failed",
                "interrupted",
                RuntimeError("controller interrupted"),
            )
        except Exception as exc:
            return persist_unallocated(
                "infrastructure_failed", "resume_failed", exc
            )
    else:
        try:
            run = worker.prepare_run(target_path, manifest, lock)
        except KeyboardInterrupt:
            return persist_unallocated(
                "infrastructure_failed",
                "interrupted",
                RuntimeError("controller interrupted"),
            )
        except worker.WorkerError as exc:
            if exc.run is None:
                return persist_unallocated(
                    "infrastructure_failed", "worker_preparation_failed", exc
                )
            run = exc.run
            preparation_failure = exc
        except Exception as exc:
            return persist_unallocated(
                "infrastructure_failed", "worker_preparation_failed", exc
            )
        if output_root is not None or run.get("execution_tier") != "simulation":
            prepared_run = run
            allocation = None
            try:
                allocation = results.allocate_attempt(
                    identity,
                    target=target_path,
                    run_config=run_config,
                    output_root=output_root,
                )
                results.snapshot_input(allocation, target_path)
                run = results.bind_prepared_run(allocation, run)
                durable_run = run
            except results.ResultError as exc:
                detail: Exception = exc
                if (
                    prepared_run.get("execution_tier") == "sealed_runsc"
                    and not prepared_run.get("worker_disposed")
                ):
                    try:
                        worker.force_destroy_worker(prepared_run)
                    except BaseException as destroy_exc:
                        detail = RuntimeError(
                            f"{exc}; forced worker destruction failed: {destroy_exc}"
                        )
                return persist_unallocated(
                    "infrastructure_failed",
                    "attempt_allocation_failed",
                    detail,
                    existing_run=allocation,
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
        run["input_root"] = str(target_path)
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
        if isinstance(run.get("preparation_manifest"), dict):
            try:
                if verifier_reference is None:
                    raise verifier.VerifierError(
                        "prepared run requires an external verifier reference"
                    )
                run["verifier_reference"] = verifier.bind_prepared_reference(
                    run, verifier_reference
                )
            except (Exception, KeyboardInterrupt) as exc:
                state["termination_detail"] = str(exc)[:1000]
                return _finish_attempt(
                    run,
                    state,
                    outcome="invalid_config",
                    reason="verifier_reference_invalid",
                )
    run.setdefault("attempt_id", identity["attempt_id"])
    run.setdefault("attempt_ledger", identity["attempt_ledger"])
    run.setdefault("input_root", str(target_path))
    if isinstance(run.get("preparation_manifest"), dict):
        if verifier_reference is None:
            state["termination_detail"] = (
                "prepared run requires an external verifier reference"
            )
            return _finish_attempt(
                run,
                state,
                outcome="invalid_config",
                reason="verifier_reference_invalid",
            )
        try:
            expected_reference = verifier.counterexample.external_reference_identity(
                verifier_reference
            )
        except (Exception, KeyboardInterrupt) as exc:
            state["termination_detail"] = str(exc)[:1000]
            return _finish_attempt(
                run,
                state,
                outcome="invalid_config",
                reason="verifier_reference_invalid",
            )
        binding = run.get("verifier_reference")
        if not isinstance(binding, dict) or any(
            binding.get(name) != value
            for name, value in expected_reference.items()
        ):
            state["termination_detail"] = (
                "verifier reference identity mismatch"
            )
            return _finish_attempt(
                run,
                state,
                outcome=(
                    "infrastructure_failed"
                    if resume_from is not None
                    else "invalid_config"
                ),
                reason=(
                    "resume_failed"
                    if resume_from is not None
                    else "verifier_reference_invalid"
                ),
            )
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
        if preparation_failure is not None:
            raise preparation_failure
        if (
            run.get("execution_tier") == "sealed_runsc"
            and not run.get("egress_receipt")
        ):
            worker.verify_egress(run)
        if resume_from is None:
            _checkpoint_if_enabled(state, "run:prepared")
        for update in _EXPERIMENT_GRAPH.stream(state, stream_mode="updates"):
            for values in update.values():
                state.update(values)
        terminal = state.get("verifier_report", {}).get("terminal_status")
        if terminal == "unverified":
            outcome, reason = "unverified", "proof_search_incomplete"
        elif terminal == "false_spec":
            outcome, reason = "false_spec", "counterexample_confirmed"
        else:
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
        rejected = getattr(exc, "report", None)
        if isinstance(rejected, dict):
            state["verifier_report"] = rejected
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
    if outcome != "success":
        _final_terminal_audit(state)
    try:
        return _finish_attempt(run, state, outcome=outcome, reason=reason)
    except (Exception, KeyboardInterrupt) as exc:
        detail = RuntimeError(
            f"final result persistence failed for {run.get('run_id')}: {exc}"
        )
        return persist_unallocated(
            "infrastructure_failed",
            "finalization_failed",
            detail,
            existing_run=durable_run,
            existing_state=state if durable_run is not None else None,
        )


def _inspect_paths(
    repo: str | Path, output: str | Path
) -> tuple[Path, Path]:
    project = Path(repo).resolve(strict=True)
    if not project.is_dir():
        raise probes.ProbeError("inspect_repo_not_directory")

    requested = Path(output)
    if not requested.name:
        raise probes.ProbeError("inspect_output_invalid")
    parent = requested.parent.resolve(strict=True)
    destination = parent / requested.name
    if destination == project or destination.is_relative_to(project):
        raise probes.ProbeError("inspect_output_inside_repository")
    if destination.is_symlink() or (
        destination.exists() and not destination.is_file()
    ):
        raise probes.ProbeError("inspect_output_unsafe")
    return project, destination


def inspect_repository(repo: str | Path, output: str | Path) -> bytes:
    """Inspect a supported repository and atomically publish its target report."""
    project, destination = _inspect_paths(repo, output)
    with tempfile.TemporaryDirectory(prefix="autofv-inspect-") as evidence:
        graph = probes.run_probes(project, evidence)
        report = probes.render_target_report(graph)

    temporary = destination.with_name(
        f".{destination.name}.{secrets.token_hex(8)}.tmp"
    )
    try:
        with temporary.open("xb") as stream:
            stream.write(report)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autofv")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("repo")
    inspect.add_argument("--output", required=True)
    run = commands.add_parser("run")
    run.add_argument("repo", nargs="?")
    run.add_argument("--config")
    run.add_argument("--output-root")
    run.add_argument("--target", dest="target_alias")
    run.add_argument("--run-config", dest="config_alias")
    return parser


def _run_arguments(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> tuple[str, str]:
    repositories = [value for value in (args.repo, args.target_alias) if value]
    configs = [value for value in (args.config, args.config_alias) if value]
    if not repositories or not configs:
        parser.error("run requires REPO and --config")
    if len(set(repositories)) != 1 or len(set(configs)) != 1:
        parser.error("run compatibility aliases disagree")
    return repositories[0], configs[0]


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    if args.command == "inspect":
        try:
            inspect_repository(args.repo, args.output)
        except (OSError, probes.ProbeError) as exc:
            parser.error(str(exc))
        return
    target, run_config = _run_arguments(parser, args)
    try:
        result = run_experiment(
            target,
            run_config,
            output_root=args.output_root,
        )
    except (ContractError, results.ResultError) as exc:
        parser.error(str(exc))
    print(canonical_json_bytes(result).decode("utf-8"))
    if result["outcome"] != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
