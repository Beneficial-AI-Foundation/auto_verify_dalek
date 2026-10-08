"""Stable entry point for one sealed AutoFV experiment.

Implementation lives behind five cohesive seams: contracts, durable run state,
model exchange, the bounded diamond scheduler, and result/evidence records.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import tempfile
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph

from . import (
    fvs_packet,
    fvs_profile,
    provider_receipts,
    preflight_runner,
    probes,
    provider_service,
    results,
    terminal_run,
    verifier,
    worker,
)
from .contracts import (
    BudgetExhausted,
    ContractError,
    ContractInconclusive,
    DECIMAL_USD,
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
from .preflight import (
    DETERMINISTIC_PREFLIGHT_CASES,
    DETERMINISTIC_PREFLIGHT_GATES,
    named_check_evidence,
    require_deterministic_preflight,
    write_deterministic_preflight,
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
    wall_started_epoch: int,
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
            "wall_started_epoch_ns": wall_started_epoch,
            "termination_detail": str(detail)[:1000],
        }
    else:
        state = dict(existing_state)
        state.update(run=run, termination_detail=str(detail)[:1000])
        # Preserve already-charged intervals instead of resetting their anchors.
        state.setdefault("wall_started_monotonic_ns", wall_started)
        state.setdefault("wall_started_epoch_ns", wall_started_epoch)
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
        results.persist_partial_reports(run, state)
        if state.get("fvs_evidence"):
            results._atomic_write_once(Path(run["evidence_dir"]) / "fvs-stages.json",
                canonical_json_bytes(state["fvs_evidence"]) + b"\n")
        results.persist_l0_sources(run, state)
        _checkpoint_if_enabled(state, "result:before-export")
    except (Exception, KeyboardInterrupt) as exc:
        failed_finalization(exc)

    try:
        results.reconcile_provider_finalization(run, state, outcome=outcome)
        _checkpoint_if_enabled(state, "provider:reconciled")
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
        if run.get("provider_binding") is not None:
            provider_service.release(run)
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


def _load_prepared_inputs(
    target: Path,
    target_manifest: dict[str, Any],
    preparation_manifest_path: str | Path,
    probe_rust_path: str | Path,
    probe_aeneas_path: str | Path,
    dependency_cache_path: str | Path,
    *,
    execution_mode: str,
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]
]:
    """Validate explicit trusted preparation evidence without exposing raw probes."""
    if execution_mode not in {"full", "proof_only"}:
        raise ContractError("prepared execution mode is invalid")
    paths = {
        "preparation manifest": _absolute_path(
            preparation_manifest_path, "preparation manifest", directory=False
        ),
        "probe-rust evidence": _absolute_path(
            probe_rust_path, "probe-rust evidence", directory=False
        ),
        "probe-aeneas evidence": _absolute_path(
            probe_aeneas_path, "probe-aeneas evidence", directory=False
        ),
        "dependency cache": _absolute_path(
            dependency_cache_path, "dependency cache", directory=False
        ),
    }
    if any(path.is_relative_to(target) for path in paths.values()):
        raise ContractError("trusted preparation evidence must be external to the target")
    preparation = _read_json(paths["preparation manifest"], "preparation manifest")
    if not isinstance(preparation, dict):
        raise ContractError("preparation manifest must be an object")
    canonical = canonical_json_bytes(preparation)
    if paths["preparation manifest"].read_bytes() not in {canonical, canonical + b"\n"}:
        raise ContractError("preparation manifest must be canonical JSON")
    rust_raw = paths["probe-rust evidence"].read_bytes()
    aeneas_raw = paths["probe-aeneas evidence"].read_bytes()
    graph = probes.parse_probe_bytes(target_manifest, rust_raw, aeneas_raw)
    try:
        verifier.terminal_verifier._preparation_identity(
            preparation, graph, worker.hash_tree(target)
        )
    except verifier.VerifierError as exc:
        raise ContractError(str(exc)) from exc
    target_report_sha256 = hashlib.sha256(
        probes.render_target_report(graph)
    ).hexdigest()
    if preparation.get("target_report_sha256") != target_report_sha256:
        raise ContractError("prepared target report identity mismatch")
    if execution_mode == "proof_only" and (
        preparation.get("mode") != "small"
        or len(graph.get("frozen_targets", [])) != 1
        or len(target_manifest.get("targets", [])) != 1
    ):
        raise ContractError("proof-only execution requires one prepared small target")
    dependency_digest = hashlib.sha256()
    with paths["dependency cache"].open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            dependency_digest.update(chunk)
    receipt_body = {
        "schema": "autofv-prepared-graph-binding/v1",
        "execution_mode": execution_mode,
        "preparation_manifest_sha256": preparation["manifest_sha256"],
        "probe_rust_sha256": graph["probe_rust_sha256"],
        "probe_aeneas_sha256": graph["probe_aeneas_sha256"],
        "target_report_sha256": target_report_sha256,
        "graph_sha256": graph["graph_sha256"],
        "dependency_cache_sha256": dependency_digest.hexdigest(),
        "dependency_cache_size": paths["dependency cache"].stat().st_size,
    }
    receipt = {
        **receipt_body,
        "receipt_sha256": _canonical_sha256(receipt_body),
    }
    sources = {
        "probe-rust": str(paths["probe-rust evidence"]),
        "probe-aeneas": str(paths["probe-aeneas evidence"]),
        "dependency-cache": str(paths["dependency cache"]),
    }
    return preparation, graph, receipt, sources


def _bind_provider_selection(
    run: dict[str, Any], selection_path: str | Path
) -> None:
    source = _absolute_path(
        selection_path, "provider selection", directory=False
    )
    raw = source.read_bytes()
    selection = _exact_dict(
        _read_json(source, "provider selection"),
        {
            "schema", "status", "selected_at", "selected_by", "decision",
            "scope", "model", "accessibility_evidence", "constraints",
            "verification",
        },
        "provider selection",
    )
    if raw != canonical_json_bytes(selection) + b"\n":
        raise ContractError("provider selection must be canonical JSON")
    if (
        selection["schema"] not in {"autofv-retained-model-selection/v1", "autofv-retained-model-selection/v2"}
        or selection["status"] != "selected"
        or selection["decision"] != "select-model"
    ):
        raise ContractError("provider selection is not approved")
    scope = _exact_dict(
        selection["scope"],
        {
            "proof_smoke", "full_retained_run", "provider_request_authorized",
            "spend_authorized", "push_authorized", "dynamic_routing_allowed",
            "model_substitution_allowed",
        },
        "provider selection scope",
    )
    if scope != {
        "proof_smoke": True,
        "full_retained_run": True,
        "provider_request_authorized": False,
        "spend_authorized": False,
        "push_authorized": False,
        "dynamic_routing_allowed": False,
        "model_substitution_allowed": False,
    }:
        raise ContractError("provider selection scope mismatch")
    fvs = selection["schema"] == "autofv-retained-model-selection/v2"
    extra = {"role_profile", "role_profile_sha256", "source_packet_sha256"} if fvs else set()
    model = _exact_dict(
        selection["model"],
        extra | {
            "model_id", "endpoint", "endpoint_sha256", "parameters", "pricing",
            "pricing_sha256", "tool_schema_sha256", "capability_sha256",
            "fixed_proxy_sha256", "proxy_id", "route_id",
        },
        "provider selection model",
    )
    binding = run.get("provider_binding")
    stable_fields = (
        "model_id", "endpoint", "endpoint_sha256", "parameters", "pricing",
        "pricing_sha256", "tool_schema_sha256", "fixed_proxy_sha256",
        "proxy_id", "route_id",
    )
    if not isinstance(binding, dict) or any(
        binding.get(name) != model[name] for name in (*stable_fields, *sorted(extra))
    ) or fvs != (binding.get("schema") == "autofv-provider-binding/v2"):
        raise ContractError("provider binding does not match selected model/profile")
    if fvs:
        fvs_profile.validate_profile(model["role_profile"])
        evidence = _exact_dict(selection["accessibility_evidence"],
                               {fvs_profile.AUTHOR, fvs_profile.REVIEWER}, "FVS pair accessibility")
        handoff_records = {}
        for model_id, item in evidence.items():
            item = _exact_dict(item, {"provider_preflight", "supported_parameters", "supported_efforts", "catalog_sha256", "endpoint_inventory"},
                               "FVS model accessibility")
            _sha256(item["catalog_sha256"], "FVS public catalog hash")
            if (not isinstance(item["supported_parameters"], list)
                or not {"reasoning", "tools", "tool_choice"} <= set(item["supported_parameters"])
                or not isinstance(item["supported_efforts"], list) or "xhigh" not in item["supported_efforts"]):
                raise ContractError("FVS model lacks advertised required parameters/xhigh")
            inventory = _exact_dict(item["endpoint_inventory"], {"routing_slug", "matching_endpoint_slugs", "ignored_endpoint_slugs", "supported_tool_choices", "pricing_tiers"},
                                    "FVS provider endpoint inventory")
            policy = fvs_profile.profile()["models"][model_id]
            choices = inventory["supported_tool_choices"]
            if (not isinstance(choices, list)
                or any(choice not in ("auto", "none", "required", "function") for choice in choices)
                or choices != sorted(set(choices)) or policy["tool_choice"] not in choices):
                raise ContractError("FVS endpoint lacks advertised exact tool-choice support")
            if (inventory["routing_slug"] != policy["provider"]
                or inventory["ignored_endpoint_slugs"] != policy["ignored_endpoints"]
                or inventory["matching_endpoint_slugs"] != [policy["provider"]]
                or canonical_json_bytes(inventory["pricing_tiers"]) != canonical_json_bytes(policy["tiers"])):
                raise ContractError("FVS routing has ambiguous endpoint variants or advertised price drift")
            record = provider_receipts.validate_preflight_record(item["provider_preflight"])
            old = record["provider_binding"]
            if (old.get("schema") != "autofv-provider-binding/v2"
                or record["request"]["model_id"] != model_id
                or record["request"]["model_id"] != fvs_profile.binding_model(old, record["request"]["role"])
                or old["receipt_authentication"] != binding["receipt_authentication"]
                or any(old[name] != binding[name] for name in (*stable_fields, *sorted(extra)))):
                raise ContractError("FVS pair accessibility is stale or wrong-model/profile")
            if preflight_runner.HELPER_HANDOFF_INPUT_SHA256 in record["request"]["input_hashes"]:
                handoff_records[model_id] = record
        if handoff_records or run.get("fresh_pair_preflight"):
            if (set(handoff_records) != {fvs_profile.AUTHOR, fvs_profile.REVIEWER}
                or run.get("fresh_pair_preflight") is not True or run.get("execution_mode") != "proof_only"
                or not isinstance(run.get("helper_handoff"), dict)):
                raise ContractError("handoff selection cannot be reused outside its original helper invocation")
            ready = preflight_runner.validate_helper_handoff(run)
            for model_id, record in handoff_records.items():
                if (record["provider_binding"] != binding or record["request"]["run_id"] != run["run_id"]
                    or hashlib.sha256(canonical_json_bytes(record) + b"\n").hexdigest()
                    != ready["model_records"][model_id]["sha256"]):
                    raise ContractError("handoff selection does not match its current signed pair")
        digest = fvs_profile.digest(selection)
        if run.get("provider_selection") not in (None, selection) or run.get("provider_selection_sha256") not in (None, digest):
            raise ContractError("FVS frozen provider selection changed during replay")
        run["provider_selection"] = selection
        run["provider_selection_sha256"] = digest
    if "provider_selected" not in run.setdefault("events", []):
        run["events"].append("provider_selected")


def run_experiment(
    target: str | Path,
    run_config: str | Path,
    *,
    output_root: str | Path | None = None,
    run_round=agentproc.run_round,
    resume_from: str | Path | None = None,
    verifier_reference: str | Path | None = None,
    preparation_manifest: str | Path | None = None,
    probe_rust_evidence: str | Path | None = None,
    probe_aeneas_evidence: str | Path | None = None,
    dependency_cache: str | Path | None = None,
    execution_mode: str | None = None,
    env_file: str | Path | None = None,
    provider_selection: str | Path | None = None,
    public_rust_root: str | Path | None = None,
    fresh_pair_preflight: bool = False,
) -> dict[str, Any]:
    """Run the bounded sealed tracer and persist every attempted run."""
    if type(fresh_pair_preflight) is not bool or (fresh_pair_preflight and (
        env_file is None or provider_selection is not None or resume_from is not None
        or execution_mode != "proof_only"
    )):
        raise ContractError("fresh pair handoff requires a new prepared helper run without a selection record")
    if not fresh_pair_preflight and (env_file is None) != (provider_selection is None):
        raise ContractError(
            "provider env file and selected model record must be supplied together"
        )
    prepared_arguments = (
        preparation_manifest,
        probe_rust_evidence,
        probe_aeneas_evidence,
        dependency_cache,
        execution_mode,
    )
    if any(value is not None for value in prepared_arguments) and not all(
        value is not None for value in prepared_arguments
    ):
        raise ContractError(
            "preparation manifest, evidence directory, dependency cache, and "
            "execution mode must be supplied together"
        )
    wall_started = time.monotonic_ns()
    wall_started_epoch = time.time_ns()
    results.validate_output_root(target, output_root)
    # A malformed path argument never starts a run, so it must not use an attempt.
    path_arguments = (
        (target, "target", True, "invalid_target", "target_invalid"),
        (run_config, "run config", False, "invalid_config", "run_config_invalid"),
        (resume_from, "resume root", True, "infrastructure_failed", "resume_failed"),
        (verifier_reference, "verifier reference", False, "invalid_config",
         "verifier_reference_invalid"),
        (preparation_manifest, "preparation manifest", False, "invalid_config",
         "prepared_inputs_invalid"),
        (probe_rust_evidence, "probe-rust evidence", False, "invalid_config",
         "prepared_inputs_invalid"),
        (probe_aeneas_evidence, "probe-aeneas evidence", False, "invalid_config",
         "prepared_inputs_invalid"),
        (dependency_cache, "dependency cache", False, "invalid_config",
         "prepared_inputs_invalid"),
        (public_rust_root, "public Rust root", True, "invalid_config",
         "prepared_inputs_invalid"),
        (None if env_file is None else Path(env_file).expanduser(),
         "provider env file", False, "invalid_config", "provider_inputs_invalid"),
        (provider_selection, "provider selection", False, "invalid_config",
         "provider_inputs_invalid"),
    )
    for value, label, directory, outcome, reason in path_arguments:
        if value is None:
            continue
        try:
            _absolute_path(value, label, directory=directory)
        except ContractError as exc:
            return _persist_unallocated_attempt(
                results.default_attempt_identity(),
                target,
                run_config,
                wall_started,
                wall_started_epoch=wall_started_epoch,
                outcome=outcome,
                reason=reason,
                detail=exc,
                output_root=output_root,
            )
    try:
        identity = results.new_attempt_identity(target)
    except results.ResultError as exc:
        return _persist_unallocated_attempt(
            results.default_attempt_identity(),
            target,
            run_config,
            wall_started,
            wall_started_epoch=wall_started_epoch,
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
            wall_started_epoch=wall_started_epoch,
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

    prepared_inputs = None
    if preparation_manifest is not None:
        try:
            prepared_inputs = _load_prepared_inputs(
                target_path,
                manifest,
                preparation_manifest,
                probe_rust_evidence,
                probe_aeneas_evidence,
                dependency_cache,
                execution_mode=execution_mode,
            )
        except (ContractError, OSError, probes.ProbeError) as exc:
            return persist_unallocated(
                "invalid_config", "prepared_inputs_invalid", exc
            )
        if verifier_reference is None:
            return persist_unallocated(
                "invalid_config",
                "verifier_reference_invalid",
                ContractError("prepared run requires an external verifier reference"),
            )

    if fresh_pair_preflight and (not fvs_profile.enabled(config) or prepared_inputs is None
        or config["max_cost_usd"] > Decimal("10.000000") or config["max_wall_seconds"] > 1800):
        return persist_unallocated("invalid_config", "handoff_scope_invalid",
            ContractError("fresh pair handoff requires prepared FVS with shared USD10/1800s limits"))
    if fvs_profile.enabled(config):
        try:
            if prepared_inputs is None:
                raise ContractError("FVS run/v2 requires the prepared progressive path")
            fvs_packet.bind_original(config["source_packet"], prepared_root=target_path,
                preparation=prepared_inputs[0], source_paths=list(prepared_inputs[1]["source_paths"].values()),
                rust_root=Path(public_rust_root) if public_rust_root is not None else None)
        except (ContractError, OSError) as exc:
            return persist_unallocated("invalid_config", "prepared_inputs_invalid", exc)

    preparation_failure = None

    def prepare_provider(prepared: dict[str, Any]) -> None:
        nonlocal durable_run
        durable_run = prepared
        if fresh_pair_preflight:
            prepared["fresh_pair_preflight"] = True
        if fvs_profile.enabled(config):
            prepared["role_profile"] = config["role_profile"]
            prepared["source_packet_sha256"] = config["source_packet"]["packet_sha256"]
        try:
            preflight_runner.configure_prepared_provider(
                prepared, target_path, env_file=env_file
            )
            provider_service.start(prepared)
        except BaseException:
            provider_service.release(prepared)
            raise

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
            if any(name in checkpoint["run"] for name in ("fresh_pair_preflight", "helper_handoff")):
                raise ContractError("same-worker handoff cannot be resumed as a new allocation")
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
            run = (
                worker.prepare_run(
                    target_path, manifest, lock, before_worker=prepare_provider
                )
                if env_file is not None
                else worker.prepare_run(target_path, manifest, lock)
            )
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
        if prepared_inputs is not None and run.get("execution_tier") == "sealed_runsc":
            try:
                prepared_receipt = prepared_inputs[2]
                run["dependency_cache_receipt"] = worker.seed_dependency_cache(
                    run,
                    prepared_inputs[3]["dependency-cache"],
                    prepared_receipt["dependency_cache_sha256"],
                )
                run["events"].append("dependency_cache_seeded")
            except BaseException as exc:
                try:
                    worker.force_destroy_worker(run)
                except BaseException as destroy_exc:
                    exc = RuntimeError(
                        f"{exc}; forced worker destruction failed: {destroy_exc}"
                    )
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
        if prepared_inputs is not None:
            (
                prepared_manifest,
                prepared_graph,
                prepared_receipt,
                prepared_probe_sources,
            ) = prepared_inputs
            run.update(
                {
                    "preparation_manifest": prepared_manifest,
                    "prepared_graph_receipt": prepared_receipt,
                    "prepared_probe_sources": prepared_probe_sources,
                    "execution_mode": execution_mode,
                    "probe_rust_sha256": prepared_graph["probe_rust_sha256"],
                    "probe_aeneas_sha256": prepared_graph["probe_aeneas_sha256"],
                    "graph_sha256": prepared_graph["graph_sha256"],
                }
            )
            evidence_path = Path(run["evidence_dir"]) / "prepared-graph.json"
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_bytes(canonical_json_bytes(prepared_receipt) + b"\n")
            if "prepared_graph_bound" not in run.setdefault("events", []):
                run["events"].append("prepared_graph_bound")
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
            "compiler_assumptions": verifier.compiler_assumptions(lock, run),
            "wall_seconds_used": Decimal("0.000000"),
            "wall_started_epoch_ns": wall_started_epoch,
            "finalization_reserve_seconds": _finalization_reserve(config),
        }
        if prepared_inputs is not None:
            state["graph"] = prepared_inputs[1]
            if "targets_frozen" not in run["events"]:
                run["events"].append("targets_frozen")
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
    state.setdefault("compiler_assumptions", verifier.compiler_assumptions(lock, run))
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
        if env_file is not None:
            preflight_runner.authorize_prepared_run(
                run,
                target_path,
                run_config,
                Path(run["evidence_dir"]) / "provider-prerequisite",
                env_file=env_file,
                max_age_seconds=(preflight_runner.MAX_AGE_SECONDS if fresh_pair_preflight else config["max_wall_seconds"]),
                **({"public_rust_root": public_rust_root} if public_rust_root is not None else {}),
            )
            if fresh_pair_preflight:
                if _checkpoint_value(validate_run_config(run_config)[1]) != _checkpoint_value(config):
                    raise ContractError("helper handoff configuration changed during preparation")
                provider_selection = preflight_runner.prepare_helper_handoff(
                    state, Path(run["evidence_dir"]) / "provider-prerequisite/preflight-result.json")
                preflight_runner.validate_helper_handoff(run)
            _bind_provider_selection(run, provider_selection)
            if run["provider_binding"]["model_id"] != config["model"]:
                raise ContractError("run model does not match provider binding")
            provider_service.start(run)
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
            f"final result persistence failed for {run.get('run_id')}: {exc}; "
            f"prior detail: {state.get('termination_detail')}"
        )
        try:
            return persist_unallocated(
                "infrastructure_failed",
                "finalization_failed",
                detail,
                existing_run=durable_run,
                existing_state=state if durable_run is not None else None,
            )
        except (Exception, KeyboardInterrupt) as emergency:
            raise results.ResultError(
                f"emergency result persistence failed: {emergency}; {detail}"[:2000]
            ) from emergency


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
    run.add_argument("--env-file")
    run.add_argument("--selection-record")
    run.add_argument("--fresh-pair-preflight", action="store_true",
                     help="Prepared helper only: check the pair on the same worker within the shared budget")
    run.add_argument("--preparation-manifest")
    run.add_argument("--preparation-evidence")
    run.add_argument("--preparation-cache")
    run.add_argument("--public-rust-root", help="FVS only: pinned public curve25519-dalek/src checkout; host ingestion only")
    run.add_argument("--verifier-reference")
    run.add_argument("--execution-mode", choices=("full", "proof-only"))
    run.add_argument("--target", dest="target_alias")
    run.add_argument("--run-config", dest="config_alias")
    preflight_command = commands.add_parser("preflight")
    preflight_command.add_argument("repo")
    preflight_command.add_argument("--config", required=True)
    preflight_command.add_argument("--output", required=True)
    preflight_command.add_argument("--env-file")
    preflight_command.add_argument("--preparation-manifest")
    preflight_command.add_argument("--preparation-evidence")
    preflight_command.add_argument("--preparation-cache")
    preflight_command.add_argument("--public-rust-root")
    preflight_command.add_argument("--check-model-accessibility", action="store_true",
                                   help="FVS only: at most one paid accessibility request per selected model")
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
    if args.command == "preflight":
        from .preflight_runner import run_fvs_preflight, run_preflight

        prepared = (args.preparation_manifest, args.preparation_evidence,
                    args.preparation_cache, args.public_rust_root)
        if any(value is not None for value in prepared) or args.check_model_accessibility:
            if args.env_file is None or any(value is None for value in prepared):
                parser.error("FVS preflight requires --env-file and all preparation/public-Rust flags")
            options = {"env_file": args.env_file, "preparation_manifest": args.preparation_manifest,
                       "probe_rust_evidence": str(Path(args.preparation_evidence) / "probe-rust.json"),
                       "probe_aeneas_evidence": str(Path(args.preparation_evidence) / "probe-aeneas.json"),
                       "dependency_cache": args.preparation_cache, "public_rust_root": args.public_rust_root,
                       "check_model_accessibility": args.check_model_accessibility}
            operation = run_fvs_preflight
        else:
            operation, options = run_preflight, {"env_file": args.env_file}
        try:
            result = operation(args.repo, args.config, args.output, **options)
        except (ContractError, OSError, worker.WorkerError) as exc:
            parser.error(str(exc))
        print(canonical_json_bytes(result).decode("utf-8"))
        if result["status"] != "passed":
            raise SystemExit(1)
        return
    target, run_config = _run_arguments(parser, args)
    try:
        if args.fresh_pair_preflight:
            if args.env_file is None or args.selection_record is not None or args.execution_mode != "proof-only":
                parser.error("--fresh-pair-preflight requires --env-file and prepared --execution-mode proof-only, without --selection-record")
        elif (args.env_file is None) != (args.selection_record is None):
            parser.error(
                "--env-file and --selection-record must be supplied together"
            )
        options = {"output_root": args.output_root}
        if args.fresh_pair_preflight:
            options["fresh_pair_preflight"] = True
        if args.public_rust_root is not None:
            options["public_rust_root"] = args.public_rust_root
        if args.env_file is not None:
            options.update(
                env_file=args.env_file,
                provider_selection=args.selection_record,
            )
        if any(
            value is not None
            for value in (
                args.preparation_manifest,
                args.preparation_evidence,
                args.preparation_cache,
                args.verifier_reference,
                args.execution_mode,
            )
        ):
            options.update(
                preparation_manifest=args.preparation_manifest,
                probe_rust_evidence=(
                    str(Path(args.preparation_evidence) / "probe-rust.json")
                    if args.preparation_evidence
                    else None
                ),
                probe_aeneas_evidence=(
                    str(Path(args.preparation_evidence) / "probe-aeneas.json")
                    if args.preparation_evidence
                    else None
                ),
                dependency_cache=args.preparation_cache,
                verifier_reference=args.verifier_reference,
                execution_mode=args.execution_mode.replace("-", "_")
                if args.execution_mode
                else None,
            )
        result = run_experiment(target, run_config, **options)
    except (ContractError, results.ResultError) as exc:
        parser.error(str(exc))
    print(canonical_json_bytes(result).decode("utf-8"))
    if result["outcome"] != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
