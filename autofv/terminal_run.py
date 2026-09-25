"""Controller-owned orchestration for the single terminal verifier pass."""

from __future__ import annotations

import secrets
from typing import Any, Callable

from . import axiom_audit, verifier
from .run_state import _canonical_sha256, _event_once, _node_update


def clean_verify(
    state: dict[str, Any],
    *,
    checkpoint: Callable[[dict[str, Any], str], None],
    charge_wall: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Invoke or validate exactly one verifier report for an accepted state."""
    run, graph, accepted = state["run"], state["graph"], state["accepted"]
    invocation_id = state.get("verifier_invocation_id")
    retained = state.get("verifier_report")
    if invocation_id is not None and not isinstance(retained, dict):
        raise verifier.VerifierError("clean verifier was already invoked")
    if invocation_id is None:
        invocation_id = f"verify-{secrets.token_hex(16)}"
        state["verifier_invocation_id"] = invocation_id
    verification_state = {
        "schema": "autofv-verifier-state/v1",
        "base_commit": run["base_commit"],
        "graph": graph,
        "accepted_nodes": sorted(state.get("accepted_nodes", [])),
        "frozen_contracts": state.get("contracts", {}).get("frozen", {}),
        "native_decide_uses": state.get("native_decide_uses", []),
        "compiler_assumptions": verifier.compiler_assumptions(run["lock"]),
    }
    reference = verifier._trusted_reference(run)
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
        "axiom_scope_sha256": axiom_audit.inventory_scope_sha256(
            axiom_audit.expected_inventory(
                verification_state,
                verifier._strict_json(reference, "verifier_reference"),
            )
        ),
        "toolchain_lock_sha256": _canonical_sha256(run["lock"]),
        "accepted_commit": accepted["accepted_commit"],
        "accepted_tree_sha256": accepted["accepted_tree_sha256"],
        "reference_sha256": verifier._sha256(reference),
    }
    if isinstance(run.get("preparation_manifest"), dict):
        verification_state["target_states"] = state.get("target_states", {})
        certificate = state.get("counterexample_certificate")
        if isinstance(certificate, dict):
            verification_state["counterexample_certificate"] = certificate
        expected.update(
            verifier.terminal_verifier.terminal_expectations(
                run, verification_state
            )
        )
    if isinstance(retained, dict):
        retained_inventory_sha256 = state.get(
            "verifier_axiom_inventory_sha256"
        )
        if not isinstance(retained_inventory_sha256, str):
            raise verifier.VerifierError(
                "retained verifier axiom inventory identity is missing"
            )
        expected["axiom_inventory_sha256"] = retained_inventory_sha256
        report = verifier.validate_report(retained, run, expected)
        return _node_update(
            state,
            verifier_report=report,
            verifier_invocation_id=invocation_id,
            verifier_axiom_inventory_sha256=retained_inventory_sha256,
        )
    checkpoint(state, "verifier:before")
    try:
        run["verification_state"] = verification_state
        report = verifier.verify_run(run, expected)
        state["verifier_report"] = report
        expected["axiom_inventory_sha256"] = report.get(
            "axiom_inventory_sha256"
        )
        report = verifier.validate_report(report, run, expected)
        state["verifier_axiom_inventory_sha256"] = report[
            "axiom_inventory_sha256"
        ]
    except Exception as exc:
        rejected = state.get("verifier_report")
        if isinstance(exc, verifier.VerifierError) and isinstance(rejected, dict):
            exc.report = rejected
        charge_wall(state)
        checkpoint(state, "verifier:failed")
        raise
    finally:
        run.pop("verification_state", None)
    charge_wall(state)
    terminal_event = {
        "unverified": "clean_verifier:INCOMPLETE",
        "false_spec": "clean_verifier:FALSE_SPEC",
    }.get(report.get("terminal_status"), "clean_verifier:PASS")
    _event_once(run, terminal_event)
    checkpoint(state, "verifier:after")
    return _node_update(
        state,
        verifier_report=report,
        verifier_invocation_id=invocation_id,
        verifier_axiom_inventory_sha256=state[
            "verifier_axiom_inventory_sha256"
        ],
    )


def clean_verify_partial(
    state: dict[str, Any],
    node: str,
    *,
    checkpoint: Callable[[dict[str, Any], str], None],
    charge_wall: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Freshly check one exact accepted helper closure without blessing the root."""
    run, graph, accepted = state["run"], state["graph"], state["accepted"]
    if (
        not isinstance(run.get("preparation_manifest"), dict)
        or node not in state.get("accepted_nodes", [])
        or node in graph["frozen_targets"]
    ):
        raise verifier.VerifierError("partial verifier requires an accepted helper")
    receipt_key = f"{node}@{accepted['accepted_commit']}"
    prior = state.setdefault("partial_verifier_reports", {}).get(receipt_key)
    inflight = state.get("partial_verifier_inflight")
    if inflight is not None and prior is None:
        raise verifier.VerifierError("partial verifier invocation is unresolved")
    if prior is not None and inflight is not None:
        raise verifier.VerifierError("partial verifier state is ambiguous")
    invocation_id = prior["invocation_id"] if prior is not None else f"partial-{secrets.token_hex(16)}"
    verification_state = {
        "schema": "autofv-verifier-state/v1",
        "base_commit": run["base_commit"],
        "graph": graph,
        "accepted_nodes": sorted(state["accepted_nodes"]),
        "frozen_contracts": state["contracts"]["frozen"],
        "native_decide_uses": state.get("native_decide_uses", []),
        "compiler_assumptions": verifier.compiler_assumptions(run["lock"]),
        "partial_target": node,
    }
    reference = verifier._trusted_reference(run)
    expected = {
        "invocation_id": invocation_id,
        "snapshot_sha256": run["snapshot_sha256"],
        "manifest_sha256": run["manifest_sha256"],
        "probe_rust_sha256": graph["probe_rust_sha256"],
        "probe_aeneas_sha256": graph["probe_aeneas_sha256"],
        "graph_sha256": graph["graph_sha256"],
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run["control_bundle_sha256"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "axiom_scope_sha256": axiom_audit.inventory_scope_sha256(
            axiom_audit.expected_inventory(verification_state, {"leaves": []})
        ),
        "toolchain_lock_sha256": _canonical_sha256(run["lock"]),
        "accepted_commit": accepted["accepted_commit"],
        "accepted_tree_sha256": accepted["accepted_tree_sha256"],
        "reference_sha256": verifier._sha256(reference),
    }
    if prior is not None:
        expected["axiom_inventory_sha256"] = prior.get("axiom_inventory_sha256")
        return verifier.validate_partial_report(prior, run, expected, node, verification_state)
    state["partial_verifier_inflight"] = {
        "node": node, "accepted_commit": accepted["accepted_commit"],
        "invocation_id": invocation_id,
    }
    checkpoint(state, "partial_verifier:before")
    try:
        report = verifier.verify_run(run, expected, verification_state=verification_state)
        expected["axiom_inventory_sha256"] = report.get("axiom_inventory_sha256")
        report = verifier.validate_partial_report(report, run, expected, node, verification_state)
        state["partial_verifier_reports"][receipt_key] = report
        state.pop("partial_verifier_inflight", None)
    except BaseException:
        charge_wall(state)
        checkpoint(state, "partial_verifier:failed")
        raise
    charge_wall(state)
    checkpoint(state, "partial_verifier:after")
    return report


def final_terminal_audit(
    state: dict[str, Any],
    *,
    verify: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    """Spend reserved finalization capacity on one prepared terminal audit."""
    run = state.get("run", {})
    if (
        not isinstance(run.get("preparation_manifest"), dict)
        or isinstance(state.get("verifier_report"), dict)
        or state.get("verifier_invocation_id") is not None
        or not all(name in state for name in ("graph", "accepted"))
    ):
        return
    prior_detail = state.get("termination_detail")
    try:
        state.update(verify(state))
    except (Exception, KeyboardInterrupt) as exc:
        state["termination_detail"] = {
            "prior_detail": prior_detail,
            "terminal_audit_error": str(exc)[:1000],
        }
