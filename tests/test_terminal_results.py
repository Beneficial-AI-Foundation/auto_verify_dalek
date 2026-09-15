import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from autofv import evidence, experiment, result_audit, results, verifier
from tests.test_terminal_verifier import _prepared_report
from tests.test_results_evidence import (
    _generic_attempt,
    _receipt,
    _semantic_review,
    _sha,
)


def _counterexample_certificate(state):
    target = state["graph"]["frozen_targets"][0]
    target_state = state["target_states"][target]
    witness = "  decide"
    body = {
        "schema": "autofv-counterexample-certificate/v1",
        "target": target,
        "statement_sha256": target_state["statement_sha256"],
        "accepted_commit": state["accepted"]["accepted_commit"],
        "toolchain_lock_sha256": _sha(state["run"]["lock"]),
        "concrete_inputs": [{"bytes_hex": "ff" * 32}],
        "lean_witness": witness,
        "diagnostics_sha256": "d" * 64,
        "artifact_sha256": hashlib.sha256(witness.encode()).hexdigest(),
        "verification_command": [
            "lake",
            "env",
            "lean",
            "-o",
            ".lake/build/lib/lean/AutoFVCounterexample.olean",
            "AutoFVCounterexample.lean",
        ],
        "native_decide_uses": [],
        "compiler_assumptions": verifier.compiler_assumptions(state["run"]["lock"]),
        "axiom_inventory": [],
        "axiom_audit_sha256": _sha(
            {"theorem": "AutoFV.counterexample", "axioms": []}
        ),
    }
    return _receipt(body, "certificate_sha256")


def _false_spec_attempt(root: Path):
    run, state = _generic_attempt(root)
    target = state["graph"]["frozen_targets"][0]
    state["target_states"][target]["status"] = "false_spec"
    certificate = _counterexample_certificate(state)
    state["counterexample_certificate"] = certificate
    core = copy.deepcopy(state["verifier_report"])
    prepared, _, _ = _prepared_report()
    core["checks"]["runtime_identity"] = True
    core["checks"]["kernel_axioms"] = True
    core["axiom_inventory"] = copy.deepcopy(prepared["axiom_inventory"])
    core["axiom_inventory_sha256"] = prepared["axiom_inventory_sha256"]
    core["axiom_scope_sha256"] = prepared["axiom_scope_sha256"]
    core["native_decide_uses"] = copy.deepcopy(
        prepared["native_decide_uses"]
    )
    core["accepted_native_decide_uses"] = copy.deepcopy(
        prepared["accepted_native_decide_uses"]
    )
    core["hidden_native_decide_uses"] = copy.deepcopy(
        prepared["hidden_native_decide_uses"]
    )
    core["checks"]["target_closure"] = False
    core.update(
        {
            "verdict": "FAIL",
            "evidence_level": "L0",
            "failures": ["accepted_status_mismatch"],
        }
    )
    core.pop("report_sha256")
    core = _receipt(core, "report_sha256")
    report = {
        **{
            key: value
            for key, value in core.items()
            if key != "report_sha256"
        },
        "bundle_sha256": "e" * 64,
        "core_report": core,
        "checks": copy.deepcopy(core["checks"]),
        "failures": ["accepted_status_mismatch", "target_state_incomplete"],
        "counterexample_certificate_sha256": certificate["certificate_sha256"],
        "preparation_manifest_sha256": "f" * 64,
        "preparation_tree_sha256": run["snapshot_sha256"],
        "target_states": copy.deepcopy(state["target_states"]),
        "target_states_sha256": _sha(state["target_states"]),
        "terminal_status": "false_spec",
    }
    state["verifier_report"] = _receipt(report, "report_sha256")
    (root / "evidence/verifier.json").write_bytes(
        experiment.canonical_json_bytes(state["verifier_report"]) + b"\n"
    )
    for relative in ("evidence/l0/build.json", "evidence/l0/replay.json"):
        Path(root, relative).unlink()
    results.persist_l0_sources(run, state)
    result, receipt = results.render_attempt(
        run, state, outcome="false_spec", reason="counterexample_confirmed"
    )
    results.persist_attempt(run, result, receipt)
    retained = root.parent / "retained.json"
    retained.write_bytes(experiment.canonical_json_bytes(result) + b"\n")
    review = root.parent / "review.json"
    review.write_bytes(
        experiment.canonical_json_bytes(state["contract_semantic_review"]) + b"\n"
    )
    return run, state, result, retained, review


class TerminalResultTests(unittest.TestCase):
    def test_offline_verifier_reuses_full_report_authority(self):
        report, _, _ = _prepared_report()
        result = {
            "run_id": report["run_id"],
            "accepted_commit": report["accepted_commit"],
            "accepted_tree_sha256": report["accepted_tree_sha256"],
            "snapshot_sha256": report["snapshot_sha256"],
            "manifest_sha256": report["manifest_sha256"],
            "probe_rust_sha256": report["probe_rust_sha256"],
            "probe_aeneas_sha256": report["probe_aeneas_sha256"],
            "graph_sha256": report["graph_sha256"],
            "image_digest": report["image_digest"],
            "control_bundle_sha256": report["control_bundle_sha256"],
            "native_decide_policy_sha256": report[
                "native_decide_policy_sha256"
            ],
            "native_decide_uses": copy.deepcopy(
                report["native_decide_uses"]
            ),
            "accepted_native_decide_uses": copy.deepcopy(
                report["accepted_native_decide_uses"]
            ),
            "hidden_native_decide_uses": copy.deepcopy(
                report["hidden_native_decide_uses"]
            ),
            "axiom_inventory_sha256": report["axiom_inventory_sha256"],
            "axiom_scope_sha256": report["axiom_scope_sha256"],
            "toolchain_lock_sha256": report["toolchain_lock_sha256"],
            "reference_sha256": report["reference_sha256"],
            "preparation_manifest_sha256": report[
                "preparation_manifest_sha256"
            ],
            "preparation_tree_sha256": report["preparation_tree_sha256"],
            "target_states": report["target_states"],
            "terminal_status": report["terminal_status"],
            "verifier_report_sha256": report["report_sha256"],
            "verifier_invocation_id": report["invocation_id"],
            "agent_worker_id": report["agent_worker_id"],
            "verifier_worker_id": report["verifier_worker_id"],
            "verifier_bundle_sha256": report["bundle_sha256"],
            "outcome": "success",
            "scored": True,
            "evidence_level": "L4",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "evidence/verifier.json").write_bytes(
                experiment.canonical_json_bytes(report) + b"\n"
            )
            self.assertIsNone(result_audit._validate_verifier(result, root))
            for mutation in ("same_worker", "wrong_toolchain", "missing_core"):
                hostile = copy.deepcopy(report)
                if mutation == "same_worker":
                    hostile["verifier_worker_id"] = hostile["agent_worker_id"]
                    hostile["core_report"]["verifier_worker_id"] = hostile[
                        "agent_worker_id"
                    ]
                    core_body = {
                        key: value
                        for key, value in hostile["core_report"].items()
                        if key != "report_sha256"
                    }
                    hostile["core_report"]["report_sha256"] = _sha(core_body)
                elif mutation == "wrong_toolchain":
                    hostile["toolchain_lock_sha256"] = "f" * 64
                    hostile["core_report"]["toolchain_lock_sha256"] = "f" * 64
                    core_body = {
                        key: value
                        for key, value in hostile["core_report"].items()
                        if key != "report_sha256"
                    }
                    hostile["core_report"]["report_sha256"] = _sha(core_body)
                else:
                    hostile.pop("core_report")
                body = {
                    key: value
                    for key, value in hostile.items()
                    if key != "report_sha256"
                }
                hostile["report_sha256"] = _sha(body)
                candidate = {
                    **result,
                    "verifier_report_sha256": hostile["report_sha256"],
                }
                if mutation == "same_worker":
                    candidate["verifier_worker_id"] = hostile[
                        "verifier_worker_id"
                    ]
                elif mutation == "wrong_toolchain":
                    candidate["toolchain_lock_sha256"] = "f" * 64
                (root / "evidence/verifier.json").write_bytes(
                    experiment.canonical_json_bytes(hostile) + b"\n"
                )
                with self.subTest(mutation=mutation), self.assertRaises(
                    result_audit.AuditError
                ):
                    result_audit._validate_verifier(candidate, root)

            (root / "evidence/verifier.json").write_bytes(
                experiment.canonical_json_bytes(report) + b"\n"
            )
            hostile_states = copy.deepcopy(result)
            target = next(iter(hostile_states["target_states"]))
            hostile_states["target_states"][target]["statement_sha256"] = "f" * 64
            with self.assertRaises(result_audit.AuditError):
                result_audit._validate_verifier(hostile_states, root)

    def test_non_success_causes_remain_distinct_and_withheld(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _generic_attempt(Path(tmp) / "run")
            target = state["graph"]["frozen_targets"][0]
            state["target_states"][target]["status"] = "unverified"
            for outcome, reason in (
                ("unverified", "proof_search_failed"),
                ("budget_exhausted", "wall_budget_exhausted"),
                ("contract_inconclusive", "contract_inconclusive"),
                ("infrastructure_failed", "provider_transport_failed"),
            ):
                with self.subTest(outcome=outcome):
                    result, _ = results.render_attempt(
                        run, state, outcome=outcome, reason=reason
                    )
                    self.assertEqual(result["outcome"], outcome)
                    self.assertEqual(result["termination_reason"], reason)
                    self.assertEqual(result["claim"]["status"], "withheld")

    def test_incomplete_terminal_event_preserves_l0_build_replay_and_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _generic_attempt(Path(tmp) / "run")
            baseline = [
                event for event in run["events"] if event != "clean_verifier:PASS"
            ]
            for terminal_event in (
                "clean_verifier:INCOMPLETE",
                "clean_verifier:FALSE_SPEC",
            ):
                run["events"] = [*baseline, terminal_event]
                receipt = evidence.render_l0(run, state)
                items = {item["name"]: item for item in receipt["items"]}
                for name in ("build", "replay", "verifier"):
                    self.assertEqual(items[name]["status"], "present")

    def test_recovered_frozen_contracts_require_semantic_review_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _generic_attempt(Path(tmp) / "run")
            for target in state["target_states"].values():
                target.pop("contract_fingerprint", None)
            state["contracts"].pop("revision_lineage", None)
            state["contracts"].pop("invalidated_fingerprints", None)
            state.pop("contract_semantic_review")
            result, _ = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            self.assertEqual(result["contract_semantic_review_status"], "withheld")
            self.assertEqual(result["claim"]["status"], "withheld")
            self.assertEqual(result["evidence_level"], "L3")

    def test_empty_review_cannot_authorize_helpers_without_fingerprints(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _generic_attempt(Path(tmp) / "run")
            for target in state["target_states"].values():
                target.pop("contract_fingerprint", None)
            for contract in state["contracts"]["frozen"].values():
                contract.pop("model_fingerprint", None)
            state["contracts"].pop("revision_lineage", None)
            state["contracts"].pop("invalidated_fingerprints", None)
            body = {
                "schema": "contract-semantic-review/v1",
                "status": "approved",
                "accepted_commit": state["accepted"]["accepted_commit"],
                "fingerprints": [],
            }
            state["contract_semantic_review"] = _receipt(body, "review_sha256")

            result, _ = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            self.assertEqual(result["contract_semantic_review_status"], "withheld")
            self.assertEqual(result["sets"]["recovered_internal_specs"]["ids"], [])
            self.assertEqual(result["claim"]["status"], "withheld")
            self.assertEqual(result["evidence_level"], "L3")

    def test_missing_withheld_or_stale_semantic_review_withholds_l4(self):
        for mutation in ("missing", "withheld", "stale"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                run, state = _generic_attempt(Path(tmp) / "run")
                if mutation == "missing":
                    state.pop("contract_semantic_review")
                else:
                    review = copy.deepcopy(state["contract_semantic_review"])
                    review["status"] = (
                        "withheld" if mutation == "withheld" else "approved"
                    )
                    if mutation == "stale":
                        review["accepted_commit"] = "f" * 40
                    review.pop("review_sha256")
                    state["contract_semantic_review"] = _receipt(
                        review, "review_sha256"
                    )
                result, _ = results.render_attempt(
                    run, state, outcome="success", reason="all_targets_verified"
                )
                self.assertEqual(result["claim"]["status"], "withheld")
                self.assertEqual(result["evidence_level"], "L3")

    def test_full_audit_rejects_false_spec_without_exact_certificate_and_cause(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, _, result, retained, review = _false_spec_attempt(Path(tmp) / "run")
            self.assertEqual(results.validate_full_audit(retained, review), result)

            for mutation in ("missing_certificate", "transport_reason"):
                hostile = copy.deepcopy(result)
                if mutation == "missing_certificate":
                    hostile["counterexample_certificate"] = None
                else:
                    hostile["termination_reason"] = "provider_transport_failed"
                raw = experiment.canonical_json_bytes(hostile) + b"\n"
                Path(run["run_root"], "result.json").write_bytes(raw)
                retained.write_bytes(raw)
                with self.subTest(mutation=mutation), self.assertRaises(
                    results.ResultError
                ):
                    results.validate_full_audit(retained, review)


if __name__ == "__main__":
    unittest.main()
