import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import experiment, results, verifier, worker
from tests.test_clean_verifier import (
    REFERENCE,
    _preparation_manifest,
    _sha256,
    _terminal_state,
)
from tests.test_phase1_diamond import TARGET
from tests.test_restart_budget import FIXTURE, LOCK, _checkpoint_state, _run_with_limit


class TerminalFinalizationTests(unittest.TestCase):
    def test_successful_forced_cleanup_does_not_erase_export_failure(self):
        run = {
            "execution_tier": "sealed_runsc",
            "base_commit": "a" * 40,
        }
        state = {"run": run}

        def render(_run, _state, *, outcome, reason):
            return ({"outcome": outcome, "termination_reason": reason}, {})

        with (
            mock.patch.object(results, "persist_verifier_report"),
            mock.patch.object(results, "persist_l0_sources"),
            mock.patch.object(experiment, "_checkpoint_if_enabled"),
            mock.patch.object(experiment, "_charge_wall"),
            mock.patch.object(
                worker,
                "dispose_run",
                side_effect=worker.WorkerError("export failed"),
            ),
            mock.patch.object(worker, "force_destroy_worker") as destroy,
            mock.patch.object(results, "render_attempt", side_effect=render),
            mock.patch.object(results, "persist_attempt"),
        ):
            result = experiment._finish_attempt(
                run,
                state,
                outcome="success",
                reason="all_targets_verified",
            )

        destroy.assert_called_once_with(run)
        self.assertTrue(run["worker_disposed"])
        self.assertEqual(result["outcome"], "infrastructure_failed")
        self.assertEqual(result["termination_reason"], "finalization_failed")
        self.assertEqual(state["termination_detail"]["prior_outcome"], "success")

    def test_phase2_terminal_inputs_survive_checkpoint_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            state["run"]["preparation_manifest"] = {
                "schema": "preparation-manifest/v1",
                "manifest_sha256": "4" * 64,
            }
            state["run"]["verifier_reference"] = {
                "schema": "autofv-verifier-reference-binding/v1",
                "reference_path": "/tmp/autofv-hidden-reference.json",
                "preparation_manifest_sha256": "4" * 64,
                "reference_sha256": "5" * 64,
            }
            state["counterexample_certificate"] = {
                "schema": "autofv-counterexample-certificate/v1",
                "certificate_sha256": "6" * 64,
            }
            state["contract_semantic_review"] = {
                "schema": "contract-semantic-review/v1",
                "review_sha256": "7" * 64,
            }
            experiment._write_checkpoint(state, "terminal:before")
            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            self.assertEqual(
                loaded["run"]["preparation_manifest"],
                state["run"]["preparation_manifest"],
            )
            self.assertEqual(
                loaded["run"]["verifier_reference"],
                state["run"]["verifier_reference"],
            )
            self.assertEqual(
                loaded["state"]["counterexample_certificate"],
                state["counterexample_certificate"],
            )
            self.assertEqual(
                loaded["state"]["contract_semantic_review"],
                state["contract_semantic_review"],
            )
            with mock.patch.object(
                worker,
                "inspect_resume_state",
                return_value={**state["working"], "valid": True},
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )
            self.assertEqual(
                resumed["counterexample_certificate"],
                state["counterexample_certificate"],
            )
            self.assertEqual(
                resumed["contract_semantic_review"],
                state["contract_semantic_review"],
            )
            expected = experiment._checkpoint_identities(state["run"])
            with self.assertRaisesRegex(
                experiment.ContractError, "compatible checkpoint"
            ):
                experiment._load_checkpoint(
                    Path(tmp),
                    {**expected, "verifier_reference_sha256": "f" * 64},
                )

    def test_terminal_clean_verify_uses_reserved_budget_after_search_exhaustion(self):
        state = _checkpoint_state(Path("/private/tmp"))
        terminal = _terminal_state(incomplete=True)
        state.update(
            {
                "graph": terminal["graph"],
                "target_states": terminal["target_states"],
                "contracts": {"frozen": terminal["frozen_contracts"]},
                "native_decide_uses": [],
                "accepted_nodes": [],
            }
        )
        state["run"].update(
            {
                "preparation_manifest": _preparation_manifest(terminal),
                "accepted": state["accepted"],
                "events": [],
            }
        )
        state["run"]["snapshot_sha256"] = state["run"]["preparation_manifest"][
            "tree_sha256"
        ]
        state["run"]["verifier_reference"] = {
            "schema": "autofv-verifier-reference-binding/v1",
            "reference_path": str(REFERENCE.resolve()),
            "preparation_manifest_sha256": state["run"]["preparation_manifest"][
                "manifest_sha256"
            ],
            "reference_sha256": _sha256(REFERENCE.read_bytes()),
        }
        state["cost"] = Decimal("1.000000")
        state["config"]["max_cost_usd"] = Decimal("1.000000")
        incomplete = {
            "verdict": "FAIL",
            "terminal_status": "unverified",
            "axiom_inventory_sha256": "9" * 64,
        }
        with (
            mock.patch.object(verifier, "verify_run", return_value=incomplete) as verify,
            mock.patch.object(verifier, "validate_report", return_value=incomplete),
            mock.patch.object(experiment, "_checkpoint_if_enabled"),
        ):
            update = experiment._clean_verify(state)
        self.assertEqual(update["verifier_report"], incomplete)
        verify.assert_called_once()

    def test_allocated_prepared_reference_failures_finalize_and_dispose(self):
        for failure in ("missing", "mismatched", "unsafe"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                staging = root / "staging"
                (staging / "evidence").mkdir(parents=True)
                output = root / "attempts"
                reference = root / "reference.json"
                reference.write_bytes(REFERENCE.read_bytes())
                supplied_reference = reference
                if failure == "missing":
                    supplied_reference = None
                elif failure == "unsafe":
                    supplied_reference = root / "reference-link.json"
                    supplied_reference.symlink_to(reference)
                prepared = {
                    "run_id": f"reference-{failure}-run",
                    "run_root": str(staging),
                    "evidence_dir": str(staging / "evidence"),
                    "project_dir": "/volume/work/project",
                    "volume": f"reference-{failure}-volume",
                    "agent_worker_id": "lima:agent:reference-fixture",
                    "execution_tier": "sealed_runsc",
                    "cost_classification": "synthetic_fixture",
                    "snapshot_sha256": "1" * 64,
                    "manifest_sha256": "2" * 64,
                    "image_digest": LOCK["image"]["image_digest"],
                    "control_bundle_sha256": "3" * 64,
                    "base_commit": FIXTURE["git"]["base_commit"],
                    "accepted": {
                        "accepted_commit": FIXTURE["git"]["base_commit"],
                        "accepted_tree_sha256": "a" * 64,
                    },
                    "preparation_manifest": {
                        "schema": "preparation-manifest/v1",
                        "manifest_sha256": "4" * 64,
                    },
                    "events": ["validated"],
                }

                def dispose(run, *, interrupted=False):
                    run["worker_disposed"] = True
                    run["events"].append("worker_disposed")
                    run["export_receipt"] = {
                        "schema": "autofv-export/v1",
                        "manifest_sha256": "5" * 64,
                    }

                mismatch = (
                    mock.patch.object(
                        verifier,
                        "bind_prepared_reference",
                        side_effect=verifier.VerifierError(
                            "clean verifier reference hash mismatch"
                        ),
                    )
                    if failure == "mismatched"
                    else mock.patch.object(
                        verifier,
                        "bind_prepared_reference",
                        wraps=verifier.bind_prepared_reference,
                    )
                )
                with (
                    mock.patch.object(worker, "prepare_run", return_value=prepared),
                    mismatch,
                    mock.patch.object(
                        worker, "dispose_run", side_effect=dispose
                    ) as cleanup,
                    mock.patch.object(results, "materialize_accepted") as materialize,
                ):
                    result = experiment.run_experiment(
                        TARGET,
                        TARGET / "run.json",
                        output_root=output,
                        verifier_reference=supplied_reference,
                    )
                self.assertEqual(result["outcome"], "invalid_config", msg=result)
                self.assertEqual(
                    result["termination_reason"], "verifier_reference_invalid"
                )
                cleanup.assert_called_once()
                materialize.assert_called_once()
                self.assertTrue(Path(result["run_root"], "result.json").is_file())

    def test_clean_verifier_pass_wins_when_budget_expires_during_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            terminal = _terminal_state()
            state["graph"] = terminal["graph"]
            state["contracts"] = {"frozen": terminal["frozen_contracts"]}
            state["accepted_nodes"] = terminal["accepted_nodes"]
            state["wall_started_monotonic_ns"] = 0
            state["wall_seconds_used"] = Decimal("0.900000")
            state["finalization_reserve_seconds"] = Decimal("0.100000")
            expected_report = {
                "verdict": "PASS",
                "report_sha256": "6" * 64,
                "axiom_inventory_sha256": "9" * 64,
            }
            with (
                mock.patch.object(verifier, "verify_run", return_value=expected_report),
                mock.patch.object(
                    verifier, "validate_report", return_value=expected_report
                ),
                mock.patch.object(
                    experiment.time, "monotonic_ns", return_value=2_000_000_000
                ),
            ):
                update = experiment._clean_verify(state)
        self.assertEqual(update["verifier_report"]["verdict"], "PASS")
        self.assertEqual(state["verifier_report"]["verdict"], "PASS")

    def test_clean_verifier_failure_is_retained_for_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            terminal = _terminal_state()
            state["graph"] = terminal["graph"]
            state["contracts"] = {"frozen": terminal["frozen_contracts"]}
            state["accepted_nodes"] = terminal["accepted_nodes"]
            report = {"verdict": "FAIL", "failures": ["scope_mismatch"]}
            with (
                mock.patch.object(verifier, "verify_run", return_value=report),
                mock.patch.object(
                    verifier,
                    "validate_report",
                    side_effect=verifier.VerifierError(
                        "clean verifier did not pass"
                    ),
                ),
                self.assertRaises(verifier.VerifierError) as rejected,
            ):
                experiment._clean_verify(state)
        self.assertEqual(state["verifier_report"], report)
        self.assertEqual(rejected.exception.report, report)


if __name__ == "__main__":
    unittest.main()
