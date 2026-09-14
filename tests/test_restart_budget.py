import copy
import json
import os
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import experiment, results, verifier, worker
from tests.test_phase1_diamond import MODEL_FIXTURE, TARGET, _FixtureProxy, _Seams


FIXTURE = json.loads(MODEL_FIXTURE.read_text())
ENTRIES = {entry["request"]["request_id"]: entry for entry in FIXTURE["entries"]}
LOCK = experiment.load_toolchain_lock()
POLICY = LOCK["native_decide_policy_sha256"]


def _checkpoint_state(root: Path) -> dict:
    accepted = {
        "accepted_commit": FIXTURE["git"]["base_commit"],
        "accepted_tree_sha256": "a" * 64,
    }
    run = {
        "run_id": FIXTURE["run_id"],
        "run_root": str(root),
        "project_dir": "/volume/work/project",
        "evidence_dir": str(root / "evidence"),
        "volume": "fixture-volume",
        "agent_worker_id": "agent-worker-fixture",
        "execution_tier": "simulation",
        "cost_classification": "synthetic_fixture",
        "snapshot_sha256": "1" * 64,
        "manifest_sha256": "2" * 64,
        "image_digest": LOCK["image"]["image_digest"],
        "control_bundle_sha256": "3" * 64,
        "native_decide_policy": "allow_audited",
        "native_decide_policy_sha256": POLICY,
        "base_commit": FIXTURE["git"]["base_commit"],
        "events": ["validated"],
        "accepted": copy.deepcopy(accepted),
        "lock": LOCK,
    }
    return {
        "run": run,
        "manifest": {
            "schema": "autofv/v1",
            "targets": [{"function": "crate::top", "spec": "Diamond.top_spec"}],
            "verify": ["lake", "build"],
        },
        "config": {
            "schema": "autofv-run/v1",
            "model": FIXTURE["model_id"],
            "max_wall_seconds": 300,
            "max_cost_usd": Decimal("1.000000"),
        },
        "run_round": lambda request: request,
        "receipts": [],
        "cost": Decimal("0.000000"),
        "accepted": copy.deepcopy(accepted),
        "working": copy.deepcopy(accepted),
        "lanes": [],
        "candidate_receipts": [],
        "processed_candidate_sha256": [],
        "accepted_sequence": [],
        "accepted_nodes": [],
    }


class RestartTests(unittest.TestCase):
    def test_completed_model_exchange_reuses_its_original_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            entry = copy.deepcopy(ENTRIES["scout-001"])
            state["receipts"] = [entry["receipt"]]
            state["cost"] = Decimal(entry["receipt"]["cost"]["amount"])
            state["model_exchanges"] = {
                "scout-001": {
                    "request": entry["request"],
                    "response": entry["response"],
                    "receipt": entry["receipt"],
                }
            }
            state["pending_model_exchanges"] = {}
            state["run_round"] = mock.Mock(side_effect=AssertionError("replayed"))

            response, receipt = experiment._model_request(
                state,
                request_id="scout-001",
                role="scout",
                input_hashes=entry["request"]["input_hashes"],
            )

            self.assertEqual(response, entry["response"])
            self.assertEqual(receipt, entry["receipt"])
            state["run_round"].assert_not_called()

    def test_loader_uses_highest_valid_sequence_not_name_or_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            first = experiment._write_checkpoint(state, "probe:before")
            state["run"]["events"].append("probe_rust")
            second = experiment._write_checkpoint(state, "probe:after")
            scrambled = second.with_name("00000000-out-of-order.json")
            second.rename(scrambled)
            os.utime(first, (2_000_000_000, 2_000_000_000))

            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            self.assertEqual(loaded["checkpoint_sequence"], 2)
            self.assertEqual(loaded["transition"], "probe:after")

            scrambled.write_text("{corrupt", encoding="utf-8")
            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            self.assertEqual(loaded["checkpoint_sequence"], 1)

    def test_interrupted_atomic_replace_leaves_previous_complete_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            experiment._write_checkpoint(state, "model:before")

            with (
                mock.patch.object(os, "replace", side_effect=OSError("power loss")),
                self.assertRaisesRegex(OSError, "power loss"),
            ):
                experiment._write_checkpoint(state, "model:after")

            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            self.assertEqual(loaded["checkpoint_sequence"], 1)
            self.assertEqual(loaded["transition"], "model:before")

    def test_controller_or_policy_drift_cannot_resume_candidate_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            state["processed_candidate_sha256"] = ["4" * 64]
            experiment._write_checkpoint(state, "candidate:after")
            expected = experiment._checkpoint_identities(state["run"])

            for field in ("control_bundle_sha256", "native_decide_policy_sha256"):
                with self.subTest(field=field), self.assertRaisesRegex(
                    experiment.ContractError, "compatible checkpoint"
                ):
                    experiment._load_checkpoint(
                        Path(tmp), {**expected, field: "f" * 64}
                    )

    def test_valid_working_state_resumes_once_and_orphan_lane_is_requeueable(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            state["lanes"] = [
                {
                    "lane_id": "proof-left-001",
                    "node": "probe:Diamond.left",
                    "status": "running",
                }
            ]
            state["processed_candidate_sha256"] = ["4" * 64]
            state["accepted_sequence"] = [{"sequence": 1, "candidate_sha256": "4" * 64}]
            path = experiment._write_checkpoint(state, "candidate:before")
            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            observed = {**state["working"], "valid": True, "dirty": False}

            with (
                mock.patch.object(worker, "inspect_resume_state", return_value=observed),
                mock.patch.object(worker, "restore_accepted") as restore,
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            self.assertEqual(resumed["recovery_source"], "working")
            self.assertEqual(resumed["run"]["manifest"], state["manifest"])
            self.assertEqual(resumed["processed_candidate_sha256"], ["4" * 64])
            self.assertEqual(len(resumed["accepted_sequence"]), 1)
            self.assertEqual(resumed["lanes"][0]["status"], "interrupted")
            self.assertTrue(resumed["lanes"][0]["requeueable"])
            restore.assert_not_called()
            self.assertTrue(path.is_file())

    def test_corrupt_working_state_restores_exact_accepted_or_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            experiment._write_checkpoint(state, "build:before")
            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            restored = {**state["accepted"], "valid": True, "dirty": False}

            with (
                mock.patch.object(
                    worker,
                    "inspect_resume_state",
                    return_value={"valid": False, "reason": "working tree changed"},
                ),
                mock.patch.object(worker, "restore_accepted", return_value=restored) as restore,
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )
            self.assertEqual(resumed["recovery_source"], "accepted")
            restore.assert_called_once_with(
                resumed["run"], state["accepted"], state["manifest"]
            )

            loaded["state"]["accepted"] = {}
            with (
                mock.patch.object(
                    worker, "inspect_resume_state", return_value={"valid": False}
                ),
                self.assertRaisesRegex(experiment.ContractError, "accepted state"),
            ):
                experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

    def test_failed_sealed_recovery_disposes_the_recreated_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            state["run"]["execution_tier"] = "sealed_runsc"
            experiment._write_checkpoint(state, "build:before")
            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            with (
                mock.patch.object(
                    worker,
                    "inspect_resume_state",
                    return_value={"valid": False, "reason": "recreated worker drift"},
                ),
                mock.patch.object(
                    worker,
                    "restore_accepted",
                    return_value={"valid": False, "reason": "accepted restore drift"},
                ),
                mock.patch.object(worker, "dispose_run") as dispose,
                self.assertRaisesRegex(experiment.ContractError, "did not match"),
            ):
                experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            dispose.assert_called_once()
            self.assertTrue(dispose.call_args.kwargs["interrupted"])

    def test_failed_recovery_forces_destruction_when_export_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            state["run"]["execution_tier"] = "sealed_runsc"
            experiment._write_checkpoint(state, "build:before")
            loaded = experiment._load_checkpoint(
                Path(tmp), experiment._checkpoint_identities(state["run"])
            )
            with (
                mock.patch.object(
                    worker,
                    "inspect_resume_state",
                    return_value={"valid": False},
                ),
                mock.patch.object(
                    worker,
                    "restore_accepted",
                    return_value={"valid": False},
                ),
                mock.patch.object(
                    worker, "dispose_run", side_effect=worker.WorkerError("export failed")
                ),
                mock.patch.object(worker, "force_destroy_worker") as destroy,
                self.assertRaisesRegex(
                    experiment.ContractError, "after forced worker destruction"
                ),
            ):
                experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            destroy.assert_called_once()

    def test_recreated_worker_invalidates_old_verifier_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _checkpoint_state(root)
            state["verifier_report"] = {
                "agent_worker_id": "agent-worker-fixture",
                "report_sha256": "f" * 64,
                "verdict": "PASS",
            }
            state["verifier_invocation_id"] = "verify-old"
            for relative in (
                "evidence/verifier.json",
                "evidence/l0/build.json",
                "evidence/l0/replay.json",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n")
            experiment._write_checkpoint(state, "result:before-export")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )

            def recreate(run, _manifest):
                run["agent_worker_id"] = "agent-worker-recreated"
                return {**state["working"], "valid": True, "dirty": False}

            with mock.patch.object(
                worker, "inspect_resume_state", side_effect=recreate
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            self.assertNotIn("verifier_report", resumed)
            self.assertNotIn("verifier_invocation_id", resumed)
            self.assertIn(
                "verifier_invalidated:worker_recreated", resumed["run"]["events"]
            )
            history = root / "evidence" / "history" / ("f" * 64)
            self.assertEqual(
                sorted(path.name for path in history.iterdir()),
                ["build.json", "replay.json", "verifier.json"],
            )
            latest = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(resumed["run"])
            )
            self.assertNotIn("verifier_report", latest["state"])


def _run_with_limit(root: Path, *, max_wall_seconds=300, max_cost_usd="1.000000"):
    config = root / "run.json"
    config.write_text(
        json.dumps(
            {
                "schema": "autofv-run/v1",
                "model": FIXTURE["model_id"],
                "max_wall_seconds": max_wall_seconds,
                "max_cost_usd": max_cost_usd,
            }
        ),
        encoding="utf-8",
    )
    seams = _Seams(root, FIXTURE)
    proxy = _FixtureProxy(FIXTURE)
    patches = (
        mock.patch.object(worker, "prepare_run", seams.prepare),
        mock.patch.object(worker, "run_probes", side_effect=seams.run_probes),
        mock.patch.object(
            worker, "check_contract_feasibility", seams.check_contract_feasibility
        ),
        mock.patch.object(worker, "accept_candidate", seams.accept),
        mock.patch.object(results, "persist_attempt", seams.persist),
        mock.patch.object(verifier, "verify_run", seams.verify),
    )
    return config, seams, proxy, patches


class BudgetTests(unittest.TestCase):
    def test_graph_carries_latest_checkpoint_and_exchange_state_between_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _seams, proxy, patches = _run_with_limit(root)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
            ):
                result = experiment.run_experiment(TARGET, config, run_round=proxy)

            checkpoints = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "checkpoints").glob("*.json")
            ]
            latest = max(checkpoints, key=lambda item: item["checkpoint_sequence"])
            self.assertEqual(result["outcome"], "success")
            self.assertEqual(len(latest["state"]["receipts"]), 8)
            self.assertEqual(len(latest["state"]["model_exchanges"]), 8)
            self.assertEqual(latest["transition"], "result:after-export")

    def test_tiny_authenticated_cost_limit_is_partial_not_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _seams, proxy, patches = _run_with_limit(
                root, max_cost_usd="0.001000"
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                result = experiment.run_experiment(TARGET, config, run_round=proxy)

            self.assertEqual(result["outcome"], "budget_exhausted")
            self.assertEqual(result["termination_reason"], "cost_budget_exhausted")
            self.assertEqual(result["proxy_requests"], 1)
            self.assertEqual(result["cost_usd"], "0.001600")
            self.assertEqual(result["termination_detail"]["kind"], "cost_usd")
            self.assertTrue((root / "result.json").is_file())
            self.assertTrue(list((root / "checkpoints").glob("*.json")))

    def test_tiny_wall_limit_stops_launches_and_finalizes_result(self):
        class Clock:
            now = -600_000_000

            def __call__(self):
                self.now += 600_000_000
                return self.now

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, _seams, proxy, patches = _run_with_limit(
                root, max_wall_seconds=1
            )
            with (
                patches[0],
                patches[1] as probes_call,
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                mock.patch.object(experiment.time, "monotonic_ns", side_effect=Clock()),
            ):
                result = experiment.run_experiment(TARGET, config, run_round=proxy)

            self.assertEqual(result["outcome"], "budget_exhausted")
            self.assertEqual(result["termination_reason"], "wall_budget_exhausted")
            self.assertGreaterEqual(Decimal(result["wall_seconds"]), Decimal("1"))
            self.assertEqual(result["proxy_requests"], 0)
            probes_call.assert_not_called()
            self.assertTrue((root / "result.json").is_file())

    def test_clean_verifier_pass_wins_when_budget_expires_during_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            state["graph"] = {
                "probe_rust_sha256": "4" * 64,
                "probe_aeneas_sha256": "5" * 64,
            }
            state["wall_started_monotonic_ns"] = 0
            state["wall_seconds_used"] = Decimal("0.900000")
            state["finalization_reserve_seconds"] = Decimal("0.100000")
            expected_report = {"verdict": "PASS", "report_sha256": "6" * 64}

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
            state["graph"] = {
                "probe_rust_sha256": "4" * 64,
                "probe_aeneas_sha256": "5" * 64,
            }
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


def _exchange_state(root: Path) -> dict:
    state = _checkpoint_state(root)
    state["run"]["base_commit"] = FIXTURE["git"]["base_commit"]
    state["config"]["model"] = FIXTURE["model_id"]
    return state


class ProxyReceiptBudgetTests(unittest.TestCase):
    def test_out_of_order_acceptance_charges_immediately_and_sorts_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _exchange_state(Path(tmp))
            for entry in FIXTURE["entries"][:5]:
                experiment._accept_model_exchange(
                    state,
                    copy.deepcopy(entry["request"]),
                    copy.deepcopy(entry["response"]),
                    copy.deepcopy(entry["receipt"]),
                )
            later = FIXTURE["entries"][6]
            experiment._accept_model_exchange(
                state,
                copy.deepcopy(later["request"]),
                copy.deepcopy(later["response"]),
                copy.deepcopy(later["receipt"]),
                allow_out_of_order=True,
            )
            self.assertEqual(state["cost"], Decimal("0.015250"))
            self.assertEqual(state["receipts"][-1]["sequence"], 7)

            earlier = FIXTURE["entries"][5]
            experiment._accept_model_exchange(
                state,
                copy.deepcopy(earlier["request"]),
                copy.deepcopy(earlier["response"]),
                copy.deepcopy(earlier["receipt"]),
                allow_out_of_order=True,
            )
            self.assertEqual(
                [item["sequence"] for item in state["receipts"]], list(range(1, 8))
            )
            self.assertEqual(state["cost"], Decimal("0.018650"))

    def test_node_update_propagates_scheduler_restart_state(self):
        state = _exchange_state(Path("/unused"))
        fields = (
            "immutable_graph_sha256",
            "target_states",
            "preparation_defects",
            "invalidated_consumers",
            "block_chains",
            "file_owners",
            "release_events",
        )
        for index, field in enumerate(fields):
            state[field] = {"sentinel": index}

        update = experiment._node_update(state)

        self.assertEqual({field: update[field] for field in fields}, {
            field: state[field] for field in fields
        })

    def test_fixture_total_is_exact_and_duplicate_is_not_charged_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _exchange_state(Path(tmp))
            for entry in FIXTURE["entries"]:
                experiment._accept_model_exchange(
                    state,
                    copy.deepcopy(entry["request"]),
                    copy.deepcopy(entry["response"]),
                    copy.deepcopy(entry["receipt"]),
                )
            self.assertEqual(state["cost"], Decimal("0.022350"))

            entry = FIXTURE["entries"][-1]
            with self.assertRaisesRegex(experiment.ContractError, "duplicate"):
                experiment._accept_model_exchange(
                    state,
                    copy.deepcopy(entry["request"]),
                    copy.deepcopy(entry["response"]),
                    copy.deepcopy(entry["receipt"]),
                )
            self.assertEqual(state["cost"], Decimal("0.022350"))
            self.assertEqual(len(state["receipts"]), 8)

    def test_invalid_receipts_leave_cost_unchanged_and_record_rejection(self):
        mutations = {
            "cross-run": lambda receipt: receipt.__setitem__("run_id", "other-run"),
            "wrong-currency": lambda receipt: receipt["cost"].__setitem__(
                "currency", "EUR"
            ),
            "unauthenticated": lambda receipt: receipt["auth"].__setitem__(
                "signature", ""
            ),
            "conflicting-hash": lambda receipt: receipt.__setitem__(
                "response_sha256", "f" * 64
            ),
        }
        entry = ENTRIES["scout-001"]
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                state = _exchange_state(Path(tmp))
                receipt = copy.deepcopy(entry["receipt"])
                mutate(receipt)
                with self.assertRaises(experiment.ContractError):
                    experiment._accept_model_exchange(
                        state,
                        copy.deepcopy(entry["request"]),
                        copy.deepcopy(entry["response"]),
                        receipt,
                    )
                self.assertEqual(state["cost"], Decimal("0.000000"))
                self.assertEqual(state["receipts"], [])
                self.assertEqual(state["receipt_rejections"][-1]["request_id"], "scout-001")


if __name__ == "__main__":
    unittest.main()
