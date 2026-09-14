import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import evidence, experiment, results, verifier, worker


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "diamond"


def _sha(value):
    raw = experiment.canonical_json_bytes(value)
    return hashlib.sha256(raw).hexdigest()


def _receipt(body, digest_field):
    return {**body, digest_field: _sha(body)}


def _complete_attempt(root: Path, *, attempt_id: str = "attempt-complete"):
    run_id = "result-evidence-run"
    lock = experiment.load_toolchain_lock()
    assumptions = verifier.compiler_assumptions(lock)
    checks = {
        name: True
        for name in (
            "bundle",
            "reference_integrity",
            "exact_commit",
            "exact_tree",
            "fresh_cache",
            "clean_build",
            "target_closure",
            "statements",
            "scope",
            "holes",
            "trust",
            "native_decide",
            "meaning",
        )
    }
    meaning = {
        "reference_integrity": True,
        "statement_equivalence": True,
        "non_vacuity": True,
        "broken_implementation_rejected": True,
    }
    report_body = {
        "schema": "autofv-verifier-report/v1",
        "run_id": run_id,
        "accepted_commit": "a" * 40,
        "accepted_tree_sha256": "b" * 64,
        "verdict": "PASS",
        "evidence_level": "L4",
        "checks": checks,
        "failures": [],
        "meaning": meaning,
        "sorry_count_before": 1,
        "sorry_count_after": 0,
        "native_decide_uses": [],
        "compiler_assumptions": assumptions,
    }
    report = _receipt(report_body, "report_sha256")
    graph = {
        "frozen_targets": ["probe:Diamond.top"],
        "supplied_specs": {"probe:Diamond.top": "probe:Diamond.top_spec"},
        "selected_nodes": [
            "probe:Diamond.left",
            "probe:Diamond.right",
            "probe:Diamond.top",
        ],
        "probe_rust_sha256": "1" * 64,
        "probe_aeneas_sha256": "2" * 64,
        "graph_sha256": "3" * 64,
    }
    worker_inventory = _receipt(
        {
            "schema": "autofv-worker-inventory/v1",
            "run_id": run_id,
            "platform": "linux",
        },
        "inventory_sha256",
    )
    scored_container = _receipt(
        {
            "schema": "autofv-scored-container/v1",
            "run_id": run_id,
            "volume": "fixture-volume",
            "runtime": "runsc-hardened",
        },
        "inspection_sha256",
    )
    proxy_policy = _receipt(
        {
            "schema": "autofv-fixed-proxy-policy/v1",
            "run_id": run_id,
            "route_id": "fixed-inference-v1",
        },
        "policy_sha256",
    )
    upstream_policy = _receipt(
        {
            "schema": "autofv-upstream-egress-policy/v1",
            "run_id": run_id,
            "enforcer": "macos-seatbelt-network-outbound",
        },
        "policy_sha256",
    )
    upstream_policy_sha256 = upstream_policy["policy_sha256"]
    egress_policy = _receipt(
        {
            "schema": "autofv-egress-policy/v1",
            "enforcer": evidence.NETWORK_ENFORCER,
            "upstream_policy_sha256": upstream_policy_sha256,
        },
        "policy_sha256",
    )
    egress = _receipt(
        {
            "schema": "autofv-egress-evidence/v1",
            "run_id": run_id,
            "policy": egress_policy,
            "upstream_policy": upstream_policy,
            "fixed_proxy_sha256": "7" * 64,
            "proxy_policy_sha256": proxy_policy["policy_sha256"],
            "upstream_denied": [],
            "worker_denied": [],
            "container_denied": [],
            "fixed_proxy": {"status": "ok"},
        },
        "evidence_sha256",
    )
    artifact_scan = _receipt(
        {
            "schema": "autofv-retained-state-scan/v1",
            "run_id": run_id,
            "clean": True,
        },
        "scan_sha256",
    )
    export_receipt = _receipt(
        {
            "schema": "autofv-export/v1",
            "run_id": run_id,
            "scan_sha256": artifact_scan["scan_sha256"],
            "verified_before_disposal": True,
        },
        "manifest_sha256",
    )
    disposal_receipt = _receipt(
        {
            "schema": "autofv-disposal/v1",
            "run_id": run_id,
            "export_manifest_sha256": export_receipt["manifest_sha256"],
            "worker_absent": True,
            "run_resources_absent": True,
        },
        "disposal_sha256",
    )
    run = {
        "attempt_id": attempt_id,
        "attempt_ledger": str(root.parent / "attempts.jsonl"),
        "run_id": run_id,
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
        "volume": "fixture-volume",
        "execution_tier": "sealed_runsc",
        "cost_classification": "synthetic_fixture",
        "agent_worker_id": "lima:agent:aaa",
        "snapshot_sha256": "4" * 64,
        "manifest_sha256": "5" * 64,
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": "6" * 64,
        "native_decide_policy": "allow_audited",
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "fixed_proxy_sha256": "7" * 64,
        "proxy_policy_sha256": proxy_policy["policy_sha256"],
        "proxy_policy_receipt": proxy_policy,
        "upstream_policy_sha256": upstream_policy_sha256,
        "egress_policy_sha256": egress_policy["policy_sha256"],
        "egress_receipt": egress,
        "worker_inventory_sha256": worker_inventory["inventory_sha256"],
        "worker_inventory": worker_inventory,
        "scored_container_receipt": scored_container,
        "manifest": json.loads((TARGET / "autofv.json").read_text()),
        "lock": lock,
        "accepted": {
            "accepted_commit": "a" * 40,
            "accepted_tree_sha256": "b" * 64,
            "checks": ["configured_build"],
        },
        "artifact_scan_receipt": artifact_scan,
        "export_receipt": export_receipt,
        "disposal_receipt": disposal_receipt,
        "events": [
            "target_copied",
            "control_bundle_verified",
            "runsc_started",
            "scored_container_inspected",
            "targets_frozen",
            "fixed_proxy_policy_bound",
            "egress_matrix_passed",
            "proxy:proof-left-001",
            "candidate_accepted:proof-left-001",
            "clean_verifier:PASS",
            "artifacts_exported",
            "worker_disposed",
        ],
    }
    state = {
        "run": run,
        "manifest": run["manifest"],
        "config": {
            "model": "fixture-model-v1",
            "max_wall_seconds": 300,
            "max_cost_usd": Decimal("1.000000"),
        },
        "graph": graph,
        "contracts": {
            "frozen": {
                "Diamond.left_spec": {"status": "frozen"},
                "Diamond.right_spec": {"status": "frozen"},
            }
        },
        "accepted": run["accepted"],
        "accepted_nodes": graph["selected_nodes"],
        "candidate_receipts": [{"status": "accepted"}],
        "accepted_sequence": [{"sequence": 1}],
        "receipts": [
            {
                "receipt_sha256": "f" * 64,
                "usage": {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14},
                "cost": {"amount": "0.010000", "currency": "USD"},
            }
        ],
        "model_exchanges": {
            "proof-left-001": {
                "request": {
                    "request_id": "proof-left-001",
                    "prompt_sha256": "c" * 64,
                }
            }
        },
        "receipt_rejections": [],
        "cost": Decimal("0.010000"),
        "wall_seconds_used": Decimal("12.500000"),
        "finalization_reserve_seconds": Decimal("5.000000"),
        "verifier_report": report,
        "native_decide_uses": [],
    }
    files = {
        "evidence/worker-inventory.json": worker_inventory,
        "evidence/scored-container.json": scored_container,
        "evidence/fixed-proxy-policy.json": proxy_policy,
        "evidence/egress.json": egress,
        "export/artifact-scan.json": artifact_scan,
        "evidence/verifier.json": report,
        "export/manifest.json": export_receipt,
        "disposal.json": disposal_receipt,
    }
    for relative, value in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(experiment.canonical_json_bytes(value) + b"\n")
    results.persist_l0_sources(run, state)
    return run, state


class ResultEvidenceTests(unittest.TestCase):
    def test_complete_l0_and_l4_are_required_for_a_recovery_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            linked = {
                item["name"]: item
                for item in receipt["items"]
                if item["location"] is not None
            }
            for item in linked.values():
                raw = (Path(run["run_root"]) / item["location"]).read_bytes()
                self.assertEqual(
                    item["sha256"], hashlib.sha256(raw).hexdigest()
                )
                self.assertEqual(item["size"], len(raw))

        self.assertEqual(
            {item["name"] for item in receipt["items"]},
            set(results.REQUIRED_L0_ITEMS),
        )
        self.assertTrue(receipt["complete"])
        self.assertEqual(
            set(linked),
            set(results.REQUIRED_L0_ITEMS),
        )
        self.assertEqual(result["evidence_level"], "L4")
        self.assertTrue(result["scored"])
        self.assertEqual(result["missing_evidence"], [])
        self.assertEqual(result["claim"]["status"], "supported")
        self.assertEqual(
            result["claim"]["recovered_specifications"],
            ["Diamond.left_spec", "Diamond.right_spec"],
        )
        self.assertEqual(result["native_decide_policy"], "allow_audited")
        self.assertEqual(result["native_decide_uses"], [])
        self.assertEqual(
            result["sets"],
            {
                "T": {"ids": ["probe:Diamond.top"], "size": 1},
                "S": {"ids": ["probe:Diamond.top"], "size": 1},
                "W": {"ids": [], "size": 0},
                "recovered_internal_specs": {
                    "ids": ["Diamond.left_spec", "Diamond.right_spec"],
                    "size": 2,
                },
            },
        )
        self.assertEqual(result["model_attempts"], 1)
        self.assertEqual(result["model_retries"], 0)
        self.assertEqual(result["prompt_sha256"], ["c" * 64])
        self.assertEqual(result["sorry_counts"], {"before": 1, "after": 0})
        self.assertEqual(result["accepted_commit"], "a" * 40)
        self.assertEqual(result["accepted_tree_sha256"], "b" * 64)
        self.assertEqual(
            result["toolchain_lock_sha256"],
            _sha(state["run"]["lock"]),
        )
        self.assertEqual(
            result["compiler_assumptions"],
            state["verifier_report"]["compiler_assumptions"],
        )
        self.assertIn("cryptographic_security", result["exclusions"])
        self.assertEqual(results.validate_l0(receipt), receipt)

    def test_missing_or_incomplete_evidence_is_unscored_and_withholds_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            _, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
        damaged = copy.deepcopy(receipt)
        damaged["items"] = [
            item for item in damaged["items"] if item["name"] != "disposal"
        ]
        assessment = results.assess_evidence(damaged, state["verifier_report"])
        claim = results.render_claim(
            assessment,
            run,
            state,
            outcome="success",
        )

        self.assertIsNone(assessment["level"])
        self.assertFalse(assessment["scored"])
        self.assertIn("disposal", assessment["missing"])
        self.assertEqual(claim["status"], "withheld")
        self.assertEqual(claim["recovered_specifications"], [])

    def test_file_backed_evidence_does_not_fall_back_through_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            verifier_path = Path(run["run_root"]) / "evidence/verifier.json"
            outside = Path(tmp) / "outside-verifier.json"
            outside.write_bytes(verifier_path.read_bytes())
            verifier_path.unlink()
            verifier_path.symlink_to(outside)

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        item = next(
            item for item in receipt["items"] if item["name"] == "verifier"
        )
        self.assertEqual(item["status"], "missing")
        self.assertEqual(item["location"], "evidence/verifier.json")
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_verifier_file_must_match_the_report_that_is_graded(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            (Path(run["run_root"]) / "evidence/verifier.json").write_text("{}\n")

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        item = next(
            item for item in receipt["items"] if item["name"] == "verifier"
        )
        self.assertEqual(item["status"], "missing")
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_proxy_policy_without_upstream_egress_evidence_is_unscored(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            run.pop("egress_receipt")

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        network = next(
            item for item in receipt["items"] if item["name"] == "network"
        )
        self.assertEqual(network["status"], "missing")
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_result_identities_are_derived_from_bound_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            run["worker_inventory_sha256"] = "0" * 64
            run["egress_policy_sha256"] = "9" * 64

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        missing = {
            item["name"]
            for item in receipt["items"]
            if item["status"] == "missing"
        }
        self.assertEqual(missing, {"runtime", "network"})
        self.assertIsNone(result["worker_inventory_sha256"])
        self.assertIsNone(result["egress_policy_sha256"])
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_l3_and_conflicting_duplicate_evidence_withhold_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            lower = copy.deepcopy(state["verifier_report"])
            lower["evidence_level"] = "L3"
            lower["checks"]["meaning"] = False
            lower["meaning"] = {}
            lower.pop("report_sha256")
            lower = _receipt(lower, "report_sha256")
            state["verifier_report"] = lower
            root = Path(run["run_root"])
            (root / "evidence/verifier.json").write_bytes(
                experiment.canonical_json_bytes(lower) + b"\n"
            )
            (root / "evidence/l0/replay.json").write_bytes(
                experiment.canonical_json_bytes(lower) + b"\n"
            )
            build = {
                "accepted_checks": run["accepted"]["checks"],
                "verifier_checks": lower["checks"],
            }
            (root / "evidence/l0/build.json").write_bytes(
                experiment.canonical_json_bytes(build) + b"\n"
            )

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            identical = copy.deepcopy(receipt)
            identical["items"].append(copy.deepcopy(identical["items"][0]))
            identical.pop("receipt_sha256")
            identical = _receipt(identical, "receipt_sha256")
            identical_assessment = results.assess_evidence(identical, lower)
            conflicting = copy.deepcopy(identical)
            conflicting["items"][-1]["sha256"] = "0" * 64
            conflicting.pop("receipt_sha256")
            conflicting = _receipt(conflicting, "receipt_sha256")
            conflicting_assessment = results.assess_evidence(conflicting, lower)

        self.assertEqual(result["evidence_level"], "L3")
        self.assertEqual(result["claim"]["status"], "withheld")
        self.assertEqual(identical_assessment["level"], "L3")
        self.assertFalse(conflicting_assessment["scored"])
        self.assertIn("input", conflicting_assessment["missing"])

    def test_attempt_ledger_appends_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            first_run, first_state = _complete_attempt(
                base / "first", attempt_id="attempt-first"
            )
            first, first_l0 = results.render_attempt(
                first_run,
                first_state,
                outcome="verification_failed",
                reason="clean_verifier_failed",
            )
            results.persist_attempt(first_run, first, first_l0)

            second_run, second_state = _complete_attempt(
                base / "second", attempt_id="attempt-second"
            )
            second, second_l0 = results.render_attempt(
                second_run,
                second_state,
                outcome="success",
                reason="all_targets_verified",
            )
            results.persist_attempt(second_run, second, second_l0)

            ledger = Path(first_run["attempt_ledger"])
            records = [json.loads(line) for line in ledger.read_text().splitlines()]
            self.assertEqual(
                [record["attempt_id"] for record in records],
                ["attempt-first", "attempt-second"],
            )
            replaced = {**first, "termination_reason": "rewritten"}
            with self.assertRaises(results.ResultError):
                results.persist_attempt(first_run, replaced, first_l0)
            self.assertEqual(len(ledger.read_text().splitlines()), 2)

    def test_final_result_and_l0_are_scanned_before_the_attempt_is_appended(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            state["termination_detail"] = "synthetic-final-result-secret"
            run["artifact_scan_markers"] = ["synthetic-final-result-secret"]
            result, receipt = results.render_attempt(
                run,
                state,
                outcome="infrastructure_failed",
                reason="controller_failed",
            )

            with self.assertRaisesRegex(
                worker.WorkerError, "forbidden material"
            ):
                results.persist_attempt(run, result, receipt)

            self.assertFalse(Path(run["run_root"], "result.json").exists())
            self.assertFalse(Path(run["attempt_ledger"]).exists())

    def test_invalid_config_is_persisted_before_worker_allocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / "run.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "autofv-run/v1",
                        "model": "fixture-model-v1",
                        "max_wall_seconds": 60,
                        "max_cost_usd": 1,
                        "unexpected": True,
                    }
                )
            )
            ledger = base / "attempts.jsonl"
            with (
                mock.patch.dict(os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}),
                mock.patch.object(worker, "prepare_run") as prepare,
            ):
                result = experiment.run_experiment(TARGET, config)

            prepare.assert_not_called()
            self.assertEqual(result["outcome"], "invalid_config")
            self.assertEqual(result["termination_reason"], "run_config_invalid")
            run_root = Path(result["run_root"])
            self.assertTrue((run_root / "result.json").is_file())
            self.assertTrue((run_root / "evidence" / "l0.json").is_file())
            self.assertEqual(len(ledger.read_text().splitlines()), 1)
            self.assertFalse(result["scored"])

    def test_invalid_ledger_and_preparation_interrupt_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fallback = base / "fallback.jsonl"
            with (
                mock.patch.object(results, "DEFAULT_ATTEMPT_LEDGER", fallback),
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": "relative.jsonl"}
                ),
                mock.patch.object(worker, "prepare_run") as prepare,
            ):
                invalid = experiment.run_experiment(TARGET, TARGET / "run.json")
            prepare.assert_not_called()
            self.assertEqual(invalid["outcome"], "invalid_config")
            self.assertEqual(
                invalid["termination_reason"], "attempt_ledger_invalid"
            )
            self.assertEqual(len(fallback.read_text().splitlines()), 1)

            ledger = base / "interrupts.jsonl"
            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(
                    worker, "prepare_run", side_effect=KeyboardInterrupt
                ),
            ):
                interrupted = experiment.run_experiment(
                    TARGET, TARGET / "run.json"
                )
            self.assertEqual(interrupted["outcome"], "infrastructure_failed")
            self.assertEqual(interrupted["termination_reason"], "interrupted")
            self.assertEqual(len(ledger.read_text().splitlines()), 1)

    def test_invalid_target_has_explicit_empty_counts_and_identities(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(worker, "prepare_run") as prepare,
            ):
                result = experiment.run_experiment(
                    base / "missing-target", TARGET / "run.json"
                )

            prepare.assert_not_called()
            self.assertEqual(result["outcome"], "invalid_target")
            self.assertEqual(result["termination_reason"], "target_invalid")
            self.assertEqual(result["targets_total"], 0)
            self.assertEqual(result["internal_specs_accepted"], 0)
            self.assertEqual(result["internal_proofs_accepted"], 0)
            self.assertIsNone(result["snapshot_sha256"])
            self.assertIsNone(result["accepted_commit"])
            self.assertEqual(result["native_decide_uses"], [])
            self.assertFalse(result["scored"])
            self.assertEqual(len(ledger.read_text().splitlines()), 1)

    def test_terminal_checkpoint_failure_still_persists_a_typed_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = {
                "attempt_id": "attempt-finalization",
                "attempt_ledger": str(root / "attempts.jsonl"),
                "run_id": "finalization-run",
                "run_root": str(root),
                "evidence_dir": str(root / "evidence"),
                "execution_tier": "simulation",
                "cost_classification": "synthetic_fixture",
                "events": [],
            }
            state = {
                "run": run,
                "config": {},
                "receipts": [],
                "checkpoint_enabled": True,
            }
            with (
                mock.patch.object(
                    experiment,
                    "_checkpoint_if_enabled",
                    side_effect=(None, OSError("checkpoint unavailable")),
                ),
                mock.patch.object(results, "persist_attempt") as persist,
            ):
                result = experiment._finish_attempt(
                    run,
                    state,
                    outcome="success",
                    reason="all_targets_verified",
                )

            self.assertEqual(result["outcome"], "infrastructure_failed")
            self.assertEqual(result["termination_reason"], "finalization_failed")
            persist.assert_called_once()

    def test_unrecoverable_final_renderer_failure_gets_an_emergency_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            prepared = {
                "run_id": "renderer-failure-run",
                "run_root": str(base / "original"),
                "evidence_dir": str(base / "original" / "evidence"),
                "execution_tier": "simulation",
                "cost_classification": "synthetic_fixture",
                "events": ["validated"],
            }
            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH, "stream", return_value=[]
                ),
                mock.patch.object(
                    experiment,
                    "_finish_attempt",
                    side_effect=results.ResultError("renderer failed"),
                ),
            ):
                result = experiment.run_experiment(TARGET, TARGET / "run.json")

            self.assertEqual(result["outcome"], "infrastructure_failed")
            self.assertEqual(result["termination_reason"], "finalization_failed")
            self.assertIn("renderer failed", result["termination_detail"])
            self.assertTrue(Path(result["run_root"], "result.json").is_file())
            self.assertEqual(len(ledger.read_text().splitlines()), 1)

    def test_durable_finalization_failure_reuses_the_allocated_attempt_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            staging = base / "staging"
            (staging / "evidence").mkdir(parents=True)
            prepared = {
                "run_id": "durable-renderer-failure-run",
                "run_root": str(staging),
                "evidence_dir": str(staging / "evidence"),
                "execution_tier": "simulation",
                "cost_classification": "synthetic_fixture",
                "events": ["validated"],
            }
            allocated_roots = []

            class FixedDatetime:
                @classmethod
                def now(cls, tz):
                    return datetime(2026, 9, 14, tzinfo=timezone.utc)

            def fail_finalization(run, *_args, **_kwargs):
                allocated_roots.append(Path(run["run_root"]))
                raise results.ResultError("renderer failed")

            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(results, "datetime", FixedDatetime),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH, "stream", return_value=[]
                ),
                mock.patch.object(
                    experiment, "_finish_attempt", side_effect=fail_finalization
                ),
            ):
                try:
                    result = experiment.run_experiment(
                        TARGET,
                        TARGET / "run.json",
                        output_root=base / "attempts",
                    )
                except results.ResultError as exc:
                    self.fail(
                        "emergency result was not persisted in the allocated "
                        f"attempt root: {exc}"
                    )

            self.assertEqual(result["termination_reason"], "finalization_failed")
            self.assertEqual(Path(result["run_root"]), allocated_roots[0])
            self.assertTrue((allocated_roots[0] / "result.json").is_file())

    def test_durable_binding_failure_force_destroys_the_prepared_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            staging = base / "staging"
            (staging / "evidence").mkdir(parents=True)
            prepared = {
                "run_id": "binding-failure-run",
                "run_root": str(staging),
                "evidence_dir": str(staging / "evidence"),
                "volume": "autofv-binding-failure",
                "execution_tier": "sealed_runsc",
                "cost_classification": "provider_backed",
                "events": ["validated"],
            }
            moments = iter(
                (
                    datetime(2026, 9, 14, 0, 0, 0, tzinfo=timezone.utc),
                    datetime(2026, 9, 14, 0, 0, 1, tzinfo=timezone.utc),
                )
            )

            class AdvancingDatetime:
                @classmethod
                def now(cls, tz):
                    return next(moments)

            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(results, "datetime", AdvancingDatetime),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    results,
                    "bind_prepared_run",
                    side_effect=results.ResultError("binding failed"),
                ),
                mock.patch.object(worker, "force_destroy_worker") as destroy,
            ):
                result = experiment.run_experiment(
                    TARGET,
                    TARGET / "run.json",
                    output_root=base / "attempts",
                )

            self.assertEqual(result["termination_reason"], "attempt_allocation_failed")
            destroy.assert_called_once_with(prepared)
            attempt_roots = [path.resolve() for path in (base / "attempts").iterdir()]
            self.assertEqual(attempt_roots, [Path(result["run_root"]).resolve()])

    def test_durable_binding_removes_the_worker_staging_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            staging = base / "staging"
            (staging / "evidence").mkdir(parents=True)
            prepared = {
                "run_id": "successful-binding-run",
                "run_root": str(staging),
                "evidence_dir": str(staging / "evidence"),
                "volume": "autofv-successful-binding",
                "execution_tier": "sealed_runsc",
                "cost_classification": "provider_backed",
                "base_commit": "a" * 40,
                "egress_receipt": {"status": "allowed"},
                "events": ["validated"],
            }

            def finish_without_worker_calls(run, *_args, **_kwargs):
                return {"outcome": "success", "run_root": run["run_root"]}

            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH, "stream", return_value=[]
                ),
                mock.patch.object(
                    experiment,
                    "_finish_attempt",
                    side_effect=finish_without_worker_calls,
                ),
            ):
                result = experiment.run_experiment(
                    TARGET,
                    TARGET / "run.json",
                    output_root=base / "attempts",
                )

            self.assertEqual(result["outcome"], "success")
            self.assertNotEqual(Path(result["run_root"]), staging)
            self.assertFalse(staging.exists())


if __name__ == "__main__":
    unittest.main()
