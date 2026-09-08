import copy
import hashlib
import json
import os
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import experiment, results, verifier, worker


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "diamond"


def _sha(value):
    raw = experiment.canonical_json_bytes(value)
    return hashlib.sha256(raw).hexdigest()


def _complete_attempt(root: Path, *, attempt_id: str = "attempt-complete"):
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
        "verdict": "PASS",
        "evidence_level": "L4",
        "checks": checks,
        "failures": [],
        "meaning": meaning,
        "native_decide_uses": [],
        "compiler_assumptions": assumptions,
    }
    report = {**report_body, "report_sha256": _sha(report_body)}
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
    run = {
        "attempt_id": attempt_id,
        "attempt_ledger": str(root.parent / "attempts.jsonl"),
        "run_id": "result-evidence-run",
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
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
        "proxy_policy_sha256": "8" * 64,
        "worker_inventory_sha256": "9" * 64,
        "worker_inventory": {"schema": "autofv-worker-inventory/v1"},
        "manifest": json.loads((TARGET / "autofv.json").read_text()),
        "lock": lock,
        "accepted": {
            "accepted_commit": "a" * 40,
            "accepted_tree_sha256": "b" * 64,
            "checks": ["configured_build"],
        },
        "export_receipt": {
            "manifest_sha256": "c" * 64,
            "scan_sha256": "d" * 64,
            "verified_before_disposal": True,
        },
        "disposal_receipt": {
            "disposal_sha256": "e" * 64,
            "worker_absent": True,
            "run_resources_absent": True,
        },
        "events": [
            "target_copied",
            "control_bundle_verified",
            "runsc_started",
            "scored_container_inspected",
            "targets_frozen",
            "fixed_proxy_policy_bound",
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
        "receipt_rejections": [],
        "cost": Decimal("0.010000"),
        "wall_seconds_used": Decimal("12.500000"),
        "finalization_reserve_seconds": Decimal("5.000000"),
        "verifier_report": report,
        "native_decide_uses": [],
    }
    return run, state


class ResultEvidenceTests(unittest.TestCase):
    def test_complete_l0_and_l4_are_required_for_a_recovery_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        self.assertEqual(
            {item["name"] for item in receipt["items"]},
            set(results.REQUIRED_L0_ITEMS),
        )
        self.assertTrue(receipt["complete"])
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


if __name__ == "__main__":
    unittest.main()
