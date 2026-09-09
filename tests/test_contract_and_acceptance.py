import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import diamond, experiment, results, verifier, worker
from tests.test_phase1_diamond import TARGET, _FixtureProxy, _Seams


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads(
    (ROOT / "tests/fixtures/model-proxy/diamond-responses.json").read_text()
)
ENTRIES = {
    entry["request"]["request_id"]: entry for entry in FIXTURE["entries"]
}
TOP = FIXTURE["statement_fingerprints"]["Diamond.top_spec"]
WEAK = ENTRIES["contract-left-001"]["response"]["payload"]["text_sha256"]
LEFT = FIXTURE["statement_fingerprints"]["Diamond.left_spec"]
RIGHT = FIXTURE["statement_fingerprints"]["Diamond.right_spec"]
POLICY = "b" * 64


def _state():
    return {
        "run": {
            "events": [],
            "accepted": {"accepted_commit": "a" * 40},
            "native_decide_policy_sha256": POLICY,
        },
        "receipts": [],
    }


def _responses():
    ordered = iter(
        ENTRIES[name]["response"]
        for name in (
            "contract-left-001",
            "contract-right-001",
            "contract-left-review-002",
        )
    )
    return lambda *args, **kwargs: (copy.deepcopy(next(ordered)), {})


def _feasibility(status, detail):
    return {
        "status": status,
        "reason": "consumer_proof_failed" if status == "failed" else None,
        "diagnostic_sha256": hashlib.sha256(detail.encode()).hexdigest(),
        "diagnostic": detail,
    }


class ContractRepairTests(unittest.TestCase):
    def test_weak_contract_fails_before_review_and_only_strong_records_freeze(self):
        state = _state()
        accepted_before = copy.deepcopy(state["run"]["accepted"])
        dependency = ENTRIES["dependency-plan-001"]["response"]

        with (
            mock.patch.object(diamond, "_model_request", side_effect=_responses()),
            mock.patch.object(
                worker,
                "check_contract_feasibility",
                create=True,
                side_effect=(
                    _feasibility("failed", "left equality is unavailable"),
                    _feasibility("passed", "consumer proof compiled"),
                ),
            ),
        ):
            contracts = experiment._repair_contracts(state, dependency, TOP)

        self.assertEqual(state["run"]["accepted"], accepted_before)
        self.assertEqual(contracts["provisional"], {})
        self.assertEqual(contracts["invalidated_fingerprints"], [WEAK])
        self.assertEqual(
            contracts["frozen_fingerprints"], sorted([LEFT, RIGHT, TOP])
        )
        self.assertNotEqual(
            contracts["attempts"][0]["canonical_sha256"],
            contracts["frozen"]["Diamond.left_spec"]["canonical_sha256"],
        )
        self.assertEqual(
            contracts["frozen"]["Diamond.left_spec"]["kind"], "theorem"
        )
        events = state["run"]["events"]
        expected = (
            "contract_draft:Diamond.left_spec",
            "provisional_consumer:failed",
            "contract_review:Diamond.left_spec",
            "provisional_consumer:passed",
            "statements_frozen",
        )
        positions = [
            next(i for i, event in enumerate(events) if event.startswith(prefix))
            for prefix in expected
        ]
        self.assertEqual(positions, sorted(positions))

    def test_exhausted_review_is_inconclusive_and_never_freezes_or_accepts(self):
        state = _state()
        accepted_before = copy.deepcopy(state["run"]["accepted"])
        dependency = ENTRIES["dependency-plan-001"]["response"]

        with (
            mock.patch.object(diamond, "_model_request", side_effect=_responses()),
            mock.patch.object(
                worker,
                "check_contract_feasibility",
                create=True,
                side_effect=(
                    _feasibility("failed", "weak bound"),
                    _feasibility("failed", "review still insufficient"),
                ),
            ),
            self.assertRaisesRegex(
                experiment.ContractInconclusive, "review still insufficient"
            ),
        ):
            experiment._repair_contracts(state, dependency, TOP)

        self.assertEqual(state["run"]["accepted"], accepted_before)
        self.assertNotIn("statements_frozen", state["run"]["events"])

    def test_inconclusive_run_persists_partial_evidence_without_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            seams = _Seams(Path(tmp), FIXTURE)
            proxy = _FixtureProxy(FIXTURE)
            checks = iter(
                (
                    _feasibility("failed", "weak bound"),
                    _feasibility("failed", "review still insufficient"),
                )
            )
            with (
                mock.patch.object(worker, "prepare_run", seams.prepare),
                mock.patch.object(worker, "run_probes", seams.run_probes),
                mock.patch.object(
                    worker,
                    "check_contract_feasibility",
                    side_effect=lambda *args: next(checks),
                ),
                mock.patch.object(worker, "accept_candidate") as accept,
                mock.patch.object(results, "persist_attempt", seams.persist),
                mock.patch.object(verifier, "verify_run") as verify,
            ):
                result = experiment.run_experiment(
                    TARGET, TARGET / "run.json", run_round=proxy
                )

            self.assertEqual(result["outcome"], "contract_inconclusive")
            self.assertEqual(result["termination_reason"], "contract_inconclusive")
            self.assertEqual(result["proxy_requests"], 5)
            self.assertEqual(result["cost_usd"], "0.012000")
            self.assertIn("contract_inconclusive", result["events"])
            self.assertTrue((Path(tmp) / "result.json").is_file())
            self.assertTrue((Path(tmp) / "evidence/l0.json").is_file())
            accept.assert_not_called()
            verify.assert_not_called()

    def test_old_fingerprint_or_policy_cannot_bind_candidate_work(self):
        current = sorted([LEFT, RIGHT, TOP])
        self.assertTrue(
            experiment._candidate_binding_is_current([LEFT], POLICY, current, POLICY)
        )
        self.assertFalse(
            experiment._candidate_binding_is_current([WEAK], POLICY, current, POLICY)
        )
        self.assertFalse(
            experiment._candidate_binding_is_current([LEFT], "c" * 64, current, POLICY)
        )


if __name__ == "__main__":
    unittest.main()
