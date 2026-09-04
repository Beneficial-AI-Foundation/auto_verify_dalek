import copy
import json
import tempfile
import threading
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import experiment, probes, worker
from tests.test_model_proxy_fixture import _FixtureProgram
from tests.test_phase1_diamond import AENEAS_PROBE, MODEL_FIXTURE, RUST_PROBE, TARGET


FIXTURE = json.loads(MODEL_FIXTURE.read_text())
ENTRIES = {
    entry["request"]["request_id"]: entry for entry in FIXTURE["entries"]
}
LEFT = "probe:Diamond.left"
RIGHT = "probe:Diamond.right"
TOP = "probe:Diamond.top"
POLICY = experiment.load_toolchain_lock()["native_decide_policy_sha256"]


def _graph():
    return probes.parse_probe_bytes(
        json.loads((TARGET / "autofv.json").read_text()),
        RUST_PROBE.read_bytes(),
        AENEAS_PROBE.read_bytes(),
    )


def _state(run_round=None):
    first_five = [copy.deepcopy(entry["receipt"]) for entry in FIXTURE["entries"][:5]]
    return {
        "run": {
            "run_id": FIXTURE["run_id"],
            "base_commit": FIXTURE["git"]["base_commit"],
            "native_decide_policy_sha256": POLICY,
            "events": [],
            "accepted": {"accepted_commit": FIXTURE["git"]["base_commit"]},
        },
        "config": {
            "model": FIXTURE["model_id"],
            "max_cost_usd": Decimal("1.000000"),
        },
        "run_round": run_round,
        "receipts": first_five,
        "cost": sum(
            (Decimal(item["cost"]["amount"]) for item in first_five),
            Decimal("0.000000"),
        ),
        "contracts": {
            "frozen_fingerprints": sorted(FIXTURE["statement_fingerprints"].values())
        },
        "processed_candidate_sha256": [],
        "accepted_sequence": [],
        "accepted_nodes": [],
        "candidate_receipts": [],
    }


class ParallelLaneTests(unittest.TestCase):
    def test_leaf_proxy_rounds_overlap_but_receipts_commit_in_sequence(self):
        program = _FixtureProgram(FIXTURE, threading.Barrier(2))
        for entry in FIXTURE["entries"][:5]:
            program.invoke(entry["request"])
        state = _state(program.invoke)

        exchanges = experiment._parallel_model_requests(
            state,
            [
                {
                    "request_id": "proof-left-001",
                    "role": "proof-author",
                    "batch_id": "proof-leaves-001",
                    "input_hashes": ENTRIES["proof-left-001"]["request"]["input_hashes"],
                },
                {
                    "request_id": "proof-right-001",
                    "role": "proof-author",
                    "batch_id": "proof-leaves-001",
                    "input_hashes": ENTRIES["proof-right-001"]["request"]["input_hashes"],
                },
            ],
        )

        self.assertEqual(
            [response["request_id"] for response, _ in exchanges],
            ["proof-left-001", "proof-right-001"],
        )
        self.assertEqual(
            [item["request_id"] for item in state["receipts"][-2:]],
            ["proof-left-001", "proof-right-001"],
        )
        left = program.intervals["proof-left-001"]
        right = program.intervals["proof-right-001"]
        self.assertLess(max(left[0], right[0]), min(left[1], right[1]))
        self.assertEqual(
            state["run"]["events"][-3:],
            ["proxy:proof-left-001", "proxy:proof-right-001", "proof_lanes:overlapped"],
        )

    def test_leaf_lanes_share_a_base_but_no_mutable_path(self):
        run = {
            "base_commit": FIXTURE["git"]["base_commit"],
            "project_dir": "/volume/work/project",
        }
        lanes = experiment._lane_descriptors(run, _graph(), [LEFT, RIGHT])

        self.assertEqual({lane["base_commit"] for lane in lanes}, {run["base_commit"]})
        self.assertEqual(
            {lane["assigned_path"] for lane in lanes},
            {"Diamond/Left.lean", "Diamond/Right.lean"},
        )
        for field in ("worktree_path", "cache_path", "result_path"):
            values = [lane[field] for lane in lanes]
            self.assertEqual(len(values), len(set(values)))
            self.assertTrue(all(value.startswith("/volume/lanes/") for value in values))

    def test_checkpoint_is_serial_idempotent_and_reverifies_stale_work(self):
        state = _state()
        lanes = experiment._lane_descriptors(state["run"], _graph(), [LEFT, RIGHT])
        candidates = [
            experiment._candidate_record(
                copy.deepcopy(ENTRIES[lane["request_id"]]["response"]), lane, POLICY
            )
            for lane in lanes
        ]
        active = 0
        maximum = 0
        commits = iter(("1" * 40, "2" * 40))

        def accept(run, response, manifest):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            active -= 1
            return {
                "accepted_commit": next(commits),
                "accepted_tree_sha256": "a" * 64,
                "checks": ["configured_build"],
            }

        with mock.patch.object(worker, "accept_candidate", side_effect=accept) as called:
            first = experiment._checkpoint_candidate(state, candidates[0], {})
            second = experiment._checkpoint_candidate(state, candidates[1], {})
            replay = experiment._checkpoint_candidate(state, candidates[1], {})

        self.assertEqual(first["status"], "accepted")
        self.assertEqual(second["status"], "accepted_reverified")
        self.assertEqual(replay["status"], "duplicate")
        self.assertEqual(maximum, 1)
        self.assertEqual(called.call_count, 2)
        self.assertEqual(len(state["accepted_sequence"]), 2)
        self.assertEqual(state["accepted"]["accepted_commit"], "2" * 40)
        self.assertEqual(set(state["accepted_nodes"]), {LEFT, RIGHT})

    def test_scope_policy_and_stale_integration_fail_without_advancing(self):
        state = _state()
        lanes = experiment._lane_descriptors(state["run"], _graph(), [LEFT, RIGHT])
        accepted_before = copy.deepcopy(state["accepted"])

        with self.assertRaises(experiment.ContractError):
            experiment._candidate_record(
                copy.deepcopy(ENTRIES["proof-left-001"]["response"]), lanes[1], POLICY
            )

        wrong_policy = experiment._candidate_record(
            copy.deepcopy(ENTRIES["proof-left-001"]["response"]),
            lanes[0],
            "c" * 64,
        )
        with mock.patch.object(worker, "accept_candidate") as accept:
            rejected = experiment._checkpoint_candidate(state, wrong_policy, {})
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["reason"], "candidate_policy_mismatch")
        self.assertEqual(state["accepted"], accepted_before)
        accept.assert_not_called()

        good = experiment._candidate_record(
            copy.deepcopy(ENTRIES["proof-left-001"]["response"]), lanes[0], POLICY
        )
        state["accepted"] = {"accepted_commit": "9" * 40}
        with mock.patch.object(
            worker, "accept_candidate", side_effect=worker.WorkerError("patch no longer applies")
        ):
            requeue = experiment._checkpoint_candidate(state, good, {})
        self.assertEqual(requeue["status"], "requeue")
        self.assertEqual(state["accepted"], {"accepted_commit": "9" * 40})

    def test_top_waits_for_both_term_dependencies(self):
        graph = _graph()

        self.assertEqual(experiment._proof_ready_nodes(graph, set()), [LEFT, RIGHT])
        self.assertEqual(experiment._proof_ready_nodes(graph, {LEFT}), [RIGHT])
        self.assertEqual(experiment._proof_ready_nodes(graph, {LEFT, RIGHT}), [TOP])


if __name__ == "__main__":
    unittest.main()
