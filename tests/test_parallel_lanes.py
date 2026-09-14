import copy
import json
import tempfile
import threading
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import diamond, experiment, probes, worker
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


def _event_graph(*, same_file=False):
    nodes = ["fast", "middle", "root", "slow"]
    return {
        "selected_nodes": nodes,
        "term_dependencies": [
            ["middle", "fast"],
            ["root", "middle"],
            ["root", "slow"],
        ],
        "source_paths": {
            node: "Graph/Shared.lean" if same_file else f"Graph/{node}.lean"
            for node in nodes
        },
    }


def _graph():
    return probes.parse_probe_bytes(
        json.loads((TARGET / "autofv.json").read_text()),
        RUST_PROBE.read_bytes(),
        AENEAS_PROBE.read_bytes(),
    )


def _state(run_round=None):
    first_five = [copy.deepcopy(entry["receipt"]) for entry in FIXTURE["entries"][:5]]
    accepted = {"accepted_commit": FIXTURE["git"]["base_commit"]}
    return {
        "run": {
            "run_id": FIXTURE["run_id"],
            "base_commit": FIXTURE["git"]["base_commit"],
            "native_decide_policy_sha256": POLICY,
            "events": [],
            "accepted": copy.deepcopy(accepted),
        },
        "accepted": accepted,
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
    def test_newly_ready_consumer_starts_while_slow_lane_is_running(self):
        slow_started = threading.Event()
        middle_started = threading.Event()

        def run(node):
            if node == "slow":
                slow_started.set()
                self.assertTrue(middle_started.wait(1))
            elif node == "fast":
                self.assertTrue(slow_started.wait(1))
            elif node == "middle":
                middle_started.set()
            return node

        accepted = getattr(diamond, "_schedule_proofs", lambda *_: set())(
            _event_graph(), run, lambda *_: None
        )

        self.assertEqual(accepted, {"fast", "middle", "root", "slow"})

    def test_ready_jobs_in_one_file_never_overlap(self):
        graph = {
            "selected_nodes": ["left", "right", "root"],
            "term_dependencies": [["root", "left"], ["root", "right"]],
            "source_paths": {
                "left": "Graph/Shared.lean",
                "right": "Graph/Shared.lean",
                "root": "Graph/Root.lean",
            },
        }
        left_started = threading.Event()
        right_started = threading.Event()
        release_left = threading.Event()
        finished = threading.Event()

        def run(node):
            if node == "left":
                left_started.set()
                self.assertTrue(release_left.wait(1))
            elif node == "right":
                right_started.set()
            return node

        def schedule():
            scheduler = getattr(diamond, "_schedule_proofs", lambda *_: set())
            scheduler(graph, run, lambda *_: None)
            finished.set()

        thread = threading.Thread(target=schedule)
        thread.start()
        self.assertTrue(left_started.wait(1))
        self.assertFalse(right_started.is_set())
        release_left.set()
        self.assertTrue(finished.wait(1))
        thread.join()

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

    def test_undeclared_candidate_is_retained_as_a_preparation_defect(self):
        state = _state()
        state["graph"] = _graph()
        lane = experiment._lane_descriptors(state["run"], state["graph"], [LEFT])[0]
        candidate = experiment._candidate_record(
            copy.deepcopy(ENTRIES["proof-left-001"]["response"]), lane, POLICY
        )
        candidate["node"] = "probe:Unknown.local"
        body = {
            key: value
            for key, value in candidate.items()
            if key not in {"candidate_sha256", "response"}
        }
        candidate["candidate_sha256"] = experiment._canonical_sha256(body)

        with mock.patch.object(
            worker,
            "accept_candidate",
            return_value={
                "accepted_commit": "1" * 40,
                "accepted_tree_sha256": "2" * 64,
                "checks": ["configured_build"],
            },
        ) as accept:
            rejected = experiment._checkpoint_candidate(state, candidate, {})

        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["reason"], "preparation_defect_undeclared_node")
        self.assertEqual(state["preparation_defects"][0]["node"], candidate["node"])
        accept.assert_not_called()

    def test_top_waits_for_both_term_dependencies(self):
        graph = _graph()

        self.assertEqual(experiment._proof_ready_nodes(graph, set()), [LEFT, RIGHT])
        self.assertEqual(experiment._proof_ready_nodes(graph, {LEFT}), [RIGHT])
        self.assertEqual(experiment._proof_ready_nodes(graph, {LEFT, RIGHT}), [TOP])


if __name__ == "__main__":
    unittest.main()
