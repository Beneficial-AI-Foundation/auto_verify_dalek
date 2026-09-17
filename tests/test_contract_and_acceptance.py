import copy
import hashlib
import json
import tempfile
import threading
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

ROOT = "probe:Graph.root"
LEFT_NODE = "probe:Graph.left"
RIGHT_NODE = "probe:Graph.right"
SHARED = "probe:Graph.shared"
OTHER = "probe:Graph.other"


def _shared_graph():
    return {
        "frozen_targets": [ROOT],
        "selected_nodes": [LEFT_NODE, RIGHT_NODE, ROOT, SHARED],
        "term_dependencies": [
            [LEFT_NODE, SHARED],
            [RIGHT_NODE, SHARED],
            [ROOT, LEFT_NODE],
            [ROOT, RIGHT_NODE],
        ],
        "source_paths": {
            LEFT_NODE: "Graph/Left.lean",
            RIGHT_NODE: "Graph/Right.lean",
            ROOT: "Graph/Root.lean",
            SHARED: "Graph/Shared.lean",
        },
    }


def _failure_graph():
    graph = _shared_graph()
    graph["selected_nodes"].append(OTHER)
    graph["term_dependencies"].append([ROOT, OTHER])
    graph["source_paths"][OTHER] = "Graph/Other.lean"
    return graph


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
    def test_candidate_checkpoint_follows_out_of_order_receipt_acceptance(self):
        class LaterReceiptFirst(_FixtureProxy):
            def __init__(self, fixture):
                super().__init__(fixture)
                self.right_accepted = threading.Event()

            def __call__(self, request):
                if request["request_id"] == "proof-left-001":
                    self.assert_true(self.right_accepted.wait(5))
                return super().__call__(request)

            @staticmethod
            def assert_true(value):
                if not value:
                    raise AssertionError("later receipt did not finish first")

        with tempfile.TemporaryDirectory() as tmp:
            seams = _Seams(Path(tmp), FIXTURE)
            proxy = LaterReceiptFirst(FIXTURE)
            original = diamond._checkpoint_candidate
            checkpointed = []

            def checkpoint(state, candidate, manifest):
                request_id = candidate["request_id"]
                self.assertIn(request_id, state["model_exchanges"])
                self.assertIn(
                    request_id, {receipt["request_id"] for receipt in state["receipts"]}
                )
                checkpointed.append(request_id)
                transition = original(state, candidate, manifest)
                if request_id == "proof-right-001":
                    proxy.right_accepted.set()
                return transition

            with (
                mock.patch.object(worker, "prepare_run", seams.prepare),
                mock.patch.object(worker, "run_probes", seams.run_probes),
                mock.patch.object(
                    worker, "check_contract_feasibility", seams.check_contract_feasibility
                ),
                mock.patch.object(worker, "accept_candidate", seams.accept),
                mock.patch.object(results, "persist_attempt", seams.persist),
                mock.patch.object(verifier, "verify_run", seams.verify),
                mock.patch.object(diamond, "_checkpoint_candidate", side_effect=checkpoint),
            ):
                result = experiment.run_experiment(
                    TARGET, TARGET / "run.json", run_round=proxy
                )

        self.assertEqual(result["outcome"], "success")
        self.assertEqual(checkpointed[0], "proof-right-001")

    def test_contract_frontier_is_consumer_first_for_shared_helpers(self):
        graph = _shared_graph()
        frontier = getattr(diamond, "_contract_frontier", lambda *_: [])
        immediate_consumers = getattr(diamond, "_immediate_consumers", lambda *_: [])

        self.assertEqual(frontier(graph, set()), [ROOT])
        self.assertEqual(
            frontier(graph, {ROOT}),
            [LEFT_NODE, RIGHT_NODE],
        )
        self.assertEqual(
            frontier(graph, {ROOT, LEFT_NODE, RIGHT_NODE}),
            [SHARED],
        )
        self.assertEqual(
            immediate_consumers(graph, SHARED),
            [LEFT_NODE, RIGHT_NODE],
        )

    def test_contract_revision_invalidates_only_its_proof_and_transitive_consumers(self):
        graph = _failure_graph()
        state = {
            "graph": graph,
            "contracts": {
                "node_fingerprints": {node: node + "-v1" for node in graph["selected_nodes"]},
                "invalidated_fingerprints": [],
                "revision_lineage": [],
            },
            "accepted_nodes": list(graph["selected_nodes"]),
            "proof_patch_sha256": {node: node + "-patch" for node in graph["selected_nodes"]},
            "target_states": {
                node: {"phase": "proof", "status": "accepted"}
                for node in graph["selected_nodes"]
            },
            "run": {"events": []},
        }
        revise = getattr(diamond, "_revise_contract_fingerprint", lambda *_: [])

        invalidated = revise(state, SHARED, "shared-v2")

        self.assertEqual(invalidated, [LEFT_NODE, RIGHT_NODE, ROOT])
        self.assertEqual(state["accepted_nodes"], [OTHER])
        self.assertEqual(state["target_states"][OTHER]["status"], "accepted")

    def test_exhausted_helper_blocks_only_its_consumer_chain(self):
        graph = _failure_graph()
        state = {
            "graph": graph,
            "target_states": {
                node: {"phase": "proof", "status": "accepted"}
                for node in graph["selected_nodes"]
            },
            "block_chains": {},
            "run": {"events": []},
        }
        block = getattr(diamond, "_block_dependents", lambda *_: [])

        blocked = block(state, SHARED, "proof_exhausted")

        self.assertEqual(blocked, [LEFT_NODE, RIGHT_NODE, ROOT])
        self.assertEqual(state["block_chains"][ROOT], [ROOT, LEFT_NODE, SHARED])
        self.assertEqual(state["target_states"][OTHER]["status"], "accepted")

    def test_cycle_preflight_fails_with_graph_diagnostics_before_model_work(self):
        graph = {
            "frozen_targets": ["probe:Cycle.a"],
            "selected_nodes": ["probe:Cycle.a", "probe:Cycle.b"],
            "term_dependencies": [
                ["probe:Cycle.a", "probe:Cycle.b"],
                ["probe:Cycle.b", "probe:Cycle.a"],
            ],
            "source_paths": {
                "probe:Cycle.a": "Cycle/A.lean",
                "probe:Cycle.b": "Cycle/B.lean",
            },
        }
        state = {"graph": graph, "preparation_defects": [], "run": {"events": []}}
        validate = getattr(diamond, "_validate_scheduling_graph", lambda *_: None)

        with (
            mock.patch.object(diamond, "_model_request") as model,
            self.assertRaisesRegex(
                experiment.ContractError,
                "unsupported_dependency_cycle.*probe:Cycle.a.*Cycle/A.lean",
            ),
        ):
            validate(state)

        model.assert_not_called()
        self.assertEqual(state["preparation_defects"][0]["kind"], "cycle")

    def test_immutable_graph_binds_and_validates_supplied_spec_paths(self):
        graph = _shared_graph()
        spec = "probe:Graph.root_spec"
        type_node = "probe:Graph.Input"
        graph["supplied_specs"] = {ROOT: spec}
        graph["source_paths"][spec] = "../RootSpec.lean"
        with self.assertRaisesRegex(experiment.ContractError, "invalid scheduling source"):
            diamond._validate_scheduling_graph(
                {"graph": graph, "run": {"events": []}}
            )

        graph["source_paths"][spec] = "Graph/Root.lean"
        graph["source_paths"][type_node] = "Graph/Input.lean"
        graph["type_dependencies"] = [[spec, ROOT], [LEFT_NODE, type_node]]
        state = {"graph": graph, "run": {"events": []}}
        digest = diamond._validate_scheduling_graph(state)
        self.assertEqual(
            digest,
            experiment._canonical_sha256(
                {
                    "frozen_targets": graph["frozen_targets"],
                    "selected_nodes": graph["selected_nodes"],
                    "term_dependencies": graph["term_dependencies"],
                    "type_dependencies": graph["type_dependencies"],
                    "source_paths": graph["source_paths"],
                    "supplied_specs": graph["supplied_specs"],
                }
            ),
        )

    def test_contract_revision_limit_is_per_helper_with_unique_request_ids(self):
        first = "probe:Alpha.helper"
        second = "probe:Beta.helper"
        graph = {
            "frozen_targets": [ROOT],
            "selected_nodes": [first, ROOT, second],
            "term_dependencies": [[ROOT, first], [ROOT, second]],
            "source_paths": {first: "Alpha.lean", ROOT: "Graph/Root.lean", second: "Beta.lean"},
        }

        def statement(node, version):
            declaration = f"{node.removeprefix('probe:')}_spec"
            text = f"theorem {declaration} : True := by trivial -- {version}"
            fingerprint = hashlib.sha256(text.encode()).hexdigest()
            return {
                "payload": {
                    "declaration": declaration,
                    "text": text,
                    "text_sha256": fingerprint,
                },
                "statement_fingerprints": [TOP, fingerprint],
            }

        responses = iter(
            (
                statement(first, "draft"),
                statement(second, "draft"),
                statement(first, "review"),
                statement(second, "review"),
            )
        )
        request_ids = []

        def model_request(*args, **kwargs):
            request_ids.append(kwargs["request_id"])
            return next(responses), {}

        checks = iter(
            (
                {**_feasibility("failed", "first weak"), "declaration": "Alpha.helper_spec"},
                {**_feasibility("failed", "second weak"), "declaration": "Beta.helper_spec"},
                _feasibility("passed", "both compiled"),
            )
        )
        state = _state()
        state["config"] = {"max_contract_revisions": 1}
        with (
            mock.patch.object(diamond, "_model_request", side_effect=model_request),
            mock.patch.object(
                worker,
                "check_contract_feasibility",
                side_effect=lambda *args: next(checks),
            ),
        ):
            contracts = diamond._repair_contracts(
                state,
                {"payload_sha256": "d" * 64},
                TOP,
                graph,
            )

        self.assertEqual(
            [item["node"] for item in contracts["revision_lineage"]],
            [first, second],
        )
        self.assertEqual(len(request_ids), len(set(request_ids)))
        self.assertEqual(contracts["proof_barrier"], "frozen")

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
