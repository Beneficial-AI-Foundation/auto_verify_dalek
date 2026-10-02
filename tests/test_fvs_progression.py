"""Real host Git/worktree/snapshot progression; model and Lean verdicts are synthetic."""
from __future__ import annotations

import copy
import difflib
import hashlib
import json
import subprocess
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import (agent_lane, contracts, diamond, fvs_adapter, fvs_packet, fvs_profile,
                    generic_role_runtime, provider_config, provider_receipts, role_journal,
                    run_state, worker)
from tests import test_fvs_offline as offline
from tests.test_fvs_offline import PASS, PATH, packet
from tests.test_provider_transport import _provider_env

NODES = ["probe:Arithmetic.increment", "probe:Arithmetic.wrap", "probe:Arithmetic.finish"]
ROOT = NODES[-1]
SHARED = ("import Types\nnamespace Arithmetic\n"
          "def increment (n : Nat) := n + 1\n"
          "def wrap (n : Nat) := increment n\n"
          "def finish (n : Nat) := wrap n\n"
          "@[step]\ntheorem finish_spec (n : Nat) : ∃ result, finish n = ok result := by\n"
          "  sorry\nend Arithmetic\n")


def diff(old, new):
    header = f"diff --git a/{PATH} b/{PATH}\n"
    if old == new:
        # A root specification review can preserve its already supplied statement.
        lines = old.splitlines(keepends=True)
        return header + f"--- a/{PATH}\n+++ b/{PATH}\n@@ -1,{len(lines)} +1,{len(lines)} @@\n" + "".join(" " + line for line in lines)
    return header + "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile="a/" + PATH, tofile="b/" + PATH))


class FvsProgressionTests(unittest.TestCase):
    exchange = offline.FvsOfflineTests.exchange
    remember = offline.FvsOfflineTests.remember

    def setUp(self):
        offline.FvsOfflineTests.setUp(self)
        self.project = self.root / "project"
        self.project.mkdir()
        public = packet()
        public["sources"][0] = fvs_packet.source(PATH, "lean", SHARED)
        public["packet_sha256"] = fvs_profile.digest({k: v for k, v in public.items() if k != "packet_sha256"})
        for item in public["sources"]:
            if item["surface"] != "rust":
                (self.project / item["path"]).write_text(item["content"])
        self.git("init", "-q")
        # Test-only object creation; never stage or commit the working repository.
        entries = []
        for path in sorted(self.project.iterdir()):
            if path.is_file():
                obj = self.git("hash-object", "-w", "--", path.name).decode().strip()
                entries.append(f"100644 blob {obj}\t{path.name}\n")
        tree = self.git("mktree", input_bytes="".join(entries).encode()).decode().strip()
        base = self.git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@invalid",
                        "commit-tree", tree, input_bytes=b"synthetic public base\n").decode().strip()
        self.git("update-ref", "HEAD", base)
        self.git("read-tree", base)
        self.run.update(project_dir=str(self.project), run_root=str(self.root), base_commit=base,
                        execution_tier="simulation", preparation_manifest={"schema": "synthetic-preparation/v1"}, events=[])
        accepted = {"accepted_commit": base, "accepted_tree_sha256": hashlib.sha256(self.git("archive", "--format=tar", base)).hexdigest()}
        self.state["config"]["source_packet"] = public
        provider_config.release_provider(self.run)
        self.run.pop("provider_binding", None)
        self.run["source_packet_sha256"] = public["packet_sha256"]
        env = _provider_env(self.root, overrides={
            "AUTOFV_PROVIDER_ENDPOINT": "https://openrouter.ai/api/v1/chat/completions",
            "AUTOFV_PROVIDER_MODEL": fvs_profile.AUTHOR,
            "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2",
            "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION": "0.1",
            "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION": "10"})
        provider_config.configure_provider(self.run, env_path=env, tool_schemas=list(agent_lane._TOOL_SCHEMAS), project_root=self.root)
        self.binding = provider_config.provider_binding(self.run)
        graph = {"frozen_targets": [ROOT], "selected_nodes": NODES,
                 "term_dependencies": [[NODES[1], NODES[0]], [ROOT, NODES[1]]], "type_dependencies": [],
                 "source_paths": {**{node: PATH for node in NODES}, ROOT + "_spec": PATH},
                 "supplied_specs": {ROOT: ROOT + "_spec"}}
        graph["graph_sha256"] = fvs_profile.digest(graph)
        graph.update(probe_rust_sha256="1" * 64, probe_aeneas_sha256="2" * 64)
        self.state.update(graph=graph, accepted=accepted, working=accepted,
                          target_states={n: {"status": "pending"} for n in NODES})
        self.run["accepted"] = accepted
        self.calls = []
        self.conversations = {}
        self.views = {}
        self.verifications = []
        self.patches = [mock.patch("autofv.agent_lane.run_role_conversation", side_effect=self.conversation),
                        mock.patch("autofv.worker.check_lane", return_value="sealed_runtime:exit=0:synthetic host-only verdict"),
                        mock.patch("autofv.terminal_run.clean_verify_partial", side_effect=self.partial)]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def git(self, *args, input_bytes=None, cwd=None):
        return subprocess.run(("git", *args), cwd=cwd or self.project, input=input_bytes,
                              capture_output=True, check=True).stdout

    def partial(self, state, node, **_):
        commit = state["accepted"]["accepted_commit"]
        key = node + "@" + commit
        prior = state.setdefault("partial_verifier_reports", {}).get(key)
        if prior is not None:
            return prior
        self.verifications.append((node, commit))
        report = {"schema": "synthetic-host-partial-report/v1", "verdict": "SCOPED_PASS", "partial_target": node,
                  "accepted_commit": commit, "accepted_tree_sha256": state["accepted"]["accepted_tree_sha256"],
                  "agent_worker_id": "synthetic-agent", "verifier_worker_id": "synthetic-distinct-verifier",
                  "root_status": "unverified"}
        state["partial_verifier_reports"][key] = report
        return report

    async def conversation(self, state, job, tools):
        identity = agent_lane.role_conversation_spec(job)["conversation_id"]
        if identity in self.conversations:
            return copy.deepcopy(self.conversations[identity])
        node, role = job["declaration"], job["role"]
        stage = job["role_context"].get("stage", "planning")
        self.calls.append((node, role, stage))
        generation = state.get("fvs_lane_generations", {}).get(node)
        baseline_packet = generation["packet"] if generation else state["config"]["source_packet"]
        baseline = fvs_packet.validate_view(baseline_packet)[PATH]["content"]
        visible = tools["read_allowed"]["invoke"]({"path": PATH})
        self.views[(node, stage)] = visible
        if stage == "implementation-research":
            lane = generation["lane"] if generation else next(l for l in state["lanes"] if l["node"] == node)
            self.assertEqual(worker.read_lane_file(self.run, lane, PATH, [PATH]), visible)
            self.assertEqual(self.git("status", "--porcelain", cwd=lane["worktree_path"]), b"")
        name = node.rsplit(".", 1)[-1]
        canon = f"theorem Arithmetic.{name}_spec (n : Nat) : ∃ result, {name} n = ok result"
        spec = baseline
        if node != ROOT:
            spec = baseline.replace("end Arithmetic\n", "@[step]\n" + canon.replace("Arithmetic.", "") + " := by\n  sorry\nend Arithmetic\n")
        else:
            canon = canon.replace("Arithmetic.", "")
        proof = spec.replace(canon.replace("Arithmetic.", "") + " := by\n  sorry", canon.replace("Arithmetic.", "") + " := by\n  rfl")
        proposed = diff(baseline, proof if stage.startswith("proof-") else spec)
        evidence = ["statement:" + canon]
        if role in fvs_profile.REVIEW_ROLES:
            proposed = job["role_context"]["reviewed_candidate"]["patch"]
            evidence = [PASS]
        elif "triage" in stage:
            proposed = job["role_context"]["source_packet"]["patch"]
            evidence.append('triage:{"findings": [], "summary": "Synthetic author checked source-bound review."}')
        candidate = tools["submit_candidate"]["invoke"]({"patch": proposed, "claimed_status": "candidate", "evidence": evidence})
        exchange = self.exchange(role, input_hashes=job["input_hashes"])
        exchange["response"]["payload"] = {"schema": "autofv-lane-tool-call/v1", "name": "submit_candidate",
            "arguments": {"patch": proposed, "claimed_status": "candidate", "evidence": evidence}}
        exchange["response"]["payload_sha256"] = fvs_profile.digest(exchange["response"]["payload"])
        exchange["receipt"] = provider_receipts.sign_receipt(self.binding, self.run, exchange["request"], exchange["response"], exchange["receipt"]["provider"])
        self.remember(exchange)
        self.conversations[identity] = copy.deepcopy(candidate)
        return candidate

    def run_path(self):
        return generic_role_runtime.run_generic_role_path(self.state)

    def test_three_node_shared_helper_progression_has_clean_immutable_generations_and_review_views(self):
        self.run_path()
        self.assertEqual([t["node"] for t in self.state["accepted_sequence"]], NODES)
        final = (self.project / PATH).read_text()
        self.assertNotIn("sorry", final)
        self.assertEqual(self.git("status", "--porcelain"), b"")
        for index, node in enumerate(NODES[1:], 1):
            generation = self.state["fvs_lane_generations"][node]
            self.assertEqual(generation["phase"], "ready")
            self.assertEqual(generation["lane"]["base_commit"], self.state["accepted_sequence"][index - 1]["accepted_commit"])
            self.assertEqual(generation["binding"]["dependencies"], [NODES[index - 1]])
            visible = self.views[(node, "implementation-research")]
            for helper in NODES[:index]:
                name = helper.rsplit(".", 1)[-1] + "_spec"
                self.assertIn(name + " (n : Nat)", visible)
                self.assertIn("  rfl\n", visible)
            review = self.state["fvs_evidence"][node + ":proof-review:0"]["packet"]
            self.assertEqual(review["dependency_generation"], generation["binding"])
            self.assertEqual(fvs_packet.validate_view(review)[PATH]["content"], self.views[(node, "proof-review:0")])
        fvs_adapter.validate_evidence(self.state["fvs_evidence"], binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def pause_at_generation(self, point="ready"):
        def checkpoint(state, transition):
            if transition == f"fvs-generation:{NODES[1]}:{point}":
                raise InterruptedError("synthetic controller interruption")
        with mock.patch("autofv.generic_role_runtime._checkpoint_if_enabled", side_effect=checkpoint):
            with self.assertRaises(InterruptedError):
                self.run_path()

    def reload_checkpoint(self):
        payload = json.loads(contracts.canonical_json_bytes(run_state._checkpoint_payload(self.state, "synthetic-restart", 1)))
        runtime = {"lock": self.run["lock"]}
        self.run = {**payload["run"], **runtime}
        self.state = {**payload["state"], "run": self.run, "config": self.state["config"],
                      "manifest": self.state["manifest"], "cost": Decimal(payload["cost_usd_used"]), "checkpoint_enabled": False}

    def test_restart_pins_generation_and_requests_after_canonical_tree_advances(self):
        self.pause_at_generation()
        prior = copy.deepcopy(self.state["fvs_lane_generations"][NODES[1]])
        before = list(self.calls)
        self.reload_checkpoint()
        self.run_path()
        self.assertEqual(self.state["fvs_lane_generations"][NODES[1]], prior)
        self.assertEqual([t["node"] for t in self.state["accepted_sequence"]], NODES)
        self.assertFalse(any(node == NODES[0] and stage != "planning" for node, _, stage in self.calls[len(before):]))

    def test_active_consumer_restart_reuses_original_requests_and_exact_author_snapshot(self):
        def checkpoint(state, transition):
            if transition == "fvs:" + NODES[1] + ":proof-gates:0":
                raise InterruptedError("synthetic post-author-snapshot crash")
        with mock.patch("autofv.generic_role_runtime._checkpoint_if_enabled", side_effect=checkpoint):
            with self.assertRaises(InterruptedError):
                self.run_path()
        generation = copy.deepcopy(self.state["fvs_lane_generations"][NODES[1]])
        before = list(self.calls)
        receipt = copy.deepcopy(self.state["lane_snapshots"][NODES[1]])
        self.assertEqual(receipt["lane"], generation["lane"])
        self.assertGreater(receipt["sequence"], 1)
        self.reload_checkpoint()
        self.run_path()
        self.assertEqual(self.state["fvs_lane_generations"][NODES[1]], generation)
        self.assertFalse(any(node == NODES[1] and stage in {"implementation-research", "spec-author:0", "proof-author:0"}
                             for node, _, stage in self.calls[len(before):]))
        self.assertEqual([t["node"] for t in self.state["accepted_sequence"]], NODES)

    def test_canonical_dirty_material_is_not_frozen_as_an_accepted_dependency(self):
        self.pause_at_generation()
        self.state["fvs_lane_generations"].pop(NODES[1])
        lane = next(l for l in self.state["lanes"] if l["node"] == NODES[1])
        before = self.git("rev-parse", "HEAD", cwd=lane["worktree_path"])
        with (self.project / PATH).open("a") as destination:
            destination.write("-- unaccepted local dependency material\n")
        with self.assertRaisesRegex(contracts.ContractError, "canonical acceptance drift"):
            generic_role_runtime._dependency_ready_lane(self.state, lane)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=lane["worktree_path"]), before)
        self.assertNotIn(NODES[1], self.state["fvs_lane_generations"])

    def test_interrupted_or_failed_generation_never_dispatches_consumer(self):
        self.pause_at_generation("before")
        before = list(self.calls)
        self.reload_checkpoint()
        with self.assertRaisesRegex(contracts.ContractError, "ambiguous"):
            self.run_path()
        self.assertFalse(any(node == NODES[1] for node, _, _ in self.calls[len(before):]))

    def test_replay_rejects_source_report_and_generation_identity_drift(self):
        self.pause_at_generation()
        original = copy.deepcopy({k: v for k, v in self.state.items() if not k.startswith("_")})
        attacks = [lambda s: s["fvs_lane_generations"][NODES[1]]["packet"]["dependency_overlays"][0].update(content="altered\n"),
                   lambda s: s["fvs_lane_generations"][NODES[1]]["lane"].update(request_id="stale-request"),
                   lambda s: s["fvs_lane_generations"][NODES[1]]["binding"].update(generation_sha256="0" * 64),
                   lambda s: next(iter(s["partial_verifier_reports"].values())).update(verifier_worker_id="altered"),
                   lambda s: s["target_states"][NODES[0]].update(status="unverified")]
        for attack in attacks:
            self.state = copy.deepcopy(original)
            self.run = self.state["run"]
            attack(self.state)
            with self.assertRaises((contracts.ContractError, worker.WorkerError)):
                generic_role_runtime._dependency_ready_lane(self.state, next(l for l in self.state["lanes"] if l["node"] == NODES[1]))

    def test_failed_materialization_stays_ambiguous_and_never_reuses_active_lane(self):
        original_prepare = worker.prepare_lanes
        def prepare(run, lanes):
            if lanes[0].get("schema") == "autofv-proof-lane/v2":
                original_prepare(run, lanes)
                raise worker.WorkerError("synthetic interrupted materialization")
            return original_prepare(run, lanes)
        with mock.patch("autofv.worker.prepare_lanes", side_effect=prepare):
            with self.assertRaisesRegex(worker.WorkerError, "interrupted materialization"):
                self.run_path()
        self.assertEqual(self.state["fvs_lane_generations"][NODES[1]]["phase"], "preparing")
        self.assertFalse(any(node == NODES[1] for node, _, _ in self.calls))
        with self.assertRaisesRegex(contracts.ContractError, "ambiguous"):
            self.run_path()

    def test_job_identity_binds_dependency_generation_and_rejects_stale_candidate_base(self):
        self.pause_at_generation()
        entry = self.state["fvs_lane_generations"][NODES[1]]
        original = next(l for l in self.state["lanes"] if l["node"] == NODES[1])
        def job(lane):
            return generic_role_runtime._role_job(self.state, self.state["graph"], lane, "specifier",
                statement_sha256="a" * 64, contract_fingerprint="a" * 64,
                input_hashes=["a" * 64], role_context={"stage": "synthetic-identity"})
        original_job, generated_job = job(original), job(entry["lane"])
        self.assertNotEqual(agent_lane.role_conversation_spec(original_job)["conversation_id"],
                            agent_lane.role_conversation_spec(generated_job)["conversation_id"])
        self.assertEqual(generated_job["role_context"]["source_packet"], entry["packet"])
        job_before = copy.deepcopy(generated_job)
        self.reload_checkpoint()
        self.assertEqual(job(entry["lane"]), job_before)
        candidate = {"assigned_path": PATH, "request_id": entry["lane"]["request_id"],
                     "generation_node": NODES[1], "generation_sha256": entry["binding"]["generation_sha256"],
                     "payload": {"assigned_path": PATH, "patch": diff(SHARED, SHARED + "-- stale\n"),
                                 "base_commit": self.run["base_commit"]}}
        with self.assertRaisesRegex(worker.WorkerError, "generation mismatch"):
            worker.accept_candidate(self.run, candidate, self.state["manifest"])

    def test_missing_verifier_receipt_and_changed_git_baseline_fail_closed(self):
        self.pause_at_generation()
        generation = self.state["fvs_lane_generations"][NODES[1]]
        reports = self.state["partial_verifier_reports"]
        key = NODES[0] + "@" + generation["binding"]["accepted_commit"]
        report = reports.pop(key)
        lane = next(l for l in self.state["lanes"] if l["node"] == NODES[1])
        with self.assertRaisesRegex(contracts.ContractError, "receipt missing"):
            generic_role_runtime._dependency_ready_lane(self.state, lane)
        reports[key] = report
        self.git("update-ref", "HEAD", self.run["base_commit"], cwd=generation["lane"]["worktree_path"])
        with self.assertRaisesRegex(worker.WorkerError, "immutable Git base"):
            generic_role_runtime._dependency_ready_lane(self.state, lane)

    def test_unverified_dependency_and_snapshot_mismatch_do_not_refresh_original_lane(self):
        self.pause_at_generation()
        generation = self.state["fvs_lane_generations"].pop(NODES[1])
        lane = next(l for l in self.state["lanes"] if l["node"] == NODES[1])
        original_head = self.git("rev-parse", "HEAD", cwd=lane["worktree_path"])
        self.state["target_states"][NODES[0]]["status"] = "unverified"
        with self.assertRaisesRegex(contracts.ContractError, "local-only"):
            generic_role_runtime._dependency_ready_lane(self.state, lane)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=lane["worktree_path"]), original_head)
        self.state["target_states"][NODES[0]]["status"] = "accepted"
        self.state["fvs_lane_generations"][NODES[1]] = generation
        self.state["lane_snapshots"][NODES[1]] = self.state["lane_snapshots"][NODES[0]]
        with self.assertRaisesRegex(contracts.ContractError, "snapshot mismatch"):
            generic_role_runtime._dependency_ready_lane(self.state, lane)


if __name__ == "__main__":
    unittest.main()
