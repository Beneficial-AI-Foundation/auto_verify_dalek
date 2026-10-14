"""Synthetic signed Pi stage evidence; no SDK, provider, VM, or verifier call."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import agent_lane, contracts, fvs_adapter, generic_role_runtime, subscription_receipts
from tests.test_runtime_profile import config, packet
from tests.test_subscription_receipts import fixture, request, sha, terminal


class PiStageEvidenceTests(unittest.TestCase):
    def stage(self, root, *, conversation_override=None):
        run, binding = fixture(root)
        binding.public["source_packet_sha256"] = packet()["packet_sha256"]
        binding.public["binding_sha256"] = sha({k: v for k, v in binding.public.items() if k != "binding_sha256"})
        run.update(provider_binding_sha256=binding.public["binding_sha256"],
                   runtime_identity_sha256=binding.public["runtime_identity_sha256"])
        state = {"config": config(), "run": run, "model_exchanges": {}}
        graph = {"graph_sha256": "1" * 64}
        lane = {"node": "Example.f_spec", "assigned_path": "Example.lean", "base_commit": "a" * 40}

        def runner(state, graph, lane, role, **kwargs):
            job = generic_role_runtime._role_job(state, graph, lane, role, **kwargs)
            arguments = {"patch": "diff --git a/Example.lean b/Example.lean\n",
                         "claimed_status": "candidate", "evidence": []}
            candidate = agent_lane._candidate(job, arguments)
            spec = agent_lane.role_conversation_spec(job)
            conversation_id = conversation_override or spec["conversation_id"]
            req, _ = request(binding, role=role, conversation=conversation_id,
                             messages=agent_lane.initial_role_messages(spec))
            req["request_id"] = f"lane-{conversation_id[:16]}-001"
            req["input_hashes"] = sorted(set(req["input_hashes"]) | set(job["input_hashes"]))
            response, raw, continuation, metadata = terminal(binding, req)
            tool_call = {"name": "submit_candidate", "arguments": arguments}
            response["payload"] = {"schema": "autofv-lane-tool-call/v1", **tool_call}
            response["payload_sha256"] = sha(response["payload"])
            continuation["tool_call"] = tool_call
            receipt = subscription_receipts.build_receipt(binding, req, response, raw, continuation, **metadata)
            state["model_exchanges"][req["request_id"]] = {"request": req, "response": response,
                                                          "receipt": receipt, "call_kind": "explicit"}
            return candidate

        return state, binding, fvs_adapter.Stages(state, graph, lane, runner, lambda *a: None)

    def test_signed_subscription_stage_and_retained_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, binding, stage = self.stage(Path(tmp))
            result = stage.invoke("specifier", "specify-1", fingerprint="2" * 64)
            self.assertEqual(result["claimed_status"], "candidate")
            fvs_adapter.validate_evidence(state["fvs_evidence"], binding=binding.public,
                                          exchanges=state["model_exchanges"])
            entry = state["fvs_evidence"]["Example.f_spec:specify-1"]
            self.assertEqual(entry["runtime_profile"]["requested_effort"], "xhigh")
            self.assertIsNone(entry["effort_observations"][0]["observed_effort"])
            self.assertIn("independent effort observations recorded separately", entry["effort_provenance"])
            changed = copy.deepcopy(state["fvs_evidence"])
            entry = changed["Example.f_spec:specify-1"]
            entry["effort_observations"][0]["observed_effort"] = "xhigh"
            entry["record_sha256"] = sha({k: v for k, v in entry.items() if k != "record_sha256"})
            with self.assertRaisesRegex(contracts.ContractError, "requested/observed effort"):
                fvs_adapter.validate_evidence(changed, binding=binding.public, exchanges=state["model_exchanges"])

    def test_authentic_attestation_from_other_conversation_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, stage = self.stage(Path(tmp), conversation_override="f" * 64)
            with self.assertRaisesRegex(contracts.ContractError, "runtime identity mismatch"):
                stage.invoke("specifier", "specify-1", fingerprint="2" * 64)


class PiApiPreflightExclusionTests(unittest.TestCase):
    def test_api_preflight_cannot_authorize_pi(self):
        from autofv import preflight_runner, prepare_dalek
        with mock.patch.object(contracts, "validate_target", return_value=(Path("/synthetic"), {})), \
             mock.patch.object(contracts, "validate_run_config", return_value=(Path("/config"), config())), \
             mock.patch.object(prepare_dalek, "_scan_prepared"), \
             mock.patch.object(preflight_runner, "_new_preflight_output") as allocate:
            with self.assertRaisesRegex(contracts.ContractError, "distinct runtime record"):
                preflight_runner.run_preflight("/synthetic", "/config", "/output")
            with self.assertRaisesRegex(contracts.ContractError, "Pi needs separate qualification"):
                preflight_runner.run_fvs_preflight("/synthetic", "/config", "/output", env_file="/env",
                    preparation_manifest="/manifest", probe_rust_evidence="/rust", probe_aeneas_evidence="/aeneas",
                    dependency_cache="/cache", public_rust_root="/source")
        allocate.assert_not_called()

    def test_helper_api_handoff_refuses_pi_before_numeric_cost_check(self):
        from autofv import preflight_runner
        with self.assertRaisesRegex(contracts.ContractError, "new prepared FVS run"):
            preflight_runner.prepare_helper_handoff({"config": config(), "run": {}}, Path("/unused"))


if __name__ == "__main__":
    unittest.main()
