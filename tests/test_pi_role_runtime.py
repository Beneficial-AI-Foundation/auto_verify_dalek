"""Pinned DeepAgents unit tests with a synthetic model seam; no Pi/live requests."""
from __future__ import annotations

import asyncio
import copy
import unittest
from unittest import mock

from autofv import agent_lane, deepagents_lane, model, worker
from tests.test_runtime_profile import binding, config, job, packet, pi_job


class PiRoleRuntimeTests(unittest.TestCase):
    def state(self):
        return {"config": config(), "run": {"run_id": "run-profile-test",
                "runtime_identity_sha256": binding()["runtime_identity_sha256"]},
                "checkpoint_enabled": False}

    def tools(self, value):
        return agent_lane.build_lane_tools(value, read_file=mock.Mock(), search_files=mock.Mock(),
                                         edit_assigned=mock.Mock(), check_lean=mock.Mock())

    def response(self, name="submit_candidate", arguments=None):
        return ({"kind": "tool_call", "payload": {"name": name, "arguments": arguments or {
            "patch": "diff --git a/Example.lean b/Example.lean\n",
            "claimed_status": "candidate", "evidence": []}}}, {})

    def test_same_five_tool_loop_without_artificial_output_limit(self):
        value = pi_job()
        value["role_context"]["source_packet"] = packet()
        state = self.state()
        expected_id = agent_lane.role_conversation_spec(value)["conversation_id"]
        with mock.patch.object(model, "_model_request", return_value=self.response()) as request:
            candidate = asyncio.run(agent_lane.run_role_conversation(state, value, self.tools(value)))
        self.assertEqual(candidate, agent_lane.validate_candidate(candidate, value))
        self.assertEqual(request.call_count, 1)
        kwargs = request.call_args.kwargs
        self.assertEqual(kwargs["conversation_id"], expected_id)
        self.assertEqual(len(kwargs["conversation_id"]), 64)
        self.assertNotIn("max_tokens", kwargs)
        self.assertNotIn("max_output_tokens", kwargs)
        self.assertEqual(state["role_progress"][expected_id]["runtime_profile"], value["runtime_profile"])
        spec = agent_lane.role_conversation_spec(value)
        routed = deepagents_lane._RoutedRoleModel(state, value, spec, list(agent_lane._TOOL_SCHEMAS), [], {})
        self.assertIsNone(routed.max_tokens)
        self.assertEqual(len(agent_lane.capture_tool_schemas(self.tools(value))), 5)

    def test_history_tool_arguments_are_canonical_before_model_hashing(self):
        value = pi_job()
        value["role_context"]["source_packet"] = packet()
        with mock.patch.object(model, "_model_request", side_effect=[
            self.response("read_allowed", {"path": "Example.lean"}), self.response()]) as request:
            asyncio.run(agent_lane.run_role_conversation(self.state(), value, self.tools(value)))
        messages = request.call_args.kwargs["messages"]
        assistant = next(m for m in messages if m["role"] == "assistant")
        self.assertEqual(assistant["tool_calls"][0]["function"]["arguments"], '{"path":"Example.lean"}')

    def test_duplicate_tool_argument_keys_fail_before_dispatch(self):
        value = pi_job()
        normalized = [{"role": "assistant", "content": "", "tool_calls": [{"function": {
            "name": "read_allowed", "arguments": '{"path":"first","path":"second"}'}}]}]
        with mock.patch.object(deepagents_lane, "_normalize_messages", return_value=normalized), \
             mock.patch.object(model, "_model_request") as request:
            with self.assertRaisesRegex(worker.WorkerError, "invalid tool arguments"):
                asyncio.run(agent_lane.run_role_conversation(self.state(), value, self.tools(value)))
        request.assert_not_called()

    def test_invalid_native_action_does_not_trigger_hidden_schema_retry(self):
        value, state = pi_job(), self.state()
        with mock.patch.object(model, "_model_request", return_value=self.response("shell")) as request:
            with self.assertRaisesRegex(worker.WorkerError, "not allowlisted"):
                asyncio.run(agent_lane.run_role_conversation(state, value, self.tools(value)))
        self.assertEqual(request.call_count, 1)

    def test_profile_drift_is_rejected_before_model_dispatch(self):
        value, state = pi_job(), self.state()
        state["run"]["runtime_identity_sha256"] = "f" * 64
        with mock.patch.object(model, "_model_request") as request:
            with self.assertRaisesRegex(worker.WorkerError, "runtime changed"):
                asyncio.run(agent_lane.run_role_conversation(state, value, self.tools(value)))
        request.assert_not_called()
        with mock.patch.object(model, "_model_request") as request:
            with self.assertRaisesRegex(worker.WorkerError, "explicit role runtime"):
                asyncio.run(agent_lane.run_role_conversation(self.state(), job(), self.tools(job())))
        request.assert_not_called()

    def test_reviewers_keep_read_only_tools_and_fresh_conversations(self):
        author = pi_job()
        author["role_context"]["source_packet"] = packet()
        author_id = agent_lane.role_conversation_spec(author)["conversation_id"]
        for role in ("spec_reviewer", "proof_reviewer"):
            value = pi_job(role)
            value["role_context"] = {"source_packet": packet(), "reviewed_candidate": {
                "patch": "diff --git a/Example.lean b/Example.lean\n"}}
            callbacks = {k: mock.Mock() for k in ("read_file", "search_files", "edit_assigned", "check_lean")}
            tools = agent_lane.build_lane_tools(value, **callbacks)
            self.assertNotEqual(agent_lane.role_conversation_spec(value)["conversation_id"], author_id)
            self.assertIn("read_only_role", agent_lane.invoke_lane_tool(tools, "edit_assigned", {"patch": "ignored"}))
            self.assertIn("read_only_role", agent_lane.invoke_lane_tool(tools, "check_lean", {}))
            source = agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": "Example.lean"})
            self.assertEqual(source, packet()["sources"][0]["content"])
            for callback in callbacks.values():
                callback.assert_not_called()
            with mock.patch.object(model, "_model_request", return_value=self.response()) as request:
                asyncio.run(agent_lane.run_role_conversation(self.state(), value, tools))
            self.assertEqual(request.call_args.kwargs["role"], role)


if __name__ == "__main__":
    unittest.main()
