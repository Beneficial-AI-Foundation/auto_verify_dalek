import asyncio
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import agent_lane, model, worker


HASHES = {
    "graph_sha256": "1" * 64,
    "statement_sha256": "2" * 64,
    "contract_fingerprint": "3" * 64,
}


def _job() -> dict:
    return {
        "schema": "autofv-role-job/v1",
        "run_id": "run-001",
        "declaration": "Diamond.left_spec",
        "role": "prover",
        "assigned_path": "Diamond/Left.lean",
        "allowed_read_paths": ["Diamond/Left.lean", "Diamond/Top.lean"],
        **HASHES,
        "input_hashes": ["4" * 64, "5" * 64],
        "accepted_commit": "a" * 40,
    }


class AgentLaneBoundaryTests(unittest.TestCase):
    def test_role_job_has_exact_hash_bound_identity(self):
        job = _job()

        self.assertEqual(agent_lane.validate_role_job(job), job)

        for field in (
            "run_id",
            "declaration",
            "role",
            "assigned_path",
            "graph_sha256",
            "statement_sha256",
            "contract_fingerprint",
            "input_hashes",
            "accepted_commit",
        ):
            with self.subTest(missing=field), self.assertRaises(worker.WorkerError):
                agent_lane.validate_role_job(
                    {key: value for key, value in job.items() if key != field}
                )

        with self.assertRaises(worker.WorkerError):
            agent_lane.validate_role_job({**job, "accepted": True})
        with self.assertRaises(worker.WorkerError):
            agent_lane.validate_role_job({**job, "assigned_path": "../Left.lean"})
        with self.assertRaises(worker.WorkerError):
            agent_lane.validate_role_job(
                {**job, "input_hashes": list(reversed(job["input_hashes"]))}
            )

    def test_effective_tool_surface_is_exactly_five_bounded_capabilities(self):
        tools = agent_lane.build_lane_tools(
            _job(),
            lane_root=Path("/lane"),
            read_file=lambda path: str(path),
            search_files=lambda query: query,
            edit_assigned=lambda patch: patch,
            check_lean=lambda: "ok",
        )

        self.assertEqual(
            agent_lane.capture_tool_schemas(tools),
            [
                {
                    "name": "read_allowed",
                    "description": "Read one allowlisted project file.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "search_allowed",
                    "description": "Search bounded allowlisted project context.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "edit_assigned",
                    "description": "Edit only the assigned project file.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"patch": {"type": "string"}},
                        "required": ["patch"],
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "check_lean",
                    "description": "Run the fixed Lean diagnostic.",
                    "input_schema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
                {
                    "name": "submit_candidate",
                    "description": "Return an untrusted candidate for controller review.",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "patch": {"type": "string"},
                            "claimed_status": {
                                "type": "string",
                                "enum": ["candidate", "blocked", "false_spec"],
                            },
                            "evidence": {
                                "type": "array",
                                "items": {"type": "string"},
                                "maxItems": 32,
                            },
                        },
                        "required": ["patch", "claimed_status", "evidence"],
                        "additionalProperties": False,
                    },
                },
            ],
        )

    def test_hostile_tool_calls_fail_before_callbacks_or_canonical_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            canonical = root / "canonical"
            lane = root / "lane"
            for base in (canonical, lane):
                (base / "Diamond").mkdir(parents=True)
                (base / "Diamond" / "Left.lean").write_text("original\n")
                (base / "Diamond" / "Top.lean").write_text("context\n")
            (lane / "Diamond" / "escape.lean").symlink_to(
                canonical / "Diamond" / "Left.lean"
            )
            callbacks = {
                "read_file": mock.Mock(return_value="contents"),
                "search_files": mock.Mock(return_value="matches"),
                "edit_assigned": mock.Mock(return_value="edited"),
                "check_lean": mock.Mock(return_value="ok"),
            }
            tools = agent_lane.build_lane_tools(
                _job(), lane_root=lane, **callbacks
            )

            hostile_calls = (
                ("read_allowed", {"path": "../canonical/Diamond/Left.lean"}),
                ("read_allowed", {"path": "Diamond/escape.lean"}),
                ("edit_assigned", {"path": "Diamond/Top.lean", "patch": "bad"}),
                ("check_lean", {"command": "lake env lean Other.lean"}),
                ("shell", {"command": "cat /etc/passwd"}),
            )
            for name, arguments in hostile_calls:
                with self.subTest(tool=name, arguments=arguments), self.assertRaises(
                    worker.WorkerError
                ):
                    agent_lane.invoke_lane_tool(tools, name, arguments)

            for callback in callbacks.values():
                callback.assert_not_called()
            self.assertEqual(
                (canonical / "Diamond" / "Left.lean").read_text(), "original\n"
            )
            self.assertEqual((lane / "Diamond" / "Left.lean").read_text(), "original\n")

    def test_submission_is_bound_untrusted_candidate_not_acceptance(self):
        job = _job()
        tools = agent_lane.build_lane_tools(
            job,
            lane_root=Path("/lane"),
            read_file=lambda path: str(path),
            search_files=lambda query: query,
            edit_assigned=lambda patch: patch,
            check_lean=lambda: "ok",
        )
        original = copy.deepcopy(job)

        candidate = agent_lane.invoke_lane_tool(
            tools,
            "submit_candidate",
            {
                "patch": "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n",
                "claimed_status": "candidate",
                "evidence": ["fixed Lean diagnostic passed"],
            },
        )

        self.assertEqual(job, original)
        self.assertEqual(
            agent_lane.validate_candidate(candidate, job), candidate
        )
        self.assertEqual(candidate["schema"], "autofv-lane-candidate/v1")
        self.assertEqual(candidate["assigned_path"], job["assigned_path"])
        self.assertEqual(candidate["accepted_commit"], job["accepted_commit"])
        self.assertEqual(candidate["contract_fingerprint"], job["contract_fingerprint"])
        self.assertNotIn("accepted", candidate)
        self.assertNotIn("accepted_tree_sha256", candidate)


class RoleConversationTests(unittest.TestCase):
    def test_every_role_gets_a_fresh_bounded_conversation_spec(self):
        self.assertTrue(
            hasattr(agent_lane, "role_conversation_spec"),
            "Task 2 requires a role-local conversation specification",
        )
        ceilings = {
            "scout": 4096,
            "dependency_planner": 4096,
            "specifier": 8192,
            "spec_reviewer": 4096,
            "prover": 8192,
            "proof_reviewer": 4096,
            "repair": 8192,
            "verification_adviser": 4096,
        }
        conversation_ids = set()

        for role, ceiling in ceilings.items():
            with self.subTest(role=role):
                job = {**_job(), "role": role}
                first = agent_lane.role_conversation_spec(job)
                second = agent_lane.role_conversation_spec(job)

                self.assertEqual(first, second)
                self.assertIsNot(first, second)
                self.assertEqual(first["role"], role)
                self.assertEqual(first["max_output_tokens"], ceiling)
                self.assertIn(role, first["system_prompt"])
                self.assertIn("candidate", first["system_prompt"])
                self.assertIn("not acceptance", first["system_prompt"])
                self.assertEqual(
                    set(first["context"]),
                    {
                        "declaration",
                        "assigned_path",
                        "graph_sha256",
                        "statement_sha256",
                        "contract_fingerprint",
                        "input_hashes",
                        "accepted_commit",
                    },
                )
                self.assertNotIn("messages", first)
                conversation_ids.add(first["conversation_id"])

        self.assertEqual(len(conversation_ids), len(ceilings))

    def test_scripted_read_check_submit_uses_only_the_model_request_seam(self):
        self.assertTrue(
            hasattr(agent_lane, "run_role_conversation"),
            "Task 2 requires an async role-conversation entry point",
        )
        patch = "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n"
        responses = [
            (
                {
                    "kind": "tool_call",
                    "payload": {
                        "name": "read_allowed",
                        "arguments": {"path": "Diamond/Left.lean"},
                    },
                },
                {"receipt_sha256": "6" * 64},
            ),
            (
                {
                    "kind": "tool_call",
                    "payload": {"name": "check_lean", "arguments": {}},
                },
                {"receipt_sha256": "7" * 64},
            ),
            (
                {
                    "kind": "tool_call",
                    "payload": {
                        "name": "submit_candidate",
                        "arguments": {
                            "patch": patch,
                            "claimed_status": "candidate",
                            "evidence": ["fixed Lean diagnostic passed"],
                        },
                    },
                },
                {"receipt_sha256": "8" * 64},
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            lane = Path(tmp)
            (lane / "Diamond").mkdir()
            (lane / "Diamond" / "Left.lean").write_text("source\n")
            (lane / "Diamond" / "Top.lean").write_text("context\n")
            callbacks = {
                "read_file": mock.Mock(return_value="source"),
                "search_files": mock.Mock(return_value=""),
                "edit_assigned": mock.Mock(return_value="edited"),
                "check_lean": mock.Mock(return_value="diagnostic: clean"),
            }
            tools = agent_lane.build_lane_tools(
                _job(), lane_root=lane, **callbacks
            )
            state = {}
            with mock.patch.object(
                model, "_model_request", side_effect=responses
            ) as request:
                candidate = asyncio.run(
                    agent_lane.run_role_conversation(state, _job(), tools)
                )

        callbacks["read_file"].assert_called_once_with("Diamond/Left.lean")
        callbacks["check_lean"].assert_called_once_with()
        callbacks["search_files"].assert_not_called()
        callbacks["edit_assigned"].assert_not_called()
        self.assertEqual(candidate["claimed_status"], "candidate")
        self.assertNotIn("accepted", candidate)
        self.assertEqual(request.call_count, 3)
        self.assertEqual(
            [call.kwargs["call_kind"] for call in request.call_args_list],
            ["explicit", "explicit", "explicit"],
        )
        request_ids = [call.kwargs["request_id"] for call in request.call_args_list]
        self.assertEqual(len(set(request_ids)), 3)

    def test_schema_correction_stops_after_two_receipted_turns(self):
        self.assertTrue(
            hasattr(agent_lane, "run_role_conversation"),
            "Task 2 requires an async role-conversation entry point",
        )
        malformed = (
            {
                "kind": "tool_call",
                "payload": {
                    "name": "submit_candidate",
                    "arguments": {
                        "patch": "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n",
                        "claimed_status": "candidate",
                    },
                },
            },
            {"receipt_sha256": "9" * 64},
        )
        tools = agent_lane.build_lane_tools(
            _job(),
            lane_root=Path("/unused"),
            read_file=lambda path: path,
            search_files=lambda query: query,
            edit_assigned=lambda patch: patch,
            check_lean=lambda: "ok",
        )
        with mock.patch.object(
            model, "_model_request", side_effect=[malformed, malformed, malformed]
        ) as request, self.assertRaisesRegex(worker.WorkerError, "invalid_agent_output"):
            asyncio.run(agent_lane.run_role_conversation({}, _job(), tools))

        self.assertEqual(request.call_count, 3)
        self.assertEqual(
            [call.kwargs["call_kind"] for call in request.call_args_list],
            ["explicit", "schema_correction", "schema_correction"],
        )


if __name__ == "__main__":
    unittest.main()
