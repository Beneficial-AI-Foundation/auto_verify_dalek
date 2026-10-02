import asyncio
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import agent_lane, model, provider_messages, worker


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
        "role_context": {
            "contract": "theorem Example.left_spec (n : Nat) : Example.left n = n",
            "candidate": "diff --git a/Example/Left.lean b/Example/Left.lean\n",
            "diagnostics": ["declaration uses the immediate consumer contract"],
        },
    }


class AgentLaneBoundaryTests(unittest.TestCase):
    def test_read_only_roles_cannot_reach_the_edit_callback(self):
        for role in (
            "scout", "dependency_planner", "spec_reviewer", "proof_reviewer",
            "verification_adviser",
        ):
            with self.subTest(role=role):
                edit = mock.Mock(return_value="applied")
                tools = agent_lane.build_lane_tools(
                    {**_job(), "role": role},
                    read_file=lambda path: "source",
                    search_files=lambda query: "found",
                    edit_assigned=edit,
                    check_lean=lambda: "ok",
                )
                result = agent_lane.invoke_lane_tool(
                    tools, "edit_assigned",
                    {"patch": "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n"},
                )
                self.assertIn("read_only_role", result)
                edit.assert_not_called()
                self.assertEqual(
                    agent_lane.invoke_lane_tool(
                        tools, "read_allowed", {"path": "Diamond/Left.lean"}
                    ),
                    "source",
                )

    def test_refused_patch_returns_to_the_model_without_editing(self):
        edit = mock.Mock(side_effect=worker.PatchRejected("patch does not apply: corrupt patch"))
        tools = agent_lane.build_lane_tools(
            _job(),
            read_file=mock.Mock(),
            search_files=mock.Mock(),
            edit_assigned=edit,
            check_lean=mock.Mock(),
        )
        other = "diff --git a/Diamond/Top.lean b/Diamond/Top.lean\n"
        self.assertEqual(
            agent_lane.invoke_lane_tool(tools, "edit_assigned", {"patch": other}),
            "patch_rejected: candidate must modify exactly its assigned file",
        )
        edit.assert_not_called()
        valid = "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n"
        self.assertEqual(
            agent_lane.invoke_lane_tool(tools, "edit_assigned", {"patch": valid}),
            "patch_rejected: patch does not apply: corrupt patch",
        )
        edit.side_effect = worker.WorkerError("agent worker command failed")
        with self.assertRaisesRegex(worker.WorkerError, "agent worker command failed"):
            agent_lane.invoke_lane_tool(tools, "edit_assigned", {"patch": valid})

    def test_worker_owned_lane_operations_apply_real_patch_and_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "lane"
            (root / "Diamond").mkdir(parents=True)
            source = root / "Diamond" / "Left.lean"
            source.write_text("source\n")
            subprocess.run(("git", "init", "-q"), cwd=root, check=True)
            subprocess.run(("git", "add", "--all"), cwd=root, check=True)
            subprocess.run(
                (
                    "git", "-c", "user.name=AutoFV", "-c",
                    "user.email=autofv@invalid", "commit", "-q", "-m", "base",
                ),
                cwd=root,
                check=True,
            )
            lane = {
                "lane_id": "proof-left-001",
                "assigned_path": "Diamond/Left.lean",
                "worktree_path": str(root),
            }
            run = {"execution_tier": "simulation"}
            allowed = ["Diamond/Left.lean"]
            patch = (
                "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n"
                "--- a/Diamond/Left.lean\n"
                "+++ b/Diamond/Left.lean\n"
                "@@ -1 +1 @@\n-source\n+proved\n"
            )

            self.assertEqual(worker.read_lane_file(run, lane, allowed[0], allowed), "source\n")
            self.assertIn("Diamond/Left.lean:1", worker.search_lane_files(
                run, lane, "source", allowed
            ))
            applied = worker.edit_lane_file(run, lane, patch)
            diagnostic = worker.check_lane(run, lane, {"verify": ["lake", "build"]})

            self.assertTrue(applied.startswith("applied:"))
            self.assertEqual(source.read_text(), "proved\n")
            self.assertTrue(diagnostic.startswith("simulation_static:exit=0:"))
            outside = Path(tmp) / "outside.lean"
            outside.write_text("secret\n")
            source.unlink()
            source.symlink_to(outside)
            with self.assertRaisesRegex(worker.WorkerError, "symlink"):
                worker.read_lane_file(run, lane, allowed[0], allowed)

    def test_fvs_context_keeps_complete_sources_without_raising_legacy_bound(self):
        context = {"source_evidence": "public source\n" * 10_000}
        legacy = {**_job(), "role_context": context}
        with self.assertRaisesRegex(worker.WorkerError, "context exceeds its bound"):
            agent_lane.validate_role_job(legacy)
        fvs_job = {
            **legacy, "schema": "autofv-role-job/v2", "methodology": "fvs-fc/v1"
        }
        messages = agent_lane.initial_role_messages(
            agent_lane.role_conversation_spec(fvs_job)
        )
        self.assertEqual(
            json.loads(messages[1]["content"])["context"]["role_context"], context
        )
        for malformed in (None, [], {"methodology": "unknown"}):
            with self.assertRaises(worker.WorkerError):
                agent_lane.initial_role_messages(
                    {**agent_lane.role_conversation_spec(fvs_job), "context": malformed}
                )
        self.assertEqual(
            agent_lane.role_conversation_spec(fvs_job)["max_output_tokens"], 16384
        )
        for role in ("spec_reviewer", "proof_reviewer"):
            self.assertEqual(
                agent_lane.role_conversation_spec({**fvs_job, "role": role})[
                    "max_output_tokens"
                ],
                8192,
            )
        with self.assertRaises(worker.WorkerError):
            agent_lane.validate_role_job({**fvs_job, "methodology": "unknown"})
        with self.assertRaisesRegex(worker.WorkerError, "context exceeds its bound"):
            agent_lane.validate_role_job(
                {**fvs_job, "role_context": {"source_evidence": "x" * 262144}}
            )

    def test_fvs_candidate_cannot_replay_as_a_legacy_context(self):
        legacy = _job()
        fvs_job = {
            **legacy, "schema": "autofv-role-job/v2", "methodology": "fvs-fc/v1"
        }
        tools = agent_lane.build_lane_tools(
            fvs_job,
            read_file=lambda path: "source",
            search_files=lambda query: "found",
            edit_assigned=lambda patch: "applied",
            check_lean=lambda: "ok",
        )
        candidate = agent_lane.invoke_lane_tool(
            tools, "submit_candidate",
            {
                "patch": "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n",
                "claimed_status": "candidate", "evidence": [],
            },
        )
        self.assertEqual(agent_lane.validate_candidate(candidate, fvs_job), candidate)
        with self.assertRaisesRegex(worker.WorkerError, "role context mismatch"):
            agent_lane.validate_candidate(candidate, legacy)
        candidate["role_context_sha256"] = agent_lane.role_context_sha256(
            legacy["role_context"]
        )
        with self.assertRaisesRegex(worker.WorkerError, "role context mismatch"):
            agent_lane.validate_candidate(candidate, fvs_job)

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
            "role_context",
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
        self.assertEqual(
            candidate["role_context_sha256"],
            agent_lane.role_context_sha256(job["role_context"]),
        )


class RoleConversationTests(unittest.TestCase):
    def test_exact_deepagents_runtime_is_the_only_role_lane_path(self):
        self.assertTrue(
            hasattr(agent_lane, "role_lane_runtime"),
            "Plan 02-12 requires the pinned Deep Agents runtime facade",
        )
        runtime = agent_lane.role_lane_runtime()

        self.assertEqual(runtime["runtime"], "deepagents")
        self.assertEqual(runtime["deepagents"], "0.7.15")
        self.assertEqual(runtime["langgraph"], "1.2.11")
        self.assertEqual(runtime["langchain"], "1.4.2")
        self.assertEqual(runtime["langchain_core"], "1.6.3")
        self.assertEqual(
            runtime["excluded_tools"],
            [
                "delete",
                "edit_file",
                "execute",
                "glob",
                "grep",
                "ls",
                "read_file",
                "task",
                "write_file",
            ],
        )
        self.assertFalse(runtime["general_purpose_subagent"])
        self.assertEqual(runtime["execution_location"], "trusted_controller")
        self.assertFalse(runtime["alternate_runtime"])

        lock = json.loads(
            (Path(__file__).parents[1] / "docker" / "autofv" / "toolchain-lock.json").read_text()
        )
        members = lock["controller_delivery"]["allowed_members"]
        self.assertNotIn("autofv/deepagents_lane.py", members)
        self.assertNotIn("deepagents==0.7.15", (
            Path(__file__).parents[1] / "docker" / "autofv" / "Dockerfile"
        ).read_text())

    def test_framework_cancellation_is_translated_back_to_asyncio_cancellation(self):
        self.assertTrue(
            hasattr(agent_lane, "role_lane_runtime"),
            "Plan 02-12 requires the pinned Deep Agents runtime facade",
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
            model, "_model_request", side_effect=asyncio.CancelledError
        ), self.assertRaises(asyncio.CancelledError):
            asyncio.run(agent_lane.run_role_conversation({}, _job(), tools))

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
                        "role_context",
                    },
                )
                messages = agent_lane.initial_role_messages(first)
                self.assertEqual([item["role"] for item in messages], ["system", "user"])
                visible_context = json.loads(messages[1]["content"])["context"][
                    "role_context"
                ]
                self.assertEqual(visible_context, job["role_context"])
                conversation_ids.add(first["conversation_id"])

        self.assertEqual(len(conversation_ids), len(ceilings))

    def test_role_methodology_keeps_the_frozen_graph_and_tool_boundary(self):
        expectations = {
            "scout": "source locations",
            "dependency_planner": "preparation defect",
            "specifier": "impossible precondition",
            "spec_reviewer": "non-vacuity",
            "prover": "accepted dependency lemmas",
            "proof_reviewer": "dirty-cache-only",
            "repair": "Keep frozen statements",
            "verification_adviser": "semantic specification recovery",
        }
        prompts = []
        for role, expected in expectations.items():
            with self.subTest(role=role):
                prompt = agent_lane.role_conversation_spec({**_job(), "role": role})[
                    "system_prompt"
                ]
                self.assertIn(expected, prompt)
                self.assertIn("A -> B means A depends on B", prompt)
                self.assertIn("agents cannot re-run probes", prompt)
                self.assertIn("no arbitrary shell", prompt)
                self.assertIn("Mathlib compilation", prompt)
                self.assertIn("candidate, not acceptance", prompt)
                prompts.append(prompt)
        self.assertEqual(len(set(prompts)), len(expectations))

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
        progress = next(iter(state["role_progress"].values()))
        self.assertEqual(progress["status"], "completed")
        self.assertEqual(progress["last_turn"], 3)
        self.assertEqual(progress["last_tool"], "submit_candidate")
        self.assertEqual(len(progress["candidate_sha256"]), 64)
        self.assertEqual(request.call_count, 3)
        first_messages = request.call_args_list[0].kwargs["messages"]
        second_messages = request.call_args_list[1].kwargs["messages"]
        self.assertEqual([item["role"] for item in first_messages], ["system", "user"])
        self.assertEqual(second_messages[:2], first_messages)
        self.assertEqual(second_messages[-1]["role"], "tool")
        self.assertIn("source", second_messages[-1]["content"])
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

    def test_provider_hiccup_retries_under_a_new_id_without_using_a_turn(self):
        hiccup = worker.TransientProviderError("fixed proxy upstream_error")
        submit = (
            {
                "kind": "tool_call",
                "payload": {
                    "name": "submit_candidate",
                    "arguments": {
                        "patch": "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n",
                        "claimed_status": "candidate",
                        "evidence": ["fixed Lean diagnostic passed"],
                    },
                },
            },
            {"receipt_sha256": "6" * 64},
        )
        tools = agent_lane.build_lane_tools(
            _job(),
            lane_root=Path("/unused"),
            read_file=lambda path: path,
            search_files=lambda query: query,
            edit_assigned=lambda patch: patch,
            check_lean=lambda: "ok",
        )
        state = {}
        with mock.patch.object(
            model, "_model_request", side_effect=[hiccup, hiccup, submit]
        ) as request, mock.patch("autofv.deepagents_lane.time.sleep") as sleep:
            candidate = asyncio.run(agent_lane.run_role_conversation(state, _job(), tools))

        self.assertEqual(candidate["claimed_status"], "candidate")
        ids = [call.kwargs["request_id"] for call in request.call_args_list]
        self.assertEqual([ids[0] + "-r1", ids[0] + "-r2"], ids[1:])
        self.assertEqual(
            [call.kwargs["call_kind"] for call in request.call_args_list],
            ["explicit", "retry", "retry"],
        )
        self.assertEqual([call.args for call in sleep.call_args_list], [(2,), (8,)])
        self.assertEqual(next(iter(state["role_progress"].values()))["last_turn"], 1)

    def test_empty_search_result_still_makes_valid_provider_messages(self):
        search = (
            {
                "kind": "tool_call",
                "payload": {"name": "search_allowed", "arguments": {"query": "absent"}},
            },
            {"receipt_sha256": "8" * 64},
        )
        submit = (
            {
                "kind": "tool_call",
                "payload": {
                    "name": "submit_candidate",
                    "arguments": {
                        "patch": "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n",
                        "claimed_status": "candidate",
                        "evidence": ["fixed Lean diagnostic passed"],
                    },
                },
            },
            {"receipt_sha256": "9" * 64},
        )
        tools = agent_lane.build_lane_tools(
            _job(),
            lane_root=Path("/unused"),
            read_file=lambda path: path,
            search_files=lambda query: "",
            edit_assigned=lambda patch: patch,
            check_lean=lambda: "ok",
        )
        with mock.patch.object(
            model, "_model_request", side_effect=[search, submit]
        ) as request:
            asyncio.run(agent_lane.run_role_conversation({}, _job(), tools))

        provider_messages.validate_messages(request.call_args_list[1].kwargs["messages"])

    def test_provider_hiccups_fail_the_lane_past_the_turn_or_role_cap(self):
        hiccup = worker.TransientProviderError("fixed proxy timeout")
        read = (
            {
                "kind": "tool_call",
                "payload": {
                    "name": "read_allowed",
                    "arguments": {"path": "Diamond/Left.lean"},
                },
            },
            {"receipt_sha256": "7" * 64},
        )
        tools = agent_lane.build_lane_tools(
            _job(),
            lane_root=Path("/unused"),
            read_file=lambda path: path,
            search_files=lambda query: query,
            edit_assigned=lambda patch: patch,
            check_lean=lambda: "ok",
        )
        for name, replies, calls in (
            ("turn", [hiccup] * 3, 3),
            ("role", [hiccup, hiccup, read] * 3 + [hiccup], 10),
        ):
            with self.subTest(cap=name), mock.patch.object(
                model, "_model_request", side_effect=replies
            ) as request, mock.patch(
                "autofv.deepagents_lane.time.sleep"
            ), self.assertRaises(worker.TransientProviderError):
                asyncio.run(agent_lane.run_role_conversation({}, _job(), tools))
            self.assertEqual(request.call_count, calls)

    def test_managed_lane_tools_perform_read_edit_check_and_submit_without_host_path_access(self):
        job = _job()
        patch = (
            "diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n"
            "--- a/Diamond/Left.lean\n"
            "+++ b/Diamond/Left.lean\n"
            "@@ -1 +1 @@\n"
            "-source\n"
            "+proved\n"
        )
        operations = mock.Mock()
        operations.read.return_value = "source\n"
        operations.search.return_value = "Diamond/Left.lean:1:source"
        operations.edit.return_value = "applied:" + "9" * 64
        operations.check.return_value = "simulation_static: git diff --check passed"
        tools = agent_lane.build_lane_tools(
            job,
            read_file=operations.read,
            search_files=operations.search,
            edit_assigned=operations.edit,
            check_lean=operations.check,
        )

        self.assertEqual(
            agent_lane.invoke_lane_tool(
                tools, "read_allowed", {"path": "Diamond/Left.lean"}
            ),
            "source\n",
        )
        self.assertIn(
            "Diamond/Left.lean",
            agent_lane.invoke_lane_tool(
                tools, "search_allowed", {"query": "source"}
            ),
        )
        self.assertTrue(
            agent_lane.invoke_lane_tool(
                tools, "edit_assigned", {"patch": patch}
            ).startswith("applied:")
        )
        diagnostic = agent_lane.invoke_lane_tool(tools, "check_lean", {})
        candidate = agent_lane.invoke_lane_tool(
            tools,
            "submit_candidate",
            {"patch": patch, "claimed_status": "candidate", "evidence": [diagnostic]},
        )

        operations.read.assert_called_once_with("Diamond/Left.lean")
        operations.search.assert_called_once_with("source")
        operations.edit.assert_called_once_with(patch)
        operations.check.assert_called_once_with()
        self.assertEqual(candidate["patch"], patch)


if __name__ == "__main__":
    unittest.main()
