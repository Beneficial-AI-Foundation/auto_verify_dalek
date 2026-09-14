import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import agent_lane, worker


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


if __name__ == "__main__":
    unittest.main()
