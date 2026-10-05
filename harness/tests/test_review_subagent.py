"""Diagnosis triggers, isolation, budget and handoff without model/API calls."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agentproc
import driver
import proof_state
import review_subagent as review


def checked(status="failure", **updates):
    return {"status": status, "module": "Test", "obligation": "Test.target",
            "sources_unchanged": True, "finished": status != "timeout",
            "first_error": {"file": "Test.lean", "message": "unsolved goals"},
            "goal_text": "Test.lean:3:2: unsolved goals\n⊢ True",
            **updates}


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.monitor = review.Monitor("/tmp/work", "task")

    def test_three_failures_ignore_line_movement_and_source_edits(self):
        for i in range(3):
            self.monitor.observe(checked(goal_text=f"Test.lean:{i+1}:2: unsolved goals\n⊢ True",
                                         source_hashes={"Test.lean": str(i)}))
        self.assertEqual(self.monitor.pending["reason"], "repeated_failure")
        self.assertEqual(self.monitor.pending["consecutive_checks"], 3)

    def test_two_labelled_timeouts(self):
        for _ in range(2):
            self.monitor.observe(checked("timeout", first_error=None, goal_text=None))
        self.assertEqual(self.monitor.pending["reason"], "repeated_timeout")
        self.assertEqual(self.monitor.pending["attribution"], "caller_label")

    def test_no_guessing_unlabelled_timeout(self):
        for _ in range(4):
            self.monitor.observe(checked("timeout", obligation=None))
        self.assertIsNone(self.monitor.pending)

    def test_progress_other_obligation_changed_goal_and_tool_errors_break_streak(self):
        for change in (checked("success"), checked(obligation="Other.helper"),
                       checked(goal_text="⊢ False"), checked("error"),
                       checked(sources_unchanged=False)):
            with self.subTest(change=change):
                self.monitor.reset()
                self.monitor.observe(checked())
                self.monitor.observe(checked())
                self.monitor.observe(change)
                self.monitor.observe(checked())
                self.assertIsNone(self.monitor.pending)

    def test_busy_does_not_count_or_break_streak(self):
        self.monitor.observe(checked())
        self.monitor.observe(checked("busy"))
        self.monitor.observe(checked())
        self.assertIsNone(self.monitor.pending)
        self.monitor.observe(checked())
        self.assertIsNotNone(self.monitor.pending)

    def test_scan_is_task_scoped_ordered_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            for i in reversed(range(5)):
                record = checked(task_id="task" if i < 2 else "other",
                                 workspace="/tmp/work", started_at_ns=i)
                Path(directory, f"{i}.json").write_text(json.dumps(record))
            self.assertIsNone(self.monitor.poll(directory))
            self.assertIsNone(self.monitor.poll(directory))
            Path(directory, "partial.json").write_text('{"status":')
            self.assertIsNone(self.monitor.poll(directory))
            Path(directory, "last.json").write_text(json.dumps(checked(
                task_id="task", workspace="/tmp/work", started_at_ns=9)))
            self.assertIsNotNone(self.monitor.poll(directory))

    def test_later_success_cancels_pending_trigger(self):
        for _ in range(3):
            self.monitor.observe(checked())
        self.monitor.observe(checked("success"))
        self.assertIsNone(self.monitor.pending)


class ReviewIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.work = self.root / "work"
        self.work.mkdir()
        (self.work / "Test.lean").write_text("theorem target : True := by sorry\n")
        (self.work / "lakefile.toml").write_text('name = "test"\n')
        self.config = self.root / "prover_config"
        self.config.mkdir()
        (self.config / agentproc.CREDENTIALS_FILE).write_text("test credentials")
        self.env = {"CLAUDE_CONFIG_DIR": str(self.config)}
        self.args = SimpleNamespace(**{**review.OPTIONS, "review_subagent": True},
            model="test", rounds=2, max_turns=5, timeout=10, build_timeout=1,
            g2=False, max_cost_usd=0, stall_rounds=0, bloat_threshold_tokens=10000,
            auto_reset=False, max_auto_resets=0, quiet_turns=True)
        self.logs = self.root / "checks"
        self.logs.mkdir()
        self.calls = []

    def fake_round(self, prompt, transcript, **kwargs):
        self.calls.append((prompt, kwargs))
        Path(transcript).write_text("")
        if kwargs.get("local_checks") is False:
            self.assertEqual(kwargs["allowed_tools"], "Read,Grep,Glob")
            self.assertFalse(kwargs["resume"])
            self.assertNotEqual(kwargs["env"]["CLAUDE_CONFIG_DIR"], str(self.config))
            self.assertNotIn("skill_plugin", kwargs)
            return "ok", 0, 1, {"result": "Try a bridge lemma; scope stays fixed.",
                               "total_cost_usd": .2}, {}
        task = kwargs["env"]["LEAN_CHECK_TASK_ID"]
        for i in range(3):
            (self.logs / f"{i}.json").write_text(json.dumps(checked(
                task_id=task, workspace=str(self.work), started_at_ns=i)))
        if len(self.calls) == 1:
            trigger = kwargs["stop_check"](str(self.logs))
            self.assertEqual(trigger["reason"], "repeated_failure")
            return "review_requested", -9, 1, {}, {"local_check": {"log_dir": str(self.logs)}}
        self.assertIn("bridge lemma", kwargs["continue_message"])
        return "ok", 0, 1, {}, {"local_check": {"log_dir": str(self.logs)}}

    def run_loop(self, gates, fake=None):
        with mock.patch.object(driver, "TRANSCRIPTS", str(self.root / "transcripts")), \
             mock.patch.object(agentproc, "run_round", side_effect=fake or self.fake_round), \
             mock.patch.object(agentproc, "bwrap_prefix", return_value=["sandbox"]) as sandbox, \
             mock.patch.object(driver, "gate", side_effect=gates):
            result = driver.run_rounds("prove fixed target", "test", "Test.lean", {},
                self.args, self.env, "/settings", {}, str(self.work), ["sandbox"], lambda _: None)
        return result, sandbox

    def test_live_trigger_runs_read_only_reviewer_then_resumes_prover(self):
        result, sandbox = self.run_loop([("rejected_build", {"errors": [{"file": "Test.lean", "line": 1, "col": 1, "message": "unsolved goals", "kind": "unsolved_goals"}]}), ("accepted", {})])
        self.assertEqual(result[0], "accepted")
        self.assertEqual(len(self.calls), 3)
        self.assertTrue(sandbox.call_args.kwargs["read_only"])
        self.assertEqual(result[2][0]["review"]["cost_usd"], .2)
        self.assertEqual(result[2][0]["cost_usd"], .2)
        state = json.loads(Path(result[2][0]["proof_state"]).read_text())
        self.assertFalse(state["diagnosis_review"]["changes_authority"])
        self.assertIn("bridge lemma", proof_state.handoff(state, self.work))
        self.assertEqual((self.work / "Test.lean").read_text(), "theorem target : True := by sorry\n")

    def test_no_review_on_acceptance_or_integrity_violation(self):
        for outcome in ("accepted", "rejected_scope", "rejected_statement_changed"):
            with self.subTest(outcome=outcome):
                self.calls.clear()
                result, sandbox = self.run_loop([(outcome, {})])
                self.assertEqual(len(self.calls), 1)
                sandbox.assert_not_called()

    def test_exhausted_last_round_reports_without_adding_prover_round(self):
        self.args.rounds = 1
        def budget_round(prompt, transcript, **kwargs):
            if kwargs.get("local_checks") is False:
                return self.fake_round(prompt, transcript, **kwargs)
            self.calls.append((prompt, kwargs))
            Path(transcript).write_text("")
            return "deadline", -9, 10, {}, {}
        result, _ = self.run_loop([("rejected_build", {"errors": [{"file": "Test.lean", "line": 1, "col": 1, "message": "unsolved goals", "kind": "unsolved_goals"}]})], budget_round)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(result[2]), 1)
        self.assertEqual(result[2][0]["review"]["trigger"]["reason"], "budget_exhausted")

    def test_cost_cap_skips_review(self):
        self.args.rounds, self.args.max_cost_usd = 1, .1
        def costly(prompt, transcript, **kwargs):
            Path(transcript).write_text("")
            return "deadline", -9, 1, {"total_cost_usd": .1}, {}
        result, sandbox = self.run_loop([("rejected_build", {"errors": [{"file": "Test.lean", "line": 1, "col": 1, "message": "unsolved goals", "kind": "unsolved_goals"}]})], costly)
        sandbox.assert_not_called()
        self.assertEqual(result[0], "budget_exhausted")
        self.assertEqual(result[2][0]["review"]["status"], "skipped_cost_cap")

    def test_review_cost_counts_toward_prover_stop(self):
        self.args.max_cost_usd = .15
        result, _ = self.run_loop([("rejected_build", {"errors": [{"file": "Test.lean", "line": 1, "col": 1, "message": "unsolved goals", "kind": "unsolved_goals"}]})])
        self.assertEqual(result[0], "budget_exhausted")
        self.assertEqual(len(self.calls), 2)

    def test_same_snapshot_is_not_reviewed_again(self):
        recorder = proof_state.Recorder(self.root / "state", self.work, ["Test.lean"],
                                        "test", {}, "prove")
        recorder.state["round"] = 1
        controller = review.Controller(self.args, recorder)
        with mock.patch.object(agentproc, "bwrap_prefix", return_value=["sandbox"]), \
             mock.patch.object(agentproc, "run_round", side_effect=self.fake_round):
            call = lambda: controller.review({"reason": "repeated_failure"}, "prove",
                "rejected_build", {"errors": [{"file": "Test.lean", "line": 1, "col": 1, "message": "unsolved goals", "kind": "unsolved_goals"}]}, self.env, "/settings", 0, lambda _: None)
            self.assertIsNotNone(call())
            self.assertIsNone(call())
        self.assertEqual(len(self.calls), 1)

    def test_actual_process_is_stopped_for_review_and_reviewer_has_no_bash(self):
        for readonly in (False, True):
            transcript = str(self.root / f"process-{readonly}.jsonl")
            command = [sys.executable, "-c", "import time; time.sleep(10)"]
            with mock.patch.object(agentproc, "build_command", return_value=command) as build, \
                 mock.patch.object(agentproc, "_bounded_wait", return_value=.02):
                result = agentproc.run_round("task", transcript, cwd=str(self.work),
                    session_id="test", resume=False, model="test", allowed_tools="Read,Grep,Glob",
                    deadline_seconds=2, env=dict(os.environ), local_checks=not readonly,
                    stop_check=lambda _: {"reason": "repeated_failure"})
            self.assertEqual(result[0], "review_requested")
            self.assertLess(result[2], 2)
            tools = build.call_args.args[5]
            self.assertEqual("Bash" in tools, not readonly)

    def test_opt_in_rejects_unsandboxed_review(self):
        parser = argparse.ArgumentParser()
        review.add_arguments(parser)
        args = parser.parse_args(["--review-subagent"])
        args.sandbox = "none"
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            review.validate(args, parser)

    def test_readonly_mount_is_real_command_option(self):
        with mock.patch.object(agentproc.shutil, "which", return_value="/usr/bin/bwrap"), \
             mock.patch.object(agentproc, "_claude_binary_paths", return_value=[]):
            prefix = agentproc.bwrap_prefix(str(self.work), str(self.config), read_only=True)
        i = prefix.index(str(self.work))
        self.assertEqual(prefix[i-1], "--ro-bind")
        i = prefix.index(str(self.config))
        self.assertEqual(prefix[i-1], "--bind")

    def test_no_diagnostic_means_no_budget_review(self):
        self.args.rounds = 1
        def no_diagnostic(prompt, transcript, **kwargs):
            Path(transcript).write_text("")
            return "deadline", -9, 1, {}, {}
        result, sandbox = self.run_loop([("rejected_sorry_remains", {})], no_diagnostic)
        sandbox.assert_not_called()
        self.assertNotIn("review", result[2][0])

    def test_reviewer_timeout_does_not_block_normal_prover_feedback(self):
        def times_out(prompt, transcript, **kwargs):
            if kwargs.get("local_checks") is False:
                self.calls.append((prompt, kwargs))
                Path(transcript).write_text("")
                return "deadline", -9, 120, {}, {}
            if len(self.calls) == 2:
                self.calls.append((prompt, kwargs))
                self.assertNotIn("bridge lemma", kwargs["continue_message"])
                Path(transcript).write_text("")
                return "ok", 0, 1, {}, {}
            return self.fake_round(prompt, transcript, **kwargs)
        result, _ = self.run_loop([("rejected_build", {}), ("accepted", {})], times_out)
        self.assertEqual(result[0], "accepted")
        self.assertEqual(result[2][0]["review"]["status"], "deadline")
        self.assertEqual(result[2][0]["review"]["advice"], "")

    def test_max_reviews_and_budget_review_once(self):
        recorder = proof_state.Recorder(self.root / "state", self.work, ["Test.lean"], "test", {}, "prove")
        recorder.state["round"] = 1
        self.args.max_reviews = 1
        controller = review.Controller(self.args, recorder)
        with mock.patch.object(agentproc, "bwrap_prefix", return_value=["sandbox"]), \
             mock.patch.object(agentproc, "run_round", side_effect=self.fake_round):
            call = lambda: controller.review({"reason": "budget_exhausted"}, "prove",
                "rejected_kernel_budget", {}, self.env, "/settings", 0, lambda _: None)
            self.assertIsNotNone(call())
            (self.work / "Test.lean").write_text("-- different draft\n")
            self.assertIsNone(call())
            self.assertFalse(controller.available())
            self.args.max_reviews = 2
            controller.config["max_reviews"] = 2
            self.assertIsNone(call())


if __name__ == "__main__":
    unittest.main()
