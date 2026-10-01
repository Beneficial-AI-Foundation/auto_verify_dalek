"""Recovery must preserve useful notes without upgrading claims into proofs."""
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
import lean_check
import proof_state


class ProofStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.work = self.root / "work"
        self.work.mkdir()
        (self.work / "lakefile.toml").write_text('name = "test"\n')
        self.source = self.work / "Test.lean"
        self.source.write_text("theorem helper : True := by trivial\nexample : True := by sorry\n")
        self.logs = self.root / "logs"
        self.trace = self.root / "trace.jsonl"
        self.fps = {"Test": {"target": {"kind": "theorem", "canon": "True"}}}
        self.notes = {
            "current_node": "byte reconstruction",
            "completed_nodes": [{"name": "helper", "file": "Test.lean"}],
            "remaining_goals": ["bytes decode to original value"],
            "failed_attempts": [{"approach": "omega directly", "reason": "timeout",
                                 "evidence": "check-1.log"}],
            "next_check": "split the shift/modulo lemma"}

    def recorder(self, name="record", **kw):
        return proof_state.Recorder(self.root / name, self.work, ["Test.lean"],
                                    "Test.lean", self.fps, "fixed target", **kw)

    def emit(self, notes=None):
        text = proof_state.REPORT_MARKER + json.dumps(notes or self.notes)
        self.trace.write_text(json.dumps({"type": "assistant", "message": {
            "content": [{"type": "text", "text": text}]}}) + "\n")

    def compile(self, recorder, body="pass\n", module="Test"):
        bin_dir = self.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        lake = bin_dir / "lake"
        lake.write_text("#!/usr/bin/python3\n" + body)
        lake.chmod(0o755)
        with mock.patch.dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                             LEAN_CHECK_TASK_ID=recorder.task_id):
            return lean_check.check(self.work, module, 2, self.logs, snapshot_paths=["Test.lean"])

    def record(self, recorder, rnd=1, outcome="rejected_sorry_remains", detail=None):
        return recorder.record(self.trace, {"round": rnd, "outcome": outcome,
                                           "detail": detail or {}}, self.logs)

    def test_partial_transcript_notes_survive_without_final_result(self):
        self.emit()
        with self.trace.open("a") as stream:
            stream.write('{"type": "assistant", "partial":')
        recorder = self.recorder()
        self.record(recorder, outcome="agent_error")
        state = json.loads((recorder.root / "state.json").read_text())
        self.assertEqual(state["progress"]["next_check"], self.notes["next_check"])
        self.assertEqual(state["node_evidence"][0]["status"], "unverified")
        draft = Path(state["draft_checkpoint"])
        self.assertEqual((draft.parent / "files/Test.lean").read_bytes(), self.source.read_bytes())
        self.assertEqual(json.loads(draft.read_text())["kind"], "draft")

    def test_tool_output_cannot_supply_progress_notes_and_bad_reports_are_ignored(self):
        self.trace.write_text(json.dumps({"type": "user", "message": {"content": [{
            "type": "tool_result", "content": proof_state.REPORT_MARKER + json.dumps(self.notes)}]}}))
        self.assertEqual(proof_state.reports(self.trace), [])
        self.trace.write_text(json.dumps({"type": "assistant", "message": {"content": [{
            "type": "text", "text": proof_state.REPORT_MARKER + "not JSON"}]}}))
        self.assertEqual(proof_state.reports(self.trace), [])

    def test_successful_module_checkpoint_is_conditional_and_recovers_old_source(self):
        recorder = self.recorder()
        self.emit()
        checked = self.compile(recorder)
        self.record(recorder)
        node = recorder.state["node_evidence"][0]
        self.assertEqual(node["status"], "module_compiled")
        self.assertFalse(node["dependency_closure_checked"])
        manifest = Path(checked["checkpoint_path"])
        self.assertEqual(json.loads(manifest.read_text())["kind"], "checked_module")
        old = self.source.read_bytes()
        self.source.write_text("broken proof\n")
        self.record(recorder, rnd=2, outcome="rejected_build", detail={"errors": [{"message": "bad"}]})
        self.assertEqual((manifest.parent / "files/Test.lean").read_bytes(), old)
        self.assertEqual(recorder.state["node_evidence"][0]["status"], "unverified")
        self.assertEqual(recorder.state["last_checked_checkpoint"]["manifest"], str(manifest))

    def test_dependency_or_toolchain_changes_invalidate_evidence_on_recovery(self):
        recorder = self.recorder()
        self.emit()
        self.compile(recorder)
        self.record(recorder)
        for relative in ("Dependency.lean", "lean-toolchain"):
            with self.subTest(path=relative):
                path = self.work / relative
                path.write_text("changed\n")
                message = proof_state.handoff(recorder.state, self.work)
                self.assertIn('"check_matches_current_sources": false', message)
                self.assertIn('"gate_matches_current_sources": false', message)
                self.assertIn("stale_or_unverified", message)
                path.unlink()

    def test_latest_failure_and_gate_error_override_reported_completion(self):
        recorder = self.recorder()
        self.emit()
        self.compile(recorder)
        failed = self.compile(recorder, "import sys\nprint('error: Test.lean:1:1: unsolved goals')\nsys.exit(1)\n")
        self.record(recorder, outcome="rejected_build", detail={"errors": [{"message": "unsolved goals"}]})
        self.assertEqual(recorder.state["last_check"]["result_path"], failed["result_path"])
        self.assertEqual(recorder.state["node_evidence"][0]["status"], "unverified")
        self.assertIn("unsolved goals", proof_state.handoff(recorder.state, self.work))

    def test_no_checkpoint_when_source_changes_during_successful_build(self):
        recorder = self.recorder()
        checked = self.compile(recorder, "from pathlib import Path\nPath('Test.lean').write_text('changed')\n")
        self.assertEqual(checked["status"], "success")
        self.assertFalse(checked["sources_unchanged"])
        self.assertIsNone(checked["checkpoint_path"])

    def test_success_elsewhere_does_not_clear_target_module_failure(self):
        recorder = self.recorder()
        self.emit()
        self.compile(recorder)
        self.compile(recorder, "import sys\nsys.exit(1)\n")
        self.compile(recorder, module="Other")
        self.record(recorder)
        self.assertEqual(recorder.state["node_evidence"][0]["status"], "unverified")

    def test_full_build_does_not_imply_arbitrary_module_was_checked(self):
        recorder = self.recorder()
        self.emit()
        self.compile(recorder, module=None)
        self.record(recorder)
        self.assertEqual(recorder.state["node_evidence"][0]["status"], "unverified")

    def test_old_checks_from_other_task_are_not_imported(self):
        first = self.recorder("first")
        self.compile(first)
        second = self.recorder("second")
        self.emit()
        self.record(second)
        self.assertNotIn("last_check", second.state)
        self.assertEqual(second.state["node_evidence"][0]["status"], "unverified")

    def test_cross_run_notes_are_validated_and_never_restore_sources_implicitly(self):
        first = self.recorder("first")
        self.emit()
        saved = self.record(first)
        self.source.write_text("new draft")
        second = self.recorder("second", resume=saved)
        self.assertEqual(self.source.read_text(), "new draft")
        self.assertEqual(second.state["progress"]["current_node"], self.notes["current_node"])
        self.assertIn('"recorded_sources_match_current": false', proof_state.handoff(second.state, self.work))
        self.fps["Test"]["target"]["canon"] = "False"
        with self.assertRaisesRegex(ValueError, "statements"):
            self.recorder("third", resume=saved)

    def test_failed_attempts_accumulate_without_requiring_repetition(self):
        prior = proof_state.clean_notes(self.notes)
        update = proof_state.clean_notes({**self.notes, "failed_attempts": [], "next_check": "try another lemma"})
        merged = proof_state.merge_notes(prior, [update])
        self.assertEqual(len(merged["failed_attempts"]), 1)
        self.assertEqual(merged["next_check"], "try another lemma")

    def test_reset_and_resume_receive_progress_without_extra_source_permissions(self):
        for reset in (False, True):
            with self.subTest(reset=reset):
                traces = self.root / ("reset" if reset else "resume")
                args = SimpleNamespace(rounds=2, model="fake", max_turns=1, timeout=2,
                                       build_timeout=2, g2=False, max_cost_usd=0,
                                       stall_rounds=1 if reset else 0, bloat_threshold_tokens=1000,
                                       auto_reset=True, max_auto_resets=1, quiet_turns=True)
                calls = []
                def fake_round(prompt, transcript, **kwargs):
                    calls.append((prompt, kwargs))
                    Path(transcript).write_text(json.dumps({"type": "assistant", "message": {
                        "content": [{"type": "text", "text": proof_state.REPORT_MARKER + json.dumps(self.notes)}]}}) + "\n")
                    self.assertEqual(json.loads(kwargs["env"]["LEAN_CHECK_EDITABLE_PATHS"]), ["Test.lean"])
                    return "ok", 0, 0.1, {}, {}
                with mock.patch.object(driver, "TRANSCRIPTS", str(traces)), \
                     mock.patch.object(agentproc, "run_round", side_effect=fake_round), \
                     mock.patch.object(driver, "gate", side_effect=[("rejected_sorry_remains", {}), ("accepted", {})]):
                    outcome, _, rounds, _ = driver.run_rounds(
                        "prove", "target", "Test.lean", {}, args, {}, None,
                        self.fps, str(self.work), None, lambda _: None)
                self.assertEqual(outcome, "accepted")
                second_message = calls[1][0] if reset else calls[1][1]["continue_message"]
                self.assertIn(self.notes["next_check"], second_message)
                self.assertIn("omega directly", second_message)
                self.assertEqual(calls[1][1]["resume"], not reset)
                self.assertTrue(Path(rounds[-1]["proof_state"]).is_file())
                self.assertFalse((self.work / "state.md").exists())


if __name__ == "__main__":
    unittest.main()
