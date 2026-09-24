"""Gate diagnostics fed back into the next round (2026-09-22 as_bytes
post-mortem: the agent got "lake build fails" with no location and answered
a heartbeat timeout by raising maxHeartbeats)."""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import driver  # noqa: E402

TOBYTES = "Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/ToBytes.lean"
REDUCE_MOD = "Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce"

# shape of the real r2 gate output: the error header, then a counterexample
# listing far longer than the 4000-char tail the old detail kept
R2_OUT = (
    f"✔ [3110/3117] Built {REDUCE_MOD} (12.1s)\n"
    f"error: ./{TOBYTES}:370:48: omega could not prove the goal:\n"
    "a possible counterexample may satisfy the constraints\n"
    + "  0 ≤ l ≤ 2251799813947391\n" * 400
    + "where\n b := ↑(↑self[4]! / 2 ^ 51) * ↑p\n"
    f"error: ./{TOBYTES}:452:4: (deterministic) timeout at `whnf`, maximum "
    "number of heartbeats (4000000) has been reached\n"
    "Note: Use `set_option maxHeartbeats <num>` to set the limit.\n"
    f"error: ./{TOBYTES}:452:4: (deterministic) timeout at `whnf`, maximum "
    "number of heartbeats (4000000) has been reached\n"
    "error: Lean exited with code 1\n"
    "Some required targets logged failures:\n"
    "- Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes\n"
    "error: build failed\n")


class ParseTests(unittest.TestCase):
    def test_errors_parsed_deduplicated_and_classified(self):
        errs = driver.parse_build_errors(R2_OUT)
        self.assertEqual([(e["line"], e["kind"]) for e in errs],
                         [(370, "omega_failed"), (452, "resource")])
        self.assertEqual(errs[0]["file"], TOBYTES)
        self.assertEqual(errs[0]["message"], "omega could not prove the goal:")

    def test_per_file_cap_then_total_cap(self):
        out = "".join(f"error: A.lean:{i}:0: unsolved goals\n" for i in range(20))
        out += "".join(f"error: B.lean:{i}:0: type mismatch\n" for i in range(20))
        out += "".join(f"error: C.lean:{i}:0: unknown identifier\n" for i in range(20))
        errs = driver.parse_build_errors(out)
        self.assertEqual([e["file"] for e in errs],
                         ["A.lean"] * 3 + ["B.lean"] * 3 + ["C.lean"] * 2)
        self.assertTrue(all(e["kind"] == "other" for e in errs))

    def test_unfinished_modules(self):
        paths = [TOBYTES, "Curve25519Dalek/Specs/Backend/Serial/U64/Field/"
                 "FieldElement51/Reduce.lean"]
        self.assertEqual(driver.unfinished_modules(R2_OUT, paths),
                         [driver.path_to_module(TOBYTES)])
        self.assertEqual(driver.unfinished_modules("", paths),
                         [driver.path_to_module(p) for p in paths])

    def test_heartbeat_raises(self):
        added = ("set_option maxHeartbeats 20000000 in\n"
                 "set_option   maxHeartbeats 4000000\n theorem x := by omega")
        self.assertEqual(driver.heartbeat_raises(added), [4000000, 20000000])
        self.assertEqual(driver.heartbeat_raises(""), [])


class FeedbackMessageTests(unittest.TestCase):
    def test_build_feedback_names_locations_and_hints(self):
        detail = {"gate_build_seconds": 163.5,
                  "errors": driver.parse_build_errors(R2_OUT),
                  "heartbeats_raised": [20000000],
                  "deadline_exhausted": True}
        msg = driver.feedback_message("rejected_build", detail, timeout=3600)
        self.assertTrue(msg.startswith("The previous round was killed at the 3600s"))
        self.assertIn(driver.FEEDBACK["rejected_build"], msg)
        self.assertIn(f"{TOBYTES}:370:48: omega could not prove the goal:", msg)
        self.assertIn(f"{TOBYTES}:452:4: (deterministic) timeout", msg)
        self.assertIn("clear * -", msg)
        self.assertIn("counterexample", msg)
        self.assertIn("charged to the whole declaration", msg)
        self.assertIn("sets `maxHeartbeats` to 20000000", msg)
        self.assertIn("Revert the `maxHeartbeats` increase", msg)
        # each hint once even though two kinds could share wording
        self.assertEqual(msg.count("Revert the `maxHeartbeats`"), 1)

    def test_kernel_budget_diagnostics(self):
        detail = {"gate_build_seconds": 1200.1, "build_timeout": 1200,
                  "unfinished": [driver.path_to_module(TOBYTES)], "errors": []}
        diag = driver.diagnostics_block("rejected_kernel_budget", detail)
        self.assertIn("killed at the 1200s wall-clock limit", diag)
        self.assertIn("modules not finished: " + driver.path_to_module(TOBYTES), diag)
        self.assertIn("raising it is never the fix", diag)

    def test_kernel_budget_is_feedback(self):
        detail = {"gate_build_seconds": 1200.1, "build_timeout": 1200,
                  "unfinished": ["Top"], "errors": [], "deadline_exhausted": True}
        msg = driver.feedback_message("rejected_kernel_budget", detail, timeout=3600)
        self.assertIn(driver.FEEDBACK["rejected_kernel_budget"], msg)
        self.assertIn("modules not finished: Top", msg)

    def test_no_diagnostics_keeps_plain_verdict(self):
        detail = {"gate_build_seconds": 28.0, "before": 1, "after": 1}
        msg = driver.feedback_message("rejected_sorry_remains", detail,
                                      end_reason="COMPLETE")
        self.assertEqual(msg, "You declared END_REASON:COMPLETE but "
                         + driver.FEEDBACK["rejected_sorry_remains"])

    def test_history_block_carries_locations_and_one_hint_set(self):
        detail = {"errors": driver.parse_build_errors(R2_OUT),
                  "build_error_tail": "x" * 4000, "gate_build_seconds": 1.0}
        rounds = [{"round": 1, "outcome": "rejected_build", "detail": detail},
                  {"round": 2, "outcome": "rejected_build", "detail": detail}]
        hist = driver._history_block(rounds)
        self.assertNotIn("xxxx", hist)
        self.assertEqual(hist.count(f"{TOBYTES}:370:48"), 2)
        self.assertEqual(hist.count("Hints:"), 1)
        self.assertIn("round 2: rejected_build", hist)


class GateDetailTests(unittest.TestCase):
    """gate() stores the structured diagnostics in the verdict detail."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = self.tmp.name
        with open(os.path.join(self.work, "Top.lean"), "w") as fh:
            fh.write("-- baseline\n")
        run = lambda c: subprocess.run(c, cwd=self.work, check=True,  # noqa: E731
                                       capture_output=True)
        run(["git", "init", "-q"])
        run(["git", "add", "-A"])
        run(["git", "-c", "user.name=t", "-c", "user.email=t@e",
             "commit", "-q", "-m", "base"])

    def tearDown(self):
        self.tmp.cleanup()

    def _gate(self, build_return):
        with mock.patch.object(driver, "build_sorry_counts",
                               return_value=build_return):
            return driver.gate(self.work, "Top.lean", {"Top.lean": 1},
                               g1_base=None, g2=False)

    def test_build_failure_detail(self):
        with open(os.path.join(self.work, "Top.lean"), "a") as fh:
            fh.write("set_option maxHeartbeats 20000000 in\ntheorem t : True := trivial\n")
        outcome, detail = self._gate((1, {}, 5.0, R2_OUT))
        self.assertEqual(outcome, "rejected_build")
        self.assertEqual([e["kind"] for e in detail["errors"]],
                         ["omega_failed", "resource"])
        self.assertFalse(detail["errors_truncated"])
        self.assertEqual(detail["heartbeats_raised"], [20000000])
        self.assertEqual(detail["broken_files"], [TOBYTES])
        self.assertLessEqual(len(detail["build_error_tail"]), 4000)

    def test_kernel_budget_detail(self):
        outcome, detail = self._gate(("timeout", {}, 1200.0,
                                      f"✔ [1/2] Built {REDUCE_MOD} (1s)\n"))
        self.assertEqual(outcome, "rejected_kernel_budget")
        self.assertEqual(detail["unfinished"], ["Top"])
        self.assertEqual(detail["errors"], [])
        self.assertNotIn("heartbeats_raised", detail)


class BuildTimeoutOutputTests(unittest.TestCase):
    def test_partial_output_survives_timeout_kill(self):
        with tempfile.TemporaryDirectory() as work:
            with mock.patch.object(driver.subprocess, "Popen") as popen:
                proc = popen.return_value
                proc.pid = 12345
                proc.communicate.side_effect = [
                    driver.subprocess.TimeoutExpired("lake", 1),
                    ("✔ [1/2] Built A (1s)\n", None)]
                with mock.patch.object(driver.os, "killpg"):
                    rc, counts, secs, out = driver.build_sorry_counts(
                        work, timeout=1, include_output=True)
        self.assertEqual(rc, "timeout")
        self.assertEqual(out, "✔ [1/2] Built A (1s)\n")


if __name__ == "__main__":
    unittest.main()
