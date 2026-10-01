"""Real subprocess tests: no model/API calls and no project proof changes."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agentproc
import lean_check

SCRIPT = Path(lean_check.__file__).resolve()


class LeanCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "lakefile.toml").write_text('name = "check_test"\n')
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        self.env.pop("LEAN_CHECK_LOG_DIR", None)

    def fake_lake(self, body):
        executable = self.bin / "lake"
        executable.write_text("#!/usr/bin/python3\n" + body)
        executable.chmod(0o755)

    def command(self, *args):
        return [sys.executable, str(SCRIPT), "--work", str(self.root), *args]

    def run_check(self, *args):
        proc = subprocess.run(self.command(*args), env=self.env,
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.stderr, "")
        result = json.loads(proc.stdout)
        self.assertEqual(json.loads(Path(result["result_path"]).read_text()), result)
        return proc.returncode, result

    def wait_file(self, path):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists() and path.read_text().strip():
                return
            time.sleep(0.02)
        self.fail(f"did not create {path}")

    def assert_dead(self, pid):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{pid}/stat")
            if not stat.exists() or stat.read_text().split(") ", 1)[1].startswith("Z"):
                return
            time.sleep(0.02)
        self.fail(f"process {pid} survived cleanup")

    def test_silent_exit_is_decided_by_returncode(self):
        for code in (0, 7):
            self.fake_lake(f"import sys\nsys.exit({code})\n")
            rc, result = self.run_check("Test")
            self.assertEqual(rc, 0 if code == 0 else 1)
            self.assertEqual(result["status"], "success" if code == 0 else "failure")
            self.assertEqual(result["exit_code"], code)
            self.assertTrue(result["finished"])
            self.assertIsNone(result["first_error"])
            self.assertFalse(result["acceptance_checked"])

    def test_diagnostics_goals_and_full_log(self):
        output = ("error: ./Test.lean:12:4: unsolved goals\n"
                  "x : Nat\n⊢ x = x\n"
                  "error: Test.lean:20:2: later error\n"
                  "warning: Test.lean:30:1: declaration uses 'sorry'\n")
        self.fake_lake(f"import sys\nprint({output!r})\nsys.exit(1)\n")
        _, result = self.run_check("Test")
        self.assertEqual(result["first_error"]["line"], 12)
        self.assertEqual(result["first_error"]["column"], 4)
        self.assertIn("⊢ x = x", result["goal_text"])
        self.assertNotIn("later error", result["goal_text"])
        self.assertEqual(result["sorry_warning_count"], 1)
        self.assertIn("later error", Path(result["log_path"]).read_text())

    def test_success_with_sorry_is_not_acceptance(self):
        self.fake_lake("print(\"warning: Test.lean:1:1: declaration uses 'sorry'\")\n")
        _, result = self.run_check("Test")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["sorry_warning_count"], 1)
        self.assertFalse(result["acceptance_checked"])

    def sleeping_build(self):
        self.fake_lake(
            "import os, subprocess, time\n"
            "from pathlib import Path\n"
            "child = subprocess.Popen(['/usr/bin/sleep', '60'])\n"
            "Path('pids').write_text(f'{os.getpid()} {child.pid}')\n"
            "print('last known progress', flush=True)\n"
            "time.sleep(60)\n")

    def test_timeout_kills_descendants_and_retains_output(self):
        self.sleeping_build()
        rc, result = self.run_check("Test", "--timeout", "0.3")
        self.assertEqual(rc, 124)
        self.assertEqual(result["status"], "timeout")
        self.assertFalse(result["finished"])
        self.assertEqual(result["last_output"], "last known progress")
        self.assertIsNone(result["timeout_declaration"])
        for pid in (self.root / "pids").read_text().split():
            self.assert_dead(int(pid))

    def test_busy_then_parent_sigkill_cleans_build_and_releases_lock(self):
        self.sleeping_build()
        proc = subprocess.Popen(self.command("Test", "--timeout", "8"),
                                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.wait_file(self.root / "pids")
            rc, result = self.run_check("Test")
            self.assertEqual((rc, result["status"]), (75, "busy"))
            self.assertIsNone(result["exit_code"])
            proc.kill()  # uncatchable: supervisor must notice lifeline EOF
            out, err = proc.communicate(timeout=5)
            self.assertEqual(err, "")
            self.assertEqual(json.loads(out)["status"], "interrupted")
            for pid in (self.root / "pids").read_text().split():
                self.assert_dead(int(pid))
            self.fake_lake("pass\n")
            rc, result = self.run_check("Test")
            self.assertEqual((rc, result["status"]), (0, "success"))
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=10)

    def test_normal_exit_cleans_background_children(self):
        self.fake_lake("import subprocess\nfrom pathlib import Path\n"
                       "p = subprocess.Popen(['/usr/bin/sleep', '60'])\n"
                       "Path('pids').write_text(str(p.pid))\n")
        rc, result = self.run_check("--full")
        self.assertEqual(rc, 0)
        self.assertEqual(result["command"], ["lake", "build"])
        self.assert_dead(int((self.root / "pids").read_text()))

    def test_missing_lake_is_explicit_error(self):
        self.env["PATH"] = str(self.bin)
        rc, result = self.run_check("Test")
        self.assertEqual((rc, result["status"]), (2, "error"))
        self.assertIsNone(result["exit_code"])
        self.assertIn("lake", result["message"])

    def test_log_setup_failure_still_returns_json(self):
        blocked = self.root / "blocked"
        blocked.write_text("not a directory")
        proc = subprocess.run(self.command("Test", "--log-dir", str(blocked)),
                              env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, "")
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "error")
        self.assertIsNone(result["log_path"])

    def test_sigterm_cancels_and_reports_interrupted(self):
        self.sleeping_build()
        proc = subprocess.Popen(self.command("Test", "--timeout", "8"), env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.wait_file(self.root / "pids")
            proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=5)
            self.assertEqual((proc.returncode, err), (130, ""))
            self.assertEqual(json.loads(out)["status"], "interrupted")
            for pid in (self.root / "pids").read_text().split():
                self.assert_dead(int(pid))
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=10)

    def test_invalid_requests_never_start_lake(self):
        self.fake_lake("raise AssertionError('must not run')\n")
        for args in (("Test", "--timeout", "nan"), ("Test", "--timeout", "0"),
                     ("Test.lean:olean",), ("../Test.lean",), ("--full", "Test"), ()):
            proc = subprocess.run(self.command(*args), env=self.env, capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, 2)

    def test_round_exposes_checker_on_resume_and_records_provenance(self):
        self.fake_lake("pass\n")
        claude = self.bin / "claude"
        claude.write_text("#!/usr/bin/python3\nimport json, sys\n"
                          "print(json.dumps({'type': 'result', 'args': sys.argv[1:]}))\n")
        claude.chmod(0o755)
        status, rc, _, event, provenance = agentproc.run_round(
            "prove", str(self.root / "transcript.jsonl"), cwd=str(self.root),
            session_id="test", resume=True, continue_message="retry", env=self.env,
            allowed_tools="Read,Bash(lake build*)", deadline_seconds=5)
        self.assertEqual((status, rc), ("ok", 0))
        argv = event["args"]
        self.assertIn("retry\n\nLocal Lean check tool", argv[-1])
        self.assertIn("lean_check.py", argv[argv.index("--allowedTools") + 1])
        self.assertTrue(Path(provenance["local_check"]["tool_path"]).is_file())

    def test_sandbox_seals_only_standalone_tool(self):
        cfg = self.root / "cfg"
        cfg.mkdir()
        with mock.patch.object(agentproc.shutil, "which", return_value="/usr/bin/bwrap"), \
             mock.patch.object(agentproc, "_claude_binary_paths", return_value=[]):
            prefix = agentproc.bwrap_prefix(str(self.root), str(cfg))
        tool_dir = str(cfg / "local_check_tool")
        index = prefix.index(tool_dir)
        self.assertEqual(prefix[index - 1:index + 2], ["--ro-bind", tool_dir, tool_dir])
        self.assertEqual({p.name for p in Path(tool_dir).iterdir()}, {"lean_check.py", "proof_state.py"})


if __name__ == "__main__":
    unittest.main()
