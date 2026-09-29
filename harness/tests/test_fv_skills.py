"""Selected skill loading must preserve the experiment's isolation boundary."""
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agentproc
import driver
import fv_skills


class FVSkillsTests(unittest.TestCase):
    def test_missing_skill_invocation_cannot_accept_a_proof(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(driver, "TRANSCRIPTS", tmp), \
             mock.patch.object(driver, "gate") as gate:
            (Path(tmp) / "Target.lean").write_text("example : True := by trivial\n")

            def fake_round(prompt, transcript, **kwargs):
                Path(transcript).write_text("")
                return "ok", 0, 1.0, {}, {}

            args = SimpleNamespace(rounds=1, model="test", max_turns=1,
                                   timeout=1, skill_plugin="/plugin")
            with mock.patch.object(agentproc, "run_round", side_effect=fake_round):
                outcome, detail, rounds, _ = driver.run_rounds(
                    "prove", "target", "Target.lean", {}, args, {}, None,
                    {}, tmp, None, lambda _: None)
            self.assertEqual(outcome, "agent_error")
            self.assertIn("not successfully invoked", detail["error"])
            self.assertFalse(rounds[0]["provenance"]["fv_skills"]["loaded"])
            gate.assert_not_called()

    def test_loading_requires_a_successful_tool_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "transcript.jsonl"
            call = {"type": "assistant", "message": {"content": [{
                "type": "tool_use", "id": "skill1", "name": "Skill",
                "input": {"skill": fv_skills.SKILL}}]}}
            result = {"type": "user", "message": {"content": [{
                "type": "tool_result", "tool_use_id": "skill1", "is_error": True}]}}
            path.write_text(json.dumps(call) + "\n" + json.dumps(result))
            self.assertFalse(fv_skills.invocation_evidence(path)["loaded"])
            result["message"]["content"][0]["is_error"] = False
            path.write_text(json.dumps(call) + "\n" + json.dumps(result))
            self.assertTrue(fv_skills.invocation_evidence(path)["loaded"])

    @unittest.skipUnless(shutil.which("claude"), "Claude Code not installed")
    def test_real_cli_discovers_plugin_without_a_model_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config"
            cfg.mkdir()
            work = Path(tmp) / "work"
            work.mkdir()
            plugin, settings, _ = fv_skills.prepare(cfg, driver.OFFLINE_SETTINGS)
            # SDK initialization only: no user message, credentials, or model request.
            request = json.dumps({"type": "control_request", "request_id": "init",
                                  "request": {"subtype": "initialize"}}) + "\n"
            cmd = ["claude", "-p", "--input-format", "stream-json",
                   "--output-format", "stream-json", "--verbose",
                   "--setting-sources", "user", "--settings", settings,
                   "--strict-mcp-config", "--plugin-dir", plugin, "--tools", "Read,Skill"]
            result = subprocess.run(cmd, input=request, capture_output=True, text=True,
                                    cwd=work, env=agentproc.isolated_env(os.environ, str(cfg)),
                                    timeout=30, check=True)
            events = [json.loads(line) for line in result.stdout.splitlines()]
            reply = next(x["response"] for x in events if x.get("type") == "control_response")
            self.assertEqual(reply["subtype"], "success")
            names = {x["name"] for x in reply["response"]["commands"]}
            self.assertIn(fv_skills.SKILL, names)
            self.assertEqual({n for n in names if ":" in n}, {fv_skills.SKILL})
            self.assertNotIn("doctor", names)
            self.assertFalse(any(x.get("type") in {"assistant", "result"} for x in events))

    def test_pinned_reference_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "plugin"
            shutil.copytree(fv_skills.BUNDLE, root)
            (root / "skills/lean-verify/references/tactic-usage.md").write_text("changed")
            with self.assertRaisesRegex(ValueError, "pinned FV reference changed"):
                fv_skills.manifest(root)

    def test_prepare_disables_other_sources_and_preserves_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg"
            cfg.mkdir()
            plugin, settings, evidence = fv_skills.prepare(cfg, driver.OFFLINE_SETTINGS)
            effective = json.loads(Path(settings).read_text())
            self.assertFalse(effective["syncClaudeAiSkills"])
            self.assertTrue(effective["disableBundledSkills"])
            self.assertEqual(effective["enabledPlugins"], {})
            self.assertIn("Bash(curl *)", effective["permissions"]["deny"])
            self.assertIn("Agent", effective["permissions"]["deny"])
            self.assertEqual(fv_skills.manifest(plugin)["files_sha256"], evidence["files_sha256"])
            self.assertEqual(len(list(Path(plugin).rglob("SKILL.md"))), 1)
            self.assertFalse((Path(plugin) / "agents").exists())
            self.assertFalse((Path(plugin) / "hooks").exists())

    def test_baseline_and_resumed_skill_command(self):
        baseline = agentproc.build_command("prove", "id", False, "model", 10,
                                           driver.ALLOWED_TOOLS)
        self.assertIn("--disable-slash-commands", baseline)
        self.assertNotIn("Skill", baseline[baseline.index("--tools") + 1].split(","))
        allowed = driver.ALLOWED_TOOLS + f",Skill({fv_skills.SKILL}),Skill({fv_skills.SKILL} *)"
        for resume in [False, True]:
            cmd = agentproc.build_command("prove", "id", resume, "model", 10,
                                          allowed, skill_plugin="/sealed/plugin")
            self.assertNotIn("--disable-slash-commands", cmd)
            self.assertEqual(cmd[cmd.index("--plugin-dir") + 1], "/sealed/plugin")
            tools = cmd[cmd.index("--tools") + 1].split(",")
            self.assertIn("Skill", tools)
            self.assertNotIn("Agent", tools)
            self.assertNotIn("Task", tools)
            self.assertIn("--strict-mcp-config", cmd)

    def test_plugin_is_sealed_after_config_bind(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(agentproc.shutil, "which", return_value="/usr/bin/bwrap"), \
             mock.patch.object(agentproc, "_claude_binary_paths", return_value=[]):
            cfg = str(Path(tmp) / "cfg")
            plugin = cfg + "/fv-plugin"
            cmd = agentproc.bwrap_prefix(tmp, cfg, sealed_ro=[plugin])
            bind = next(i for i in range(len(cmd) - 2)
                        if cmd[i:i+3] == ["--bind", cfg, cfg])
            seal = next(i for i in range(len(cmd) - 2)
                        if cmd[i:i+3] == ["--ro-bind", plugin, plugin])
            self.assertGreater(seal, bind)


if __name__ == "__main__":
    unittest.main()
