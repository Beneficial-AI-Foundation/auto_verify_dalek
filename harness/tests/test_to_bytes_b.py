"""The B entry point must isolate writes and never launch a model by default."""
import contextlib
import io
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prove_to_bytes_b as experiment


class BExperimentTests(unittest.TestCase):
    def invoke(self, arguments, callback):
        with mock.patch.object(sys, "argv", ["prove_to_bytes_b.py", *arguments]), \
             mock.patch.object(experiment.harness, "main", side_effect=callback), \
             mock.patch.object(experiment.harness, "PROOF_SKETCH"), \
             mock.patch.object(experiment.harness, "LEDGER"), \
             mock.patch.object(experiment.harness.driver, "TRANSCRIPTS"), \
             mock.patch.object(experiment.harness.driver, "PROMPT", experiment.harness.driver.PROMPT), \
             contextlib.redirect_stdout(io.StringIO()):
            experiment.main()

    def test_preview_never_starts_harness(self):
        self.invoke([], lambda: self.fail("preview launched harness"))
        self.invoke(["--fv-skills"], lambda: self.fail("skill preview launched harness"))

    def test_interactive_preview_never_starts_harness(self):
        self.invoke(["--interactive-prompt"],
                    lambda: self.fail("interactive preview launched harness"))

    def test_default_prompt_is_unchanged(self):
        original_template = experiment.harness.driver.PROMPT
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "attempt"

            def check_default():
                expected = original_template.replace(
                    "replace only its `sorry` with a proof.",
                    "replace its `sorry` with a proof. You may add and prove auxiliary lemmas in this file."
                ).format(decl="to_bytes_spec", path=experiment.PATH,
                         line=experiment.SKELETON.splitlines().index("  sorry") + 1,
                         module=experiment.harness.driver.path_to_module(experiment.PATH))
                expected += "\n" + (experiment.ROOT / "experiments/to_bytes_b/prompt.md").read_text()
                self.assertEqual((run / "prompt.txt").read_text(), expected)
                self.assertEqual(json.loads((run / "experiment.json").read_text())["variant"], "B")

            self.invoke(["--prepare-only", "--run-dir", str(run)], check_default)

    def test_interactive_prompt_is_used_by_harness_and_recorded(self):
        for skills in (False, True):
            with self.subTest(skills=skills), tempfile.TemporaryDirectory() as tmp:
                run = Path(tmp) / "attempt"

                def check_interactive():
                    self.assertEqual(experiment.harness.PROOF_SKETCH, "")
                    actual = experiment.harness.driver.PROMPT.format(
                        decl="to_bytes_spec", path=experiment.PATH,
                        line=experiment.SKELETON.splitlines().index("  sorry") + 1,
                        module=experiment.harness.driver.path_to_module(experiment.PATH))
                    if skills:
                        actual += experiment.fv_skills.prompt()
                    self.assertEqual((run / "prompt.txt").read_text(), actual)
                    self.assertIn("After each build, immediately report:", actual)
                    self.assertIn("After 120 seconds", actual)
                    self.assertIn("Do not increase", actual)
                    self.assertNotIn("Read these files to confirm", actual)
                    self.assertNotIn("from dalek-top-spec-only", actual)
                    self.assertNotIn("spec_mono", actual)
                    self.assertEqual("--fv-skills" in sys.argv, skills)
                    metadata = json.loads((run / "experiment.json").read_text())
                    self.assertEqual(metadata["variant"], "B-interactive")
                    self.assertEqual(metadata["prompt_mode"], "interactive")
                    self.assertEqual(metadata["build_timeout"], 1200)
                    self.assertEqual(metadata["prompt_sha256"],
                                     hashlib.sha256(actual.encode()).hexdigest())

                flags = ["--fv-skills"] if skills else []
                self.invoke(["--prepare-only", "--interactive-prompt", *flags,
                             "--run-dir", str(run)], check_interactive)

    def test_skill_mode_is_recorded_and_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "attempt"

            def fake_prepare():
                self.assertIn("--fv-skills", sys.argv)
                self.assertIn("--dry-run", sys.argv)
                self.assertIn("fv-harness:lean-verify", (run / "prompt.txt").read_text())
                manifest = json.loads((run / "experiment.json").read_text())
                self.assertEqual(manifest["fv_skills"]["skill"], "fv-harness:lean-verify")
                self.assertTrue(manifest["fv_skills"]["files_sha256"])

            self.invoke(["--prepare-only", "--fv-skills", "--run-dir", str(run)], fake_prepare)

    def test_failed_run_keeps_local_outputs_and_source_unchanged(self):
        source = experiment.ROOT / experiment.harness.BUNDLE / experiment.PATH
        before = source.read_bytes() if source.exists() else None
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "attempt"

            def fake_failure():
                argv = sys.argv
                bundle = Path(argv[argv.index("--bundle") + 1])
                self.assertEqual(bundle, run / "bundle")
                self.assertEqual(json.loads((bundle / "bundle_manifest.json").read_text())[
                    "kept_theorems"], {experiment.PATH: [experiment.TARGET]})
                self.assertNotIn("bytes_match_limbs", (bundle / experiment.PATH).read_text())
                self.assertEqual(experiment.harness.LEDGER, str(run / "results.jsonl"))
                self.assertEqual(experiment.harness.driver.TRANSCRIPTS, str(run / "transcripts"))
                (bundle / experiment.PATH).write_text("simulated accepted write")
                raise SystemExit(1)

            with self.assertRaises(SystemExit):
                self.invoke(["--run", "--model", "fake-model", "--run-dir", str(run)], fake_failure)
            self.assertEqual(json.loads((run / "status.json").read_text())["exit_code"], 1)
            self.assertTrue((run / "prompt.txt").is_file())
            self.assertEqual(source.read_bytes() if source.exists() else None, before)

    def test_existing_directory_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            marker = Path(tmp) / "keep"
            marker.write_text("original")
            with self.assertRaises(SystemExit):
                self.invoke(["--prepare-only", "--run-dir", tmp],
                            lambda: self.fail("existing run reused"))
            self.assertEqual(marker.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
