"""The B entry point must isolate writes and never launch a model by default."""
import contextlib
import io
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

    def test_failed_run_keeps_local_outputs_and_source_unchanged(self):
        source = experiment.ROOT / experiment.harness.BUNDLE / experiment.PATH
        before = source.read_bytes()
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
            self.assertEqual(source.read_bytes(), before)

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
