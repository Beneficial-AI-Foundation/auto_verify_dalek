"""Focused tests for the phase-1 joint multi-file loop."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import driver  # noqa: E402
import prove_top_spec as topspec  # noqa: E402


def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


class JointGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = self.tmp.name
        self.paths = ["SpecA.lean", "SpecB.lean", "Top.lean"]
        for path in self.paths + ["Other.lean"]:
            with open(os.path.join(self.work, path), "w") as fh:
                fh.write("-- baseline\n")
        _run(["git", "init", "-q"], self.work)
        _run(["git", "add", "-A"], self.work)
        _run(["git", "-c", "user.name=test", "-c", "user.email=test@example",
              "commit", "-q", "-m", "base"], self.work)

    def tearDown(self):
        self.tmp.cleanup()

    def _fps(self):
        return {
            "SpecA": {
                "A.spec": {"kind": "theorem", "canon": "a", "pp": "A",
                           "consts": ["pkg.a"]},
                "B.spec": {"kind": "theorem", "canon": "b", "pp": "B",
                           "consts": ["pkg.b"]},
            },
            "SpecB": {}, "Top": {},
        }

    def _run_gate(self, after_counts=None):
        after_counts = after_counts or {"Top.lean": 0}
        with mock.patch.object(driver, "build_sorry_counts",
                               return_value=(0, after_counts, 0.1, "")), \
             mock.patch.object(driver, "stmt_fingerprints",
                               return_value=(self._fps(), 0.1)), \
             mock.patch.object(driver, "progress_specs_for",
                               side_effect=lambda fn, fps, path, work, require_progress=True:
                               ["A.spec"] if fn == "pkg.a" else ["B.spec"]):
            return driver.gate(
                self.work, "Top.lean", {"Top.lean": 1}, g1_base={
                    "SpecA": {}, "SpecB": {}, "Top": {}}, g2=False,
                mode="joint", editable_paths=self.paths,
                callees={"pkg.a": "SpecA.lean", "pkg.b": "SpecA.lean"})

    def test_two_allowlisted_files_and_shared_spec_file_are_accepted(self):
        for path in self.paths:
            with open(os.path.join(self.work, path), "a") as fh:
                fh.write("-- edit\n")
        outcome, detail = self._run_gate()
        self.assertEqual(outcome, "accepted")
        self.assertEqual(set(detail["result_specs"]), {"pkg.a", "pkg.b"})
        self.assertEqual(detail["result_specs"]["pkg.a"][0]["pp"], "A")

    def test_edit_outside_allowlist_is_rejected(self):
        with open(os.path.join(self.work, "Other.lean"), "a") as fh:
            fh.write("-- forbidden scope\n")
        outcome, detail = self._run_gate()
        self.assertEqual(outcome, "rejected_scope")
        self.assertEqual(detail["outside"], ["Other.lean"])

    def test_new_file_is_deleted_and_reported_not_fatal(self):
        stray = os.path.join(self.work, "scratch_omega_test.lean")
        with open(stray, "w") as fh:
            fh.write("example : True := trivial\n")
        os.makedirs(os.path.join(self.work, "tmpdir"))
        with open(os.path.join(self.work, "tmpdir", "x.lean"), "w") as fh:
            fh.write("-- stray\n")
        outcome, detail = self._run_gate()
        self.assertEqual(outcome, "accepted")
        self.assertEqual(sorted(detail["removed_new_files"]),
                         ["scratch_omega_test.lean", "tmpdir/"])
        self.assertFalse(os.path.exists(stray))
        self.assertFalse(os.path.exists(os.path.join(self.work, "tmpdir")))

    def test_sorry_migration_outside_batch_is_rejected(self):
        with open(os.path.join(self.work, "Top.lean"), "a") as fh:
            fh.write("-- proof\n")
        outcome, _ = self._run_gate({"Top.lean": 0, "Other.lean": 1})
        self.assertEqual(outcome, "rejected_sorry_migration")

    def test_g1_checks_an_unchanged_editable_module_too(self):
        fps = self._fps()
        fps["SpecB"] = {
            "Existing.theorem": {"kind": "theorem", "canon": "new",
                                 "pp": "new statement", "consts": []}}
        base = {"SpecA": {}, "Top": {}, "SpecB": {
            "Existing.theorem": {"kind": "theorem", "canon": "old",
                                 "pp": "old statement", "consts": []}}}
        with mock.patch.object(driver, "build_sorry_counts",
                               return_value=(0, {"Top.lean": 0}, 0.1, "")), \
             mock.patch.object(driver, "stmt_fingerprints",
                               return_value=(fps, 0.1)):
            outcome, detail = driver.gate(
                self.work, "Top.lean", {"Top.lean": 1}, g1_base=base,
                g2=False, mode="joint", editable_paths=self.paths, callees={})
        self.assertEqual(outcome, "rejected_statement_changed")
        self.assertIn("SpecB", detail["changed"])


class SnapshotAndPublishTests(unittest.TestCase):
    def test_snapshot_is_non_overwriting_and_hashes_current_and_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            work = os.path.join(td, "work")
            run = os.path.join(td, "run")
            os.makedirs(work)
            with open(os.path.join(work, "A.lean"), "w") as fh:
                fh.write("old\n")
            _run(["git", "init", "-q"], work)
            _run(["git", "add", "A.lean"], work)
            _run(["git", "-c", "user.name=test", "-c", "user.email=test@example",
                  "commit", "-q", "-m", "base"], work)
            with open(os.path.join(work, "A.lean"), "w") as fh:
                fh.write("new\n")
            with mock.patch.object(topspec, "REPO", td):
                rel = topspec.save_partial_snapshot(
                    run, 1, ["A.lean"], work, {"A.lean": ["pkg.a"]})
                with open(os.path.join(td, rel)) as fh:
                    manifest = json.load(fh)
                self.assertTrue(manifest["files"][0]["changed"])
                self.assertEqual(manifest["files"][0]["sha256"],
                                 hashlib.sha256(b"new\n").hexdigest())
                with self.assertRaises(FileExistsError):
                    topspec.save_partial_snapshot(run, 1, ["A.lean"], work)

    def test_publish_failure_restores_every_destination(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = os.path.join(td, "bundle")
            work = os.path.join(td, "work")
            os.makedirs(bundle)
            os.makedirs(work)
            for root, text in ((bundle, "old"), (work, "new")):
                for name in ("A.lean", "B.lean"):
                    with open(os.path.join(root, name), "w") as fh:
                        fh.write(text + name)
            calls = 0

            def fail_second(src, dst):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected replacement failure")
                os.replace(src, dst)

            with mock.patch.object(topspec, "REPO", td):
                with self.assertRaises(OSError):
                    topspec.atomic_publish_joint(
                        "bundle", work, ["A.lean", "B.lean"], {"x": {}},
                        replace_func=fail_second)
            for name in ("A.lean", "B.lean"):
                with open(os.path.join(bundle, name)) as fh:
                    self.assertEqual(fh.read(), "old" + name)
            self.assertFalse(os.path.exists(os.path.join(bundle, "internal_specs.json")))


if __name__ == "__main__":
    unittest.main()
