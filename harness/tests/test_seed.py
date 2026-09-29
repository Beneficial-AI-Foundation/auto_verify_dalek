"""harness/seed.py: partial-proof reuse (docs/PLAN-SEED-PARTIALS.md)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import driver  # noqa: E402
import seed  # noqa: E402
import prove_top_spec as topspec  # noqa: E402

DRAFT = """import Curve25519Dalek.Funs

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

set_option maxHeartbeats 4000000

/-- docstring for a helper -/
private theorem helper_ok (x : Nat) (h : x < 5) : x < 6 := by
  omega

@[progress]
theorem cast_spec (x : U64) :
    (↑x : U8) ⦃ r => r.val = x.val % 256 ⦄ := by
  sorry

set_option maxHeartbeats 8000000 in
private theorem heavy (a b : Nat) (h : a < b) :
    a + 1 ≤ b := by
  omega

private theorem bad_stmt (a : Nat) : a < undefined_thing := by
  omega

theorem uses_bad (a : Nat) : a < undefined_thing + 1 := by
  have := bad_stmt a
  omega

def pack (b : Nat) : Nat := b * 2

end curve25519_dalek.backend.serial.u64.field.FieldElement51
"""


class ParseTests(unittest.TestCase):
    def test_blocks_and_inventory(self):
        inv = seed.inventory(DRAFT)
        self.assertEqual([d["name"] for d in inv],
                         ["helper_ok", "cast_spec", "heavy", "bad_stmt", "uses_bad", "pack"])
        self.assertEqual([d["sorry"] for d in inv],
                         [False, True, False, False, False, False])
        self.assertTrue(inv[1]["progress"])
        blocks = seed.decl_blocks(DRAFT)
        # docstring and attribute lines belong to the block they precede
        self.assertTrue(blocks[0]["lines"][0].startswith("/--"))
        self.assertTrue(blocks[1]["lines"][0].startswith("@[progress]"))
        self.assertTrue(blocks[2]["lines"][0].startswith("set_option maxHeartbeats"))
        # the namespace `end` is not swallowed
        self.assertFalse(any(ln.startswith("end ") for b in blocks for ln in b["lines"]))


class SanitizeTests(unittest.TestCase):
    def _line_of(self, text, needle):
        return next(i + 1 for i, ln in enumerate(text.splitlines()) if needle in ln)

    def test_proof_error_becomes_sorry_statement_error_is_dropped_with_cascade(self):
        errors = [{"line": self._line_of(DRAFT, "  omega"), "col": 2},        # helper_ok proof
                  {"line": self._line_of(DRAFT, "a < undefined_thing :="),
                   "col": DRAFT.splitlines()[self._line_of(DRAFT, "a < undefined_thing :=") - 1].index("undefined")}]
        out, rep = seed.sanitize(DRAFT, errors)
        self.assertEqual(rep["sorried"], ["helper_ok"])
        self.assertEqual(rep["dropped"], ["bad_stmt", "uses_bad"])
        self.assertEqual(rep["heartbeats_removed"], 2)
        self.assertNotIn("maxHeartbeats", out)
        self.assertNotIn("bad_stmt", out)
        self.assertNotIn("uses_bad", out)
        inv = seed.inventory(out)
        self.assertEqual([(d["name"], d["sorry"]) for d in inv],
                         [("helper_ok", True), ("cast_spec", True), ("heavy", False),
                          ("pack", False)])
        # statement kept verbatim, proof replaced
        self.assertIn("private theorem helper_ok (x : Nat) (h : x < 5) : x < 6 := by\n  sorry", out)
        self.assertIn("end curve25519_dalek", out)
        self.assertIn("@[progress]\ntheorem cast_spec", out)

    def test_no_errors_only_strips_heartbeats(self):
        out, rep = seed.sanitize(DRAFT, [])
        self.assertEqual((rep["sorried"], rep["dropped"], rep["heartbeats_removed"]),
                         ([], [], 2))
        self.assertEqual(len(seed.inventory(out)), 6)

    def test_all_proofs_keeps_statements_and_defs(self):
        out, rep = seed.sanitize_all_proofs(DRAFT)
        inv = seed.inventory(out)
        self.assertTrue(all(d["sorry"] for d in inv if d["kind"] == "theorem"))
        self.assertIn("def pack (b : Nat) : Nat := b * 2", out)
        self.assertEqual(sorted(rep["sorried"]),
                         ["bad_stmt", "cast_spec", "heavy", "helper_ok", "uses_bad"])

    def test_real_drafts_parse(self):
        root = os.path.join(driver.REPO, "ledger", "runs")
        rel = ("partials/attempt-1/files/Curve25519Dalek/Specs/Backend/Serial/U64/"
               "Field/FieldElement51/ToBytes.lean")
        for run, n in (("topspec_2026-09-24T070536+0000", 12),
                       ("topspec_2026-09-22T083111+0000", 9)):
            p = os.path.join(root, run, rel)
            if not os.path.isfile(p):
                self.skipTest("ledger partials not present")
            text = open(p).read()
            self.assertEqual(len(seed.inventory(text)), n)
            out, _ = seed.sanitize_all_proofs(text)
            self.assertEqual(len(seed.inventory(out)), n)


class StateTests(unittest.TestCase):
    P = "Specs/ToBytes.lean"

    def test_compiles_from_verdicts(self):
        mod = driver.path_to_module(self.P)
        cases = [
            ([{"outcome": "rejected_sorry_remains",
               "detail": {"counts_after": {self.P: 2}}}], (True, 2)),
            ([{"outcome": "rejected_build",
               "detail": {"broken_files": [self.P], "errors": [
                   {"file": self.P, "line": 3, "kind": "omega_failed", "message": "m"},
                   {"file": "Other.lean", "line": 1, "kind": "other", "message": "x"}]}}],
             (False, None)),
            ([{"outcome": "rejected_build", "detail": {}}], (None, None)),
            ([{"outcome": "rejected_kernel_budget",
               "detail": {"unfinished": [mod]}}], (False, None)),
            ([{"outcome": "rejected_scope", "detail": {"deadline_exhausted": True}}],
             (None, None)),
        ]
        for rounds, (compiles, count) in cases:
            st = seed.file_state(self.P, DRAFT, rounds)
            self.assertEqual((st["compiles"], st["sorry_count"]), (compiles, count), rounds)
            self.assertTrue(all(e["file"] == self.P for e in st["errors"]))
        self.assertEqual(len(st["decls"]), 6)

    def test_snapshot_writes_state_and_notes(self):
        with tempfile.TemporaryDirectory() as td:
            work = os.path.join(td, "work")
            os.makedirs(os.path.join(work, "Specs"))
            with open(os.path.join(work, self.P), "w") as fh:
                fh.write("-- skeleton\n")
            subprocess.run(["git", "init", "-q"], cwd=work, check=True)
            subprocess.run(["git", "add", "-A"], cwd=work, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@e",
                            "commit", "-q", "-m", "base"], cwd=work, check=True)
            with open(os.path.join(work, self.P), "w") as fh:
                fh.write(DRAFT)
            tpath = os.path.join(td, "t.jsonl")
            with open(tpath, "w") as fh:
                fh.write("not json\n")
                fh.write(json.dumps({"type": "result", "result": "END_REASON:LIMIT — stuck"}) + "\n")
            rounds = [{"round": 1, "outcome": "rejected_build", "wall_seconds": 5,
                       "num_turns": 3, "status": "ok", "end_reason": "LIMIT",
                       "transcript": "t.jsonl",
                       "detail": {"broken_files": [self.P], "errors": [
                           {"file": self.P, "line": 11, "col": 2, "kind": "other",
                            "message": "boom"}]}}]
            with mock.patch.object(topspec, "REPO", td):
                rel = topspec.save_partial_snapshot(
                    os.path.join(td, "run"), 1, [self.P], work, {self.P: ["f"]}, rounds=rounds)
            root = os.path.dirname(os.path.join(td, rel))
            state = json.load(open(os.path.join(root, "state.json")))
            self.assertEqual(state["files"][0]["compiles"], False)
            self.assertEqual(state["files"][0]["errors"][0]["line"], 11)
            notes = open(os.path.join(root, "notes.md")).read()
            self.assertIn("rejected_build", notes)
            self.assertIn("END_REASON:LIMIT — stuck", notes)


class CandidateTests(unittest.TestCase):
    def _ledger(self, td, entries):
        lp = os.path.join(td, "ledger.jsonl")
        with open(lp, "w") as fh:
            for run_id, rounds, functions, text, state in entries:
                run = os.path.join(td, "runs", run_id.replace(":", ""))
                att = os.path.join(run, "partials", "attempt-1")
                os.makedirs(os.path.join(att, "files", "Specs"))
                with open(os.path.join(att, "files", "Specs", "A.lean"), "w") as f:
                    f.write(text)
                man = {"attempt": 1, "files": [{"path": "Specs/A.lean", "changed": True,
                                                "functions": functions}]}
                json.dump(man, open(os.path.join(att, "manifest.json"), "w"))
                if state is not None:
                    json.dump({"files": [{"path": "Specs/A.lean", **state}]},
                              open(os.path.join(att, "state.json"), "w"))
                fh.write(json.dumps({
                    "run_id": run_id, "target": "T", "plan": {"mode": "joint"},
                    "partial_manifest": os.path.relpath(os.path.join(att, "manifest.json"), td),
                    "rounds": rounds}) + "\n")
        return lp

    def test_ranking_prefers_known_compiling_then_proved_then_newer(self):
        two = "theorem a : True := by trivial\ntheorem b : True := by\n  sorry\n"
        three = "theorem a : True := by trivial\ntheorem b : True := by trivial\ntheorem c : True := by trivial\n"
        with tempfile.TemporaryDirectory() as td:
            lp = self._ledger(td, [
                ("2026-01-01T00:00:00", [{"outcome": "rejected_scope", "detail": {}}], ["f"], three, None),
                ("2026-01-02T00:00:00", [{"outcome": "rejected_sorry_remains",
                                          "detail": {"counts_after": {"Specs/A.lean": 1}}}], ["f"], two, None),
                ("2026-01-03T00:00:00", [], ["g"], three, None),   # other plan: excluded
            ])
            ranked = seed.candidates(lp, "T", {"Specs/A.lean": ["f"]}, td)
            ids = [c["run_id"] for c in ranked["Specs/A.lean"]]
            self.assertEqual(ids, ["2026-01-02T00:00:00", "2026-01-01T00:00:00"])
            self.assertEqual(ranked["Specs/A.lean"][0]["proved"], 1)
            explicit = seed.candidates(lp, "T", {"Specs/A.lean": ["f"]}, td,
                                       explicit="runs/2026-01-01T000000")
            self.assertEqual([c["run_id"] for c in explicit["Specs/A.lean"]],
                             ["2026-01-01T00:00:00"])
            self.assertEqual(seed.candidates(lp, "other", {"Specs/A.lean": ["f"]}, td),
                             {"Specs/A.lean": []})


class ApplySeedTests(unittest.TestCase):
    """apply_seed with a fake `lake build`: first build fails inside the
    seeded file, the sanitized file then builds; a seed whose errors sit
    outside the seeded files is dropped and the skeleton restored."""

    def _slot(self, td):
        work = os.path.join(td, "work")
        os.makedirs(os.path.join(work, "Specs"))
        with open(os.path.join(work, "Specs", "A.lean"), "w") as fh:
            fh.write("-- skeleton\n")
        for c in (["init", "-q"], ["add", "-A"],
                  ["-c", "user.name=t", "-c", "user.email=t@e", "commit", "-q", "-m", "base"]):
            subprocess.run(["git", *c], cwd=work, check=True)
        src = os.path.join(td, "draft.lean")
        with open(src, "w") as fh:
            fh.write(DRAFT)
        return work, {"Specs/A.lean": {"file": src, "run_id": "r1", "attempt": 1, "errors": []}}

    def test_sanitize_until_green_then_commit(self):
        with tempfile.TemporaryDirectory() as td:
            work, chosen = self._slot(td)
            # errors refer to the file as written: heartbeat lines already gone
            written = seed.sanitize(DRAFT, [])[0].splitlines()
            bad_line = next(i + 1 for i, ln in enumerate(written)
                            if "a < undefined_thing :=" in ln)
            bad_col = written[bad_line - 1].index("undefined")
            outs = iter([
                (1, {}, 0.1, f"error: ./Specs/A.lean:{bad_line}:{bad_col}: unknown identifier\n"),
                (0, {"Specs/A.lean": 1}, 0.1, ""),
            ])
            with mock.patch.object(driver, "build_sorry_counts", side_effect=lambda *a, **k: next(outs)):
                rec, counts = seed.apply_seed(work, chosen, 10, log=lambda m: None)
            f = rec["files"][0]
            self.assertFalse(f["dropped_file"])
            self.assertEqual(f["decls_dropped"], ["bad_stmt", "uses_bad"])
            self.assertIn("cast_spec", f["decls_sorried"])
            self.assertEqual(counts, {"Specs/A.lean": 1})
            log = subprocess.run(["git", "log", "--oneline"], cwd=work,
                                 capture_output=True, text=True).stdout
            self.assertIn("seed: r1/attempt-1", log)
            self.assertNotIn("undefined_thing", open(os.path.join(work, "Specs", "A.lean")).read())

    def test_timeout_falls_back_to_statements_only(self):
        with tempfile.TemporaryDirectory() as td:
            work, chosen = self._slot(td)
            outs = iter([("timeout", {}, 10.0, ""), (0, {"Specs/A.lean": 5}, 0.1, "")])
            with mock.patch.object(driver, "build_sorry_counts", side_effect=lambda *a, **k: next(outs)):
                rec, _ = seed.apply_seed(work, chosen, 10, log=lambda m: None)
            f = rec["files"][0]
            self.assertFalse(f["dropped_file"])
            self.assertTrue(any(r.get("all_proofs") for r in f["sanitize_rounds"]))
            self.assertEqual(f["decls_proved"], ["pack"])

    def test_foreign_errors_drop_the_seed(self):
        with tempfile.TemporaryDirectory() as td:
            work, chosen = self._slot(td)
            outs = iter([(1, {}, 0.1, "error: ./Specs/Other.lean:1:1: boom\n"),
                         (0, {}, 0.1, "")])
            with mock.patch.object(driver, "build_sorry_counts", side_effect=lambda *a, **k: next(outs)):
                rec, _ = seed.apply_seed(work, chosen, 10, log=lambda m: None)
            f = rec["files"][0]
            self.assertTrue(f["dropped_file"])
            self.assertEqual(f["drop_reason"], "errors_outside_seed")
            self.assertEqual(open(os.path.join(work, "Specs", "A.lean")).read(), "-- skeleton\n")
            self.assertEqual(seed.seed_block(rec), "")


class GateRuleTests(unittest.TestCase):
    """Joint gate: a planned spec file must end sorry-free even when the
    (seeded) baseline had sorries in it."""

    def test_seeded_sorry_left_in_planned_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            for p in ("SpecA.lean", "Top.lean"):
                with open(os.path.join(work, p), "w") as fh:
                    fh.write("x\n")
            for c in (["init", "-q"], ["add", "-A"],
                      ["-c", "user.name=t", "-c", "user.email=t@e", "commit", "-q", "-m", "b"]):
                subprocess.run(["git", *c], cwd=work, check=True)
            fps = {"SpecA": {"A.spec": {"kind": "theorem", "canon": "a", "pp": "A",
                                        "consts": ["pkg.a"]}}, "Top": {}}

            def run(after):
                with mock.patch.object(driver, "build_sorry_counts",
                                       return_value=(0, after, 0.1, "")), \
                     mock.patch.object(driver, "stmt_fingerprints", return_value=(fps, 0.1)), \
                     mock.patch.object(driver, "progress_specs_for", return_value=["A.spec"]):
                    return driver.gate(work, "Top.lean", {"Top.lean": 1, "SpecA.lean": 3},
                                       g1_base={"SpecA": {}, "Top": {}}, g2=False, mode="joint",
                                       editable_paths=["SpecA.lean", "Top.lean"],
                                       callees={"pkg.a": "SpecA.lean"})

            outcome, detail = run({"Top.lean": 0, "SpecA.lean": 2})
            self.assertEqual(outcome, "rejected_sorry_remains")
            self.assertEqual(detail["path"], "SpecA.lean")
            outcome, _ = run({"Top.lean": 0})
            self.assertEqual(outcome, "accepted")


if __name__ == "__main__":
    unittest.main()
