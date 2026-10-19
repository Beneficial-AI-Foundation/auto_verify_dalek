"""Pure controller snapshot authorization; no source execution or model calls."""
import unittest
from autofv import reviewed_snapshot
from autofv.contracts import ContractError, canonical_json_bytes

BASE = "namespace Demo\ndef value (n : Nat) := n\nend Demo\n"
CANON = "theorem Demo.value_spec (n : Nat) : value n = n"
SOURCE = BASE.replace("end Demo", "theorem value_spec (n : Nat) : value n = n := by sorry\nend Demo")


class ReviewedSnapshotTests(unittest.TestCase):
    def snapshot(self, source=SOURCE):
        return reviewed_snapshot.make(declaration="Demo.value_spec", canon=CANON,
            path="Demo.lean", source=source, baseline_source=BASE, base_commit="a" * 40,
            review_sha256="b" * 64)

    def validate(self, snapshot, **kwargs):
        return reviewed_snapshot.validate(snapshot, declaration="Demo.value_spec", canon=CANON,
            base_commit="a" * 40, baseline_source=BASE, **kwargs)

    def test_snapshot_binds_context_without_using_a_final_proof(self):
        snapshot = self.snapshot()
        self.assertEqual(self.validate(snapshot), snapshot)
        self.assertIn("by sorry", snapshot["source"])
        self.assertNotIn("rfl", snapshot["source"])

    def test_snapshot_rejects_hash_identity_and_pristine_source_drift(self):
        for field, value in (("source", SOURCE + "-- changed\n"), ("declaration", "Demo.other"),
                             ("canon_sha256", "0" * 64), ("base_commit", "c" * 40),
                             ("base_source_sha256", "d" * 64), ("path", "../Demo.lean")):
            with self.subTest(field=field):
                snapshot = {**self.snapshot(), field: value}
                snapshot["snapshot_sha256"] = reviewed_snapshot._sha(canonical_json_bytes(
                    {k: v for k, v in snapshot.items() if k != "snapshot_sha256"}))
                with self.assertRaises(ContractError):
                    self.validate(snapshot)

    def test_unapproved_executable_elaboration_is_refused_before_build(self):
        for code in ("initialize dangerous : IO Unit := pure ()\n", "#eval (0 : Nat)\n",
                     "macro \"bad\" : term => `(True)\n", "elab \"bad\" : command => pure ()\n",
                     "def newMeaning : Prop := True\n", "import Unapproved\n", "@[step]\n",
                     "-- disguised separator\u2028initialize bad : IO Unit := pure ()\n"):
            with self.subTest(code=code), self.assertRaises(ContractError):
                self.snapshot(SOURCE + code)
        with self.assertRaises(ContractError):
            self.snapshot(SOURCE.replace("by sorry", "by run_tac pure (); sorry"))

    def test_original_context_is_preserved_but_new_proof_bodies_are_not_expectations(self):
        with self.assertRaises(ContractError):
            self.snapshot(SOURCE.replace("by sorry", "by rfl"))
        with self.assertRaises(ContractError):
            self.snapshot(SOURCE.replace("def value (n : Nat) := n", "def value (n : Nat) := n + 1"))
        nested = SOURCE.replace("theorem value_spec", "/- ordinary /- nested -/ documentation -/\ntheorem value_spec")
        self.assertEqual(self.snapshot(nested)["source"], nested)
        with self.assertRaises(ContractError):
            self.snapshot(SOURCE + "/- unclosed")
        with self.assertRaises(ContractError):
            self.snapshot(SOURCE.replace("theorem value_spec", "open Other\ntheorem value_spec"))
        with self.assertRaises(ContractError):
            self.snapshot(SOURCE.replace("theorem value_spec", "namespace Other\ntheorem value_spec"))


if __name__ == '__main__':
    unittest.main()
