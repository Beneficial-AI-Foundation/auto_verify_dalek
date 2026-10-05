"""Scoped Lean command prefixes must be pruned with their declarations."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import build_without_internal_spec as bundle


class SpecPruningTests(unittest.TestCase):
    def test_scoped_prefixes_across_blank_lines_are_removed(self):
        text = """namespace Example
set_option maxRecDepth 1000

set_option maxHeartbeats 400000 in

-- A comment between scoped prefixes.
open Nat in

/-- A theorem that will be removed. -/

@[simp]

theorem discard : True := by
  trivial

end Example
"""
        result, removed = bundle.remove_theorems(text)
        self.assertEqual(removed, 1)
        self.assertIn("set_option maxRecDepth 1000", result)
        for fragment in ["maxHeartbeats", "open Nat in", "@[simp]", "discard"]:
            self.assertNotIn(fragment, result)
        self.assertIn("namespace Example", result)
        self.assertIn("end Example", result)

    def test_kept_theorem_preserves_its_prefix_and_neighbors(self):
        text = """namespace Example
set_option maxHeartbeats 1000 in

theorem keep : True := by
  trivial

set_option maxRecDepth 2000 in

theorem discard : True := by
  trivial

def after : Nat := 1
end Example
"""
        result, removed, kept, names = bundle.filter_theorems(text, {"Example.keep"})
        self.assertEqual((removed, kept, names), (1, 1, ["Example.keep"]))
        self.assertEqual(result.count("theorem keep"), 1)
        self.assertEqual(result.count("set_option maxHeartbeats 1000 in"), 1)
        self.assertNotIn("maxRecDepth", result)
        self.assertIn("def after : Nat := 1", result)

    def test_real_stubs_have_no_dangling_scoped_options(self):
        for rel in [
            "Backend/Serial/U64/Scalar/Scalar52/ToBytes.lean",
            "Backend/Serial/U64/Scalar/Scalar52/MulInternal.lean",
            "Backend/Serial/U64/Scalar/Scalar52/Sub.lean",
            "Backend/Serial/U64/Field/FieldElement51/Reduce.lean",
        ]:
            with self.subTest(file=rel):
                result, _ = bundle.remove_theorems(bundle.read(bundle.SPECS_DIR + "/" + rel))
                self.assertNotRegex(result, r"set_option\s+maxHeartbeats[^\n]*\bin\s*(?:end|$)")


if __name__ == "__main__":
    unittest.main()
