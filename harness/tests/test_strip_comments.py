"""Unit tests for harness/strip_comments.py.  Run: python3 -m unittest discover harness/tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import strip_comments as sc  # noqa: E402

ORIG = """/-
Copyright header
-/
import Foo

/-! # Module doc
proof sketch: use lemma_x
-/

open Bar

/-- Doc for helper: `x -- not a comment` -/
theorem helper (x : Nat) : x = x := rfl  -- trailing hint

/- natural language spec:
  • step 1
  • step 2
-/

/-- **Spec** for main.
Hint: apply helper then simp
-/
@[progress]
theorem main_spec (s : String) (c : Char) :
    s = "a -- b /- c" ∧ c ≠ '-' ∧ '\\n' = '\\n' := by
  sorry
end Bar
"""


class StripTests(unittest.TestCase):
    def test_line_preserving_and_no_comments_left(self):
        st, n = sc.strip(ORIG)
        self.assertEqual(st.count("\n"), ORIG.count("\n"))
        self.assertEqual(n, 6)
        self.assertEqual(sc.comment_spans(st), [])
        self.assertNotIn("Hint", st)
        self.assertNotIn("sketch", st)
        self.assertIn('s = "a -- b /- c"', st)          # string kept
        self.assertIn("c ≠ '-'", st)                     # char literal kept
        self.assertIn("theorem helper (x : Nat) : x = x := rfl", st)
        self.assertTrue(all(l == l.rstrip() for l in st.split("\n")))

    def test_nested_block_and_primes(self):
        t = "theorem x' (h'' : a) : b := /- outer /- inner -/ still -/ by\n  exact h''\n"
        st, n = sc.strip(t)
        self.assertEqual(n, 1)
        self.assertEqual(st, "theorem x' (h'' : a) : b :=  by\n  exact h''\n")
        self.assertIn("exact h''", st)

    def test_raw_string_and_guillemets(self):
        t = 'def s := r#"has -- and /- inside"#\ndef «weird -- name» := 1 -- real\n'
        st, n = sc.strip(t)
        self.assertEqual(n, 1)
        self.assertIn('r#"has -- and /- inside"#', st)
        self.assertIn("«weird -- name» := 1", st)
        self.assertNotIn("real", st)

    def test_unterminated_block_raises(self):
        with self.assertRaises(ValueError):
            sc.strip("/- open\n")

    def test_idempotent_on_repo_files(self):
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        for rel in ("Curve25519Dalek/Specs/Scalar/Scalar/Mul.lean",
                    "Curve25519Dalek/Math/Basic.lean"):
            p = os.path.join(root, rel)
            if not os.path.exists(p):
                continue
            with open(p, encoding="utf-8") as fh:
                t = fh.read()
            st, _ = sc.strip(t)
            self.assertEqual(sc.strip(st), (st, 0))


class MergeTests(unittest.TestCase):
    def _agent(self, edit):
        st, _ = sc.strip(ORIG)
        return edit(st)

    def test_fill_sorry(self):
        acc = self._agent(lambda s: s.replace("  sorry", "  constructor\n  · rfl\n  · simp"))
        merged = sc.merge_back(ORIG, acc)
        self.assertIn("Copyright header", merged)
        self.assertIn("Hint: apply helper then simp", merged)
        self.assertIn("-- trailing hint", merged)
        self.assertIn("  constructor\n  · rfl\n  · simp\nend Bar", merged)
        self.assertNotIn("sorry", merged)
        # Every comment of the original survives.
        self.assertEqual(len(sc.comment_spans(merged)), len(sc.comment_spans(ORIG)))

    def test_insert_helper_before_docstringed_theorem(self):
        acc = self._agent(lambda s: s.replace(
            "@[progress]\ntheorem main_spec",
            "theorem aux (n : Nat) : n + 0 = n := by simp\n\n@[progress]\ntheorem main_spec"))
        merged = sc.merge_back(ORIG, acc)
        # the new lemma must not be swallowed by the /-- Spec -/ docstring
        i_aux = merged.index("theorem aux")
        i_doc = merged.index("/-- **Spec** for main.")
        i_main = merged.index("@[progress]\ntheorem main_spec")
        self.assertTrue(i_aux < i_doc < i_main, merged)
        self.assertEqual(len(sc.comment_spans(merged)), len(sc.comment_spans(ORIG)))

    def test_insert_into_blank_run_is_relocated_before_block(self):
        # The agent inserts a lemma into the blank lines that used to be the
        # `/- natural language spec -/` block: the merge must move it before
        # the block, never inside it.
        def edit(s):
            lines = s.split("\n")
            k = ORIG.split("\n").index("  • step 1")
            lines[k:k] = ["lemma inner : True := trivial"]
            return "\n".join(lines)
        acc = self._agent(edit)
        merged = sc.merge_back(ORIG, acc)
        self.assertIn("lemma inner : True := trivial", merged)
        self.assertLess(merged.index("lemma inner"), merged.index("/- natural language spec"))
        self.assertEqual(len(sc.comment_spans(merged)), len(sc.comment_spans(ORIG)))

    def test_delete_comment_line_keeps_block_balanced(self):
        def edit(s):
            lines = s.split("\n")
            k = ORIG.split("\n").index("  • step 1")
            del lines[k]
            return "\n".join(lines)
        acc = self._agent(edit)
        merged = sc.merge_back(ORIG, acc)
        sc.comment_spans(merged)   # balanced: no ValueError
        self.assertIn("• step 2", merged)

    def test_replace_code_line_with_trailing_comment(self):
        acc = self._agent(lambda s: s.replace(
            "theorem helper (x : Nat) : x = x := rfl",
            "theorem helper (x : Nat) : x = x := by rfl"))
        merged = sc.merge_back(ORIG, acc)
        self.assertIn("theorem helper (x : Nat) : x = x := by rfl", merged)
        self.assertNotIn("-- trailing hint", merged)   # line comment of a replaced line goes

    def test_second_round_with_agent_comments(self):
        acc1 = self._agent(lambda s: s.replace(
            "  sorry", "  /- agent note -/\n  -- agent line\n  constructor <;> simp"))
        merged1 = sc.merge_back(ORIG, acc1)
        # second accept: agent edits the merged-then-stripped file again
        st1, _ = sc.strip(merged1)
        acc2 = st1.replace("theorem helper (x : Nat) : x = x := rfl",
                           "theorem helper (x : Nat) : x = x := by rfl")
        # what the slot actually holds is acc1 with the new edit, comments included
        acc2_slot = acc1.replace("theorem helper (x : Nat) : x = x := rfl",
                                 "theorem helper (x : Nat) : x = x := by rfl")
        merged2 = sc.merge_back(merged1, acc2_slot)
        self.assertEqual(merged2.count("/- agent note -/"), 1)
        self.assertEqual(merged2.count("-- agent line"), 1)
        self.assertIn(":= by rfl", merged2)
        self.assertIn("Hint: apply helper then simp", merged2)
        del acc2

    def test_agent_deleting_theorem_is_rejected(self):
        acc = self._agent(lambda s: s.replace("theorem helper (x : Nat) : x = x := rfl", ""))
        # the code differs only by a deletion: merge still reproduces the
        # agent's code, so it is accepted here (G1 rejects it upstream)
        merged = sc.merge_back(ORIG, acc)
        self.assertNotIn("theorem helper", merged)

    def test_invariant_failure_raises(self):
        # A pathological accepted text whose code cannot be reproduced.
        acc = self._agent(lambda s: s)
        # Corrupt: feed an accepted file whose line count is fine but which
        # opens a block comment the merge cannot see through.
        acc = acc.replace("open Bar", "open Bar /- oops")
        with self.assertRaises((sc.MergeError, ValueError)):
            sc.merge_back(ORIG, acc)


if __name__ == "__main__":
    unittest.main()
