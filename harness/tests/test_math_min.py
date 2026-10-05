"""Math pruning must preserve the meaning of retained declarations."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import build_without_internal_spec as bundle


class MathMinTests(unittest.TestCase):
    def make_minimizer(self, root):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = Path(tmp.name)
        rel = "Curve25519Dalek/Math/Validity.lean"
        text = (
            "structure Valid : Prop where\n"
            "  bounds : Bound\n"
            "  on_curve : True\n"
            "\n"
            "theorem unused : True := by trivial\n"
        )
        bound_rel = "Curve25519Dalek/Math/Bound.lean"
        for name, contents in [(rel, text), (bound_rel, "def Bound : Prop := True\n")]:
            dest = repo / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(contents)

        def record(name, file, start, end, deps):
            return {"display-name": name, "code-path": file,
                    "code-text": {"lines-start": start, "lines-end": end},
                    "is-in-package": True,
                    "dependencies": ["probe:" + dep for dep in deps]}

        data = {
            "probe:Valid": record("Valid", rel, 1, 3, []),
            "probe:Valid.bounds": record("Valid.bounds", rel, 2, 2, ["Valid", "Bound"]),
            "probe:Valid.on_curve": record("Valid.on_curve", rel, 3, 3, ["Valid"]),
            "probe:unused": record("unused", rel, 5, 5, []),
            "probe:Bound": record("Bound", bound_rel, 1, 1, []),
            "probe:spec": record("spec", "Curve25519Dalek/Specs/Test.lean", 1, 1, [root]),
        }
        (repo / "probe.json").write_text(json.dumps({"data": data}))
        with patch.object(bundle, "REPO", str(repo)):
            minimizer = bundle.MathMin("probe.json")
        return minimizer, rel, text

    def test_structure_retains_unused_fields_and_their_dependencies(self):
        mm, rel, text = self.make_minimizer("Valid")
        self.assertEqual(mm.keep, {"probe:Valid", "probe:Valid.bounds",
                                   "probe:Valid.on_curve", "probe:Bound"})
        self.assertEqual(mm.rewrite(rel, text), text[:text.index("theorem")])
        self.assertEqual(mm.removed[rel], ["unused"])
        self.assertNotIn("Curve25519Dalek.Math.Bound", mm.dropped_mods)

    def test_referenced_projection_preserves_sibling_fields(self):
        mm, rel, text = self.make_minimizer("Valid.on_curve")
        self.assertIn("probe:Valid.bounds", mm.keep)
        self.assertIn("bounds : Bound", mm.rewrite(rel, text))

    def test_unused_structure_can_still_be_removed_whole(self):
        mm, rel, text = self.make_minimizer("unused")
        self.assertEqual(mm.keep, {"probe:unused"})
        rewritten = mm.rewrite(rel, text)
        self.assertNotIn("structure", rewritten)
        self.assertNotIn("bounds", rewritten)
        self.assertIn("theorem unused", rewritten)
        self.assertIn("Curve25519Dalek.Math.Bound", mm.dropped_mods)

    def test_repository_edwards_validity_retains_all_fields(self):
        mm = bundle.MathMin(".verilib/probes/lean_bundle_Curve25519Dalek_0.1.0.json")
        prefix = "probe:curve25519_dalek.edwards.EdwardsPoint.IsValid"
        for field in ["X_bounds", "Y_bounds", "Z_bounds", "T_bounds", "T_relation",
                      "Z_ne_zero", "on_curve"]:
            self.assertIn(prefix + "." + field, mm.keep)
        rel = "Curve25519Dalek/Math/Edwards/Representation.lean"
        result = mm.rewrite(rel, bundle.read(rel))
        self.assertIn("X_bounds :", result)
        self.assertIn("T_relation :", result)


if __name__ == "__main__":
    unittest.main()
