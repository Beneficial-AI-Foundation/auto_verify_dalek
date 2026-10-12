"""Planner: callees of `partial_fixpoint` loops are recovered from Funs.lean.

probe-lean records such a loop's only dependency as `<loop>.mutual`, an
auxiliary without a probe entry, so `dependencies` alone loses every function
the loop body calls (montgomery `mul_loop` -> `differential_add_and_double`)."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import prove_top_spec as pts  # noqa: E402

FUNS = """\
def pkg.step (x : Nat) : Result Nat := ok x

def pkg.ext (x : Nat) : Result Nat := ok x

@[rust_loop]
def pkg.mul_loop (x : Nat) (i : Nat) : Result Nat := do
  let y ← pkg.step x
  let z ← pkg.ext y
  pkg.mul_loop z i
partial_fixpoint

def pkg.mul (x : Nat) : Result Nat := pkg.mul_loop x 3
"""


def entry(path, start, end, deps):
    return {"kind": "def", "code-path": path, "dependencies": deps,
            "code-text": {"lines-start": start, "lines-end": end}}


class PlanCalleeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Path(self.tmp.name, "Curve25519Dalek").mkdir()
        Path(self.tmp.name, "Curve25519Dalek/Funs.lean").write_text(FUNS)
        F = "Curve25519Dalek/Funs.lean"
        self.data = {
            "probe:curve25519_dalek.pkg.step": entry(F, 1, 1, []),
            "probe:curve25519_dalek.pkg.ext": entry("Curve25519Dalek/FunsExternal.lean", 3, 3, []),
            "probe:curve25519_dalek.pkg.mul_loop": entry(F, 5, 10, ["probe:curve25519_dalek.pkg.mul_loop.mutual"]),
            "probe:curve25519_dalek.pkg.mul": entry(F, 12, 12, ["probe:curve25519_dalek.pkg.mul_loop"]),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_body_callees_scans_the_loop_block(self):
        got = pts.body_callees(self.tmp.name, self.data, "probe:curve25519_dalek.pkg.mul_loop")
        self.assertEqual(got, ["probe:curve25519_dalek.pkg.step"])  # ext is external, self excluded
        self.assertEqual(pts.body_callees(self.tmp.name, self.data, "probe:curve25519_dalek.nope"), [])

    def test_callee_order_without_extra_loses_the_step(self):
        order, _, _ = pts.callee_order(self.data, "probe:curve25519_dalek.pkg.mul", set())
        self.assertEqual(order, ["probe:curve25519_dalek.pkg.mul_loop"])

    def test_callee_order_with_extra_recovers_the_step_before_the_loop(self):
        extra = lambda f: pts.body_callees(self.tmp.name, self.data, f)
        order, callers, _ = pts.callee_order(self.data, "probe:curve25519_dalek.pkg.mul", set(), extra=extra)
        self.assertEqual(order, ["probe:curve25519_dalek.pkg.step", "probe:curve25519_dalek.pkg.mul_loop"])
        self.assertEqual(callers["probe:curve25519_dalek.pkg.step"], ["probe:curve25519_dalek.pkg.mul_loop"])


if __name__ == "__main__":
    unittest.main()
