#!/usr/bin/env python3
"""G1 v2 + N1 negative/positive tests against the G1Test fixture.

Compiles harness/gates/tests/G1Test.lean to a scratch .olean, then runs
StmtCanon over the fixture decls together with the real baselines and asserts
every expected verdict (see fixture header). Run from repo root:

    python3 harness/gates/tests/test_g1.py
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "harness"))
from resynth import run_stmt_canon, vocab_violations  # noqa: E402

NS = "curve25519_dalek.scalar.Scalar"


def main():
    os.chdir(REPO)
    scratch = tempfile.mkdtemp(prefix="g1test_")
    olean = os.path.join(scratch, "G1Test.olean")
    print("compiling fixture (imports full package; ~1-3 min) …", flush=True)
    p = subprocess.run(
        ["lake", "env", "lean", "-o", olean, os.path.join(HERE, "G1Test.lean")],
        cwd=REPO, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"fixture failed to compile:\n{p.stdout[-3000:]}\n{p.stderr[-1000:]}")

    decls = [f"{NS}.{d}" for d in
             ("ZERO_spec", "invert_spec",  # baselines
              "zero_copy", "invert_renamed", "zero_alias", "zero_weak",
              "zero_instattack", "zero_vocab_bad")]
    print("running StmtCanon …", flush=True)
    recs = run_stmt_canon(decls, extra_import="G1Test", extra_lean_path=scratch)

    def canon(short):
        r = recs[f"{NS}.{short}"]
        assert r.get("found") and "error" not in r, f"{short}: {r}"
        return r["canon"]

    failures = []

    def check(label, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {label}")
        if not cond:
            failures.append(label)

    check("zero_copy == ZERO_spec (verbatim restatement)",
          canon("zero_copy") == canon("ZERO_spec"))
    check("invert_renamed == invert_spec (α-invariance)",
          canon("invert_renamed") == canon("invert_spec"))
    check("zero_alias == ZERO_spec (helper-def unfolding)",
          canon("zero_alias") == canon("ZERO_spec"))
    check("zero_weak != ZERO_spec (weaker statement detected)",
          canon("zero_weak") != canon("ZERO_spec"))
    check("zero_instattack != ZERO_spec (instance swap detected)",
          canon("zero_instattack") != canon("ZERO_spec"))
    pp_same = recs[f"{NS}.zero_instattack"]["pp"] == recs[f"{NS}.ZERO_spec"]["pp"]
    print(f"        (instattack pretty-print identical to original: {pp_same}"
          " — this is the attack surface pp-comparison misses)")

    entry_zero = {"function": f"{NS}.ZERO"}
    check("zero_vocab_bad has N1 violation (mentions to_bytes)",
          any(v["const"] == f"{NS}.to_bytes"
              for v in vocab_violations(entry_zero, recs[f"{NS}.zero_vocab_bad"]["consts"])))
    check("zero_copy has no N1 violation (target itself is allowed)",
          vocab_violations(entry_zero, recs[f"{NS}.zero_copy"]["consts"]) == [])

    if failures:
        sys.exit(f"\n{len(failures)} test(s) FAILED")
    print("\nall G1/N1 tests passed")


if __name__ == "__main__":
    main()
