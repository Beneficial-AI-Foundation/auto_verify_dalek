#!/usr/bin/env python3
"""G2 trust-base closure gate (plan.md §7).

Checks, against the frozen artifacts in harness/frozen/:

  1. frozen-file integrity: sha256 of Math/, Funs/Types(+External), Tactics,
     ExternallyVerified, lakefile/toolchain/manifest unchanged
  2. axiom closure of every Math declaration is inside the whitelist
       {propext, Classical.choice, Quot.sound} ∪ sorryAx
       ∪ 21 external axioms ∪ {Lean.ofReduceBool, Lean.trustCompiler}
     (native_decide is allowed by policy; sites are ledgered against
     native_decide_sites.json — new roots are reported, not failed.
     The forbidden path is new @[implemented_by]/@[extern] attributes,
     which can hijack native_decide; phase-2 gate must scan agent files
     for those)
  3. no axiom declaration anywhere in Curve25519Dalek.* outside
     FunsExternal/TypesExternal; no @[externally_verified] tag in Math
  4. the assumption set (Math decls whose own body mentions sorryAx) equals
     exactly the frozen list, statement hashes identical
  5. sorry warnings from `lake build`: the Math zone contains exactly the
     frozen source locations' files; no sorry appears outside the zones
     recorded in .verilib/sorry_inventory.json (shrinking is allowed and
     expected during phase 2; growing or migrating is a violation)

Exit 0 = gate passes. Exit 1 = violation (details on stdout).
Run from repo root:  python3 harness/gates/g2_trust_base.py
Pass --skip-build to reuse an existing build (skips check 5).
"""
import json, hashlib, subprocess, sys, os, re
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FROZEN = os.path.join(REPO, "harness", "frozen")
BASE3 = {"propext", "Classical.choice", "Quot.sound"}
failures = []

def fail(msg):
    failures.append(msg)
    print(f"✗ {msg}")

def ok(msg):
    print(f"✓ {msg}")

# ── 1. frozen file hashes ────────────────────────────────────────────────
for line in open(os.path.join(FROZEN, "frozen_files.sha256")):
    want, path = line.split(None, 1)
    path = path.strip()
    got = hashlib.sha256(open(os.path.join(REPO, path), "rb").read()).hexdigest()
    if got != want:
        fail(f"frozen file modified: {path}")
if not failures:
    ok("frozen files unchanged")

# ── 2–4. Lean-side audit ─────────────────────────────────────────────────
audit = subprocess.run(
    ["lake", "env", "lean", "harness/phase0_audit.lean"],
    cwd=REPO, capture_output=True, text=True)
if "AUDIT DONE" not in audit.stdout:
    fail("audit script did not complete")
    print(audit.stdout[-2000:], audit.stderr[-2000:])
    sys.exit(1)

extax, pkgax, srcsorry, types, extver = set(), [], set(), {}, []
violations = defaultdict(set)
for ln in audit.stdout.splitlines():
    parts = ln.split()
    if ln.startswith("EXTAX "):
        extax.add(parts[1])
    elif ln.startswith("PKGAXIOM "):
        pkgax.append((parts[1], parts[2]))
    elif ln.startswith("SRCSORRY "):
        srcsorry.add(parts[2])
    elif ln.startswith("EXTVERIFIED "):
        extver.append(parts[1])
    elif ln.startswith("VIOLATION "):
        violations[parts[2]].add(parts[1])
    elif ln.startswith("TYPE "):
        m = re.match(r"TYPE (\S+) ⊢ (.*)", ln)
        if m:
            types[m.group(1)] = m.group(2).strip()

frozen_ext = json.load(open(os.path.join(FROZEN, "external_axioms.json")))
if extax != set(frozen_ext["axioms"]):
    fail(f"external axiom set drifted: +{extax - set(frozen_ext['axioms'])} "
         f"-{set(frozen_ext['axioms']) - extax}")
else:
    ok(f"external axioms: exactly the frozen {len(extax)}")

if pkgax:
    fail(f"axiom declared outside FunsExternal/TypesExternal: {pkgax}")
else:
    ok("no new axiom declarations in the package")

if extver:
    fail(f"@[externally_verified] tag in Math: {extver}")
else:
    ok("no @[externally_verified] in Math")

nd = json.load(open(os.path.join(FROZEN, "native_decide_sites.json")))
nd_allowed = set(nd["trusted_axioms"])
for ax, decls in sorted(violations.items()):
    if ax not in nd_allowed:
        fail(f"axiom outside whitelist in Math closure: {ax} (used by {sorted(decls)[:5]}…)")
roots = {re.sub(r"\._proof.*|\.eq_def$", "", d)
         for ds in (violations.get(a, set()) for a in nd_allowed) for d in ds}
new_nd = roots - set(nd["declarations"])
if new_nd:
    # ofReduceBool reaching a decl outside the frozen roots means a new
    # native_decide site (frozen-file check would also trip if it's in Math)
    print(f"  note: compiler-axiom closure roots beyond frozen list: {sorted(new_nd)[:10]}")
if set(violations) <= nd_allowed:
    ok("Math axiom closure ⊆ whitelist (base3 ∪ sorryAx ∪ external ∪ native_decide)")

frozen_asm = json.load(open(os.path.join(FROZEN, "math_assumptions.json")))
want_names = {a["name"] for a in frozen_asm["assumptions"]}
if srcsorry != want_names:
    fail(f"assumption set drifted: +{srcsorry - want_names} -{want_names - srcsorry}")
else:
    ok(f"assumption set: exactly the frozen {len(want_names)} declarations")
for a in frozen_asm["assumptions"]:
    got = types.get(a["name"])
    if got is None:
        continue  # already reported as set drift
    if hashlib.sha256(got.encode()).hexdigest() != a["statement_sha256"]:
        fail(f"assumption statement drifted: {a['name']}")
if not any("statement drifted" in f for f in failures):
    ok("assumption statements: hashes identical")

# ── 5. sorry warnings from build ─────────────────────────────────────────
if "--skip-build" not in sys.argv:
    build = subprocess.run(["lake", "build"], cwd=REPO, capture_output=True, text=True)
    if build.returncode != 0:
        fail("lake build failed")
    warns = {ln.split(" declaration")[0].removeprefix("warning: ").rstrip(":")
             for ln in (build.stdout + build.stderr).splitlines()
             if "declaration uses `sorry`" in ln}
    inv = json.load(open(os.path.join(REPO, ".verilib", "sorry_inventory.json")))
    known = {loc for locs in inv["locations"].values() for loc in locs}
    known_files = {loc.split(":")[0] for loc in known}
    math_files_frozen = {a["source"].split(":")[0] for a in frozen_asm["assumptions"]}
    for w in sorted(warns):
        f = w.split(":")[0]
        if f.startswith("Curve25519Dalek/Math/") and f not in math_files_frozen:
            fail(f"new sorry in Math outside frozen assumption files: {w}")
        elif f not in known_files:
            fail(f"sorry in a file with no inventoried sorries: {w}")
    math_now = {w.split(":")[0] for w in warns if w.startswith("Curve25519Dalek/Math/")}
    if math_now - math_files_frozen:
        pass  # already failed above
    else:
        ok(f"build sorry warnings consistent with inventory "
           f"({len(warns)} decls; inventory had {inv['total']})")

print()
if failures:
    print(f"G2: FAIL ({len(failures)} violation(s))")
    sys.exit(1)
print("G2: PASS")
