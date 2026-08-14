#!/usr/bin/env python3
"""Deletion–resynthesis scaffolding for the spec budget curve (plan.md §8, 优先级 2).

Manages one "slice" (a module's top-level specs) through the cycle:

  init    build manifest from .verilib/top_level_specs.json: archive original
          file bytes, locate each spec's theorem block (+ its natural-language
          comment block), record the G1 v2 canonical statement fingerprint via
          harness/gates/StmtCanon.lean
  delete  remove the spec statements (mode `stmt`: theorem block only;
          mode `full`, default: also the natural-language spec comment) and
          leave a RESYNTH-TARGET marker telling the agent what to synthesize
  restore byte-exact restore of the original files (sha-verified)
  check   after the agent has re-synthesized (and `lake build` has succeeded):
          G1 statement identity (canon == baseline is DATA, not a gate — plan
          §10: stronger/weaker/incomparable are all informative outcomes) and
          N1 vocabulary audit (§9 obligation 1: no implementation functions
          other than the target in the statement; hard failure)

Usage:
  python3 harness/resynth.py init    --slice scalar
  python3 harness/resynth.py status  --slice scalar
  python3 harness/resynth.py delete  --slice scalar [--mode full|stmt] [--only from_spec,..]
  python3 harness/resynth.py restore --slice scalar
  python3 harness/resynth.py check   --slice scalar [--only ..]   # needs lake build first

`check` reads .olean files: run `lake build` after the agent edits, before check.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOP_SPECS = os.path.join(REPO, ".verilib", "top_level_specs.json")
STMT_CANON = os.path.join("harness", "gates", "StmtCanon.lean")
SLICES = {
    "scalar": "Curve25519Dalek/Specs/Scalar/Scalar/",
    "affine_niels": "Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/",
    "compressed_ristretto": "Curve25519Dalek/Specs/Ristretto/CompressedRistretto/",
}

THEOREM_NAME_RE = re.compile(
    r"^\s*(?:@\[[^\]]*\]\s*)*(?:private\s+|protected\s+)?theorem\s+([^\s:({\[⦃]+)",
    re.M)

MARKER = """/- ⟦RESYNTH-TARGET⟧ (spec deleted for re-synthesis; managed by harness/resynth.py)

Target function: `{function}`  (definition: Curve25519Dalek/Funs.lean)

Task: in this namespace, state a specification theorem named exactly `{short}`
for the target function, then prove it. The STATEMENT is yours to design. It
must pin down the function's behavior using only the frozen vocabulary:
Curve25519Dalek.Math.*, Aux/TypesAux definitions, Types field projections,
Mathlib, and Aeneas WP notation. Do NOT reference implementation functions
from Funs.lean/FunsExternal.lean other than the target itself. Attributes
like @[progress] / @[simp] are allowed. -/
"""


def sha(b):
    return hashlib.sha256(b).hexdigest()


def slice_dir(name):
    return os.path.join(REPO, "experiments", "spec_budget_curve", f"slice_{name}")


def manifest_path(name):
    return os.path.join(slice_dir(name), "manifest.json")


def load_manifest(name):
    with open(manifest_path(name)) as fh:
        return json.load(fh)


def save_manifest(name, m):
    os.makedirs(slice_dir(name), exist_ok=True)
    with open(manifest_path(name), "w") as fh:
        json.dump(m, fh, indent=2, ensure_ascii=False)


def run_stmt_canon(decl_names, extra_import=None, extra_lean_path=None):
    """Run StmtCanon on decl names → {name: record}."""
    cmd = ["lake", "env", "lean", "--run", STMT_CANON]
    if extra_import:
        cmd += ["--import", extra_import]
    cmd += decl_names
    env = dict(os.environ)
    if extra_lean_path:
        env["LEAN_PATH"] = extra_lean_path + ":" + env.get("LEAN_PATH", "")
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, env=env)
    if p.returncode != 0:
        sys.exit(f"StmtCanon failed:\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
    out = {}
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if ln.startswith("{"):
            rec = json.loads(ln)
            out[rec["name"]] = rec
    return out


# ── comment-block scanning (line-based; enough for this tree's style) ────
def comment_blocks(lines):
    """[(start,end,text)] 1-based inclusive, for `/- ...` blocks (not `/--`)."""
    blocks, i, n = [], 0, len(lines)
    while i < n:
        s = lines[i].lstrip()
        if s.startswith("/-") and not s.startswith("/--"):
            start, depth = i, 0
            txt = []
            while i < n:
                txt.append(lines[i])
                depth += lines[i].count("/-") - lines[i].count("-/")
                if depth <= 0:
                    break
                i += 1
            blocks.append((start + 1, i + 1, "\n".join(txt)))
        i += 1
    return blocks


def nl_block_for(blocks, thm_start):
    """The natural-language comment block ending just above the theorem block."""
    for (s, e, txt) in blocks:
        if "natural language" in txt and 0 <= thm_start - e <= 4:
            return (s, e)
    return None


# ── commands ─────────────────────────────────────────────────────────────
def cmd_init(args):
    prefix = SLICES[args.slice]
    tl = json.load(open(TOP_SPECS))["top-level-specs"]
    specs = [it for it in tl if it["spec-location"].startswith(prefix)]
    if not specs:
        sys.exit(f"no top-level specs under {prefix}")
    print(f"{len(specs)} top-level specs in slice `{args.slice}`")

    sdir = slice_dir(args.slice)
    refdir = os.path.join(sdir, "reference", "files")
    os.makedirs(refdir, exist_ok=True)

    entries, files = [], {}
    for it in specs:
        loc = it["spec-location"]
        path, rng = loc.split(":")
        lo, hi = (int(x) for x in rng.split("-"))
        full = os.path.join(REPO, path)
        if path not in files:
            data = open(full, "rb").read()
            files[path] = {"sha": sha(data), "lines": data.decode().splitlines()}
            with open(os.path.join(refdir, path.replace("/", "__")), "wb") as fh:
                fh.write(data)
        lines = files[path]["lines"]
        block = "\n".join(lines[lo - 1:hi])
        m = THEOREM_NAME_RE.search(block)
        if not m:
            sys.exit(f"{loc}: no `theorem` in lines {lo}-{hi}; stale probe data?")
        short = m.group(1)
        if not it["spec"].endswith(short):
            sys.exit(f"{loc}: block theorem `{short}` != spec `{it['spec']}`")
        nl = nl_block_for(comment_blocks(lines), lo)
        entries.append({
            "spec": it["spec"], "function": it["function"], "short": short,
            "file": path, "lines": [lo, hi], "nl_block": nl,
            "status": it.get("verification-status"),
        })

    print("elaborating canonical statement fingerprints (StmtCanon, ~1-3 min) …",
          flush=True)
    canon = run_stmt_canon([e["spec"] for e in entries])
    for e in entries:
        rec = canon.get(e["spec"])
        if not rec or not rec.get("found") or "error" in rec:
            sys.exit(f"StmtCanon could not elaborate {e['spec']}: {rec}")
        e["canon_sha"] = sha(rec["canon"].encode())
        e["pp"] = rec["pp"]
        e["consts"] = rec["consts"]

    save_manifest(args.slice, {
        "slice": args.slice, "prefix": prefix, "state": "intact",
        "files": {p: {"sha": f["sha"]} for p, f in files.items()},
        "specs": entries,
    })
    print(f"manifest written: {manifest_path(args.slice)}")


def selected(m, only):
    names = set(only.split(",")) if only else None
    return [e for e in m["specs"]
            if names is None or e["short"] in names or e["spec"] in names]


def cmd_delete(args):
    m = load_manifest(args.slice)
    if m["state"] == "deleted":
        sys.exit("slice already deleted; restore first")
    todo = selected(m, args.only)
    by_file = {}
    for e in todo:
        by_file.setdefault(e["file"], []).append(e)

    for path, es in by_file.items():
        full = os.path.join(REPO, path)
        data = open(full, "rb").read()
        if sha(data) != m["files"][path]["sha"]:
            sys.exit(f"{path} changed since init — re-run init on a clean slice")
        lines = data.decode().splitlines()
        cuts = []  # (start,end,replacement_lines)
        for e in es:
            lo, hi = e["lines"]
            marker = MARKER.format(function=e["function"], short=e["short"])
            cuts.append((lo, hi, marker.splitlines()))
            if args.mode == "full" and e["nl_block"]:
                s, t = e["nl_block"]
                cuts.append((s, t, []))
        for lo, hi, repl in sorted(cuts, reverse=True):
            lines[lo - 1:hi] = repl
        with open(full, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"deleted {len(es)} spec(s) from {path}")

    m["state"] = "deleted"
    m["deleted"] = {"mode": args.mode, "specs": [e["spec"] for e in todo]}
    save_manifest(args.slice, m)
    print(f"{len(todo)} spec(s) deleted (mode={args.mode}). "
          f"Restore with: python3 harness/resynth.py restore --slice {args.slice}")


def cmd_restore(args):
    m = load_manifest(args.slice)
    refdir = os.path.join(slice_dir(args.slice), "reference", "files")
    for path, info in m["files"].items():
        ref = os.path.join(refdir, path.replace("/", "__"))
        data = open(ref, "rb").read()
        assert sha(data) == info["sha"], f"archive corrupt for {path}"
        with open(os.path.join(REPO, path), "wb") as fh:
            fh.write(data)
        print(f"restored {path}")
    m["state"] = "intact"
    m.pop("deleted", None)
    save_manifest(args.slice, m)


IMPL_MODULES = ("Curve25519Dalek.Funs", "Curve25519Dalek.FunsExternal")


def vocab_violations(entry, consts):
    """§9 obligation (1): implementation functions other than the target,
    leftover Specs-module constants, or script-local constants."""
    bad = []
    for c in consts:
        mod, name = c["module"], c["name"]
        if mod in IMPL_MODULES and name != entry["function"]:
            bad.append({"const": name, "module": mod, "why": "impl function ≠ target"})
        elif mod.startswith("Curve25519Dalek.Specs"):
            bad.append({"const": name, "module": mod, "why": "survived normalization"})
        elif mod == "<local>":
            bad.append({"const": name, "module": mod, "why": "not from any module"})
    return bad


def cmd_check(args):
    m = load_manifest(args.slice)
    todo = selected(m, args.only)
    print(f"checking {len(todo)} spec(s) (reads .olean — run `lake build` first) …",
          flush=True)
    canon = run_stmt_canon([e["spec"] for e in todo])
    report, hard_fail = [], False
    for e in todo:
        rec = canon.get(e["spec"], {})
        if not rec.get("found"):
            report.append({"spec": e["spec"], "verdict": "MISSING"})
            hard_fail = True
            continue
        if "error" in rec:
            report.append({"spec": e["spec"], "verdict": "ERROR", "error": rec["error"]})
            hard_fail = True
            continue
        identical = sha(rec["canon"].encode()) == e["canon_sha"]
        bad = vocab_violations(e, rec["consts"])
        if bad:
            hard_fail = True
        report.append({
            "spec": e["spec"],
            "verdict": "G1-IDENTICAL" if identical else "G1-DIFFERENT",
            "vocab_violations": bad,
            **({} if identical else {"pp_synth": rec["pp"], "pp_reference": e["pp"]}),
        })
    out = os.path.join(slice_dir(args.slice), "check_report.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    for r in report:
        v = r["verdict"] + (" +VOCAB" if r.get("vocab_violations") else "")
        print(f"  {v:20s} {r['spec']}")
    print(f"report: {out}")
    if hard_fail:
        sys.exit("hard failures present (missing decl / elaboration error / "
                 "vocabulary violation)")
    print("note: G1-DIFFERENT is data, not failure — compare pp_synth vs "
          "pp_reference, then prove synth_eq_human (plan §10)")


def cmd_status(args):
    m = load_manifest(args.slice)
    print(f"slice `{m['slice']}`  state={m['state']}  "
          f"{len(m['specs'])} specs over {len(m['files'])} files")
    if m.get("deleted"):
        print(f"deleted mode={m['deleted']['mode']}: "
              f"{len(m['deleted']['specs'])} specs")
    for e in m["specs"]:
        print(f"  {e['short']:35s} {e['file']}:{e['lines'][0]}-{e['lines'][1]}"
              + ("  [nl]" if e["nl_block"] else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["init", "status", "delete", "restore", "check"])
    ap.add_argument("--slice", required=True, choices=sorted(SLICES))
    ap.add_argument("--mode", default="full", choices=["full", "stmt"])
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    {"init": cmd_init, "status": cmd_status, "delete": cmd_delete,
     "restore": cmd_restore, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    main()
