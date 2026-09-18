#!/usr/bin/env python3
"""Prove ONE top-level spec theorem of the agent bundle (dalek-top-spec-only).

Same agent loop and gates as harness/driver.py (imported, not copied):
sealed slot copy, isolated CLAUDE_CONFIG_DIR + bwrap, multi-round
`--resume`, scope / forbidden-attr / build / G1 statement identity /
sorry-count gates, rollback. Differences from driver.py:

  * the workspace is a copy of the BUNDLE, not of this checkout: the agent
    sees only Funs, the minimized Math/, Aux and the sorried top specs;
  * G2 (trust-base manifests of the main checkout) is skipped — the bundle
    has no harness/frozen; the ledger record says so;
  * one target, chosen by dependency-closure size: the kept top spec
    theorems (bundle_manifest.json `kept_theorems`) are ranked by the number
    of in-package declarations their statement transitively depends on in
    the bundle probe (--probe), smallest first. --list prints the ranking,
    --target NAME picks one, default is the smallest;
  * an accepted proof is copied back into the bundle file (and, with
    --commit, committed here). Nothing is written to Curve25519Dalek/ of
    this checkout;
  * --bottom-up: the bundle strips every internal spec, so a top spec
    whose function calls other Funs.lean functions needs their specs
    first. The plan walks the callee graph leaves-first, one internal
    function per step: the agent writes AND proves a `@[progress]` spec
    for it in that function's own spec file (created as a skeleton, and
    imported from Curve25519Dalek.lean, by the harness before the sealed
    baseline), gate mode "spec" (zero sorry in the file, a progress
    theorem mentioning the function; driver.gate). The last step is the
    top spec itself, gate mode "fill" as before. Every step is one file.
    Accepted internal specs are copied back into the bundle and recorded
    in <bundle>/internal_specs.json, so later targets skip them. A failed
    step ends the plan; earlier accepted steps are kept.

Ledger: ledger/top_spec_rounds.jsonl (one record per attempt; transcripts
in ledger/transcripts/topspec_*.jsonl like the driver's).

Usage:
  python3 harness/prove_top_spec.py --list
  python3 harness/prove_top_spec.py --dry-run                     # show pick + prompt
  python3 harness/prove_top_spec.py --model claude-sonnet-5       # smallest closure
  python3 harness/prove_top_spec.py --model <id> --target curve25519_dalek.scalar.Scalar.to_bytes_spec
  python3 harness/prove_top_spec.py --bottom-up --target curve25519_dalek.IdentityCurveModelsProjectivePoint.identity_spec --dry-run
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentproc  # noqa: E402
import driver  # noqa: E402

BUNDLE = "dalek-top-spec-only"
PROBE = ".verilib/probes/lean_bundle_Curve25519Dalek_0.1.0.json"
PROBE_FULL = ".verilib/probes/lean_Curve25519Dalek_0.1.0.json"  # human repo: where each spec lives
INTERNAL_SPECS = "internal_specs.json"  # <bundle>/: accepted internal specs {fn: {path, theorems, run_id}}
ROOT_MODULE = "Curve25519Dalek.lean"
LEDGER = os.path.join(REPO, "ledger", "top_spec_rounds.jsonl")
STMT_CANON_REL = os.path.join("harness", "gates", "StmtCanon.lean")
SLOT_EXCLUDES = (".git", ".lake/packages")


# ── candidates ───────────────────────────────────────────────────────────
def rank_candidates(bundle, probe_path):
    """[(closure, funs, math, name, path)] for every kept top spec theorem,
    smallest dependency closure first."""
    manifest = json.load(open(os.path.join(REPO, bundle, "bundle_manifest.json")))
    data = json.load(open(os.path.join(REPO, probe_path)))["data"]
    rows = []
    for path, names in sorted(manifest["kept_theorems"].items()):
        for name in names:
            pid = "probe:" + name
            if pid not in data:
                rows.append((None, None, None, name, path))
                continue
            seen, stack = set(), [pid]
            while stack:
                for x in data[stack.pop()]["dependencies"]:
                    if x in data and x not in seen and data[x].get("is-in-package"):
                        seen.add(x)
                        stack.append(x)
            cp = lambda k: data[k].get("code-path") or ""
            funs = sum(1 for k in seen if cp(k).endswith("/Funs.lean"))
            math = sum(1 for k in seen if "/Math/" in cp(k))
            rows.append((len(seen), funs, math, name, path))
    rows.sort(key=lambda r: (r[0] is None, r[0] or 0, r[3]))
    return rows


def locate(bundle, path, name):
    """(sorry_line, decl_line) of `theorem <short name>` in the bundle file."""
    short = name.rsplit(".", 1)[-1]
    lines = open(os.path.join(REPO, bundle, path)).read().splitlines()
    decl = next((i for i, l in enumerate(lines)
                 if re.match(rf"\s*(?:@\[[^\]]*\]\s*)*theorem\s+{re.escape(short)}\b", l)), None)
    if decl is None:
        sys.exit(f"{path}: theorem {short} not found")
    sorry = next((i for i in range(decl, len(lines))
                  if re.search(r"\bsorry\b", lines[i])), None)
    if sorry is None:
        sys.exit(f"{path}: {short} has no sorry (already proved?)")
    return sorry + 1, decl + 1


# ── workspace ────────────────────────────────────────────────────────────
def make_bundle_slot(run_dir, bundle, skeletons=()):
    """driver.make_slot for the bundle: rsync minus .git and .lake/packages
    (symlinked to the main checkout's), StmtCanon copied in for the G1 gate,
    `git init` + one commit as the sealed baseline. `skeletons`
    [(path, text)]: spec files a --bottom-up plan needs that the bundle
    lacks; written and imported from Curve25519Dalek.lean before sealing,
    so they are baseline, not agent edits."""
    slot = os.path.join(run_dir, "slot0", "work")
    os.makedirs(slot, exist_ok=True)
    cmd = ["rsync", "-a", "--delete"]
    for e in SLOT_EXCLUDES:
        cmd += ["--exclude", "/" + e]
    cmd += [os.path.join(REPO, bundle) + "/", slot + "/"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"slot: rsync failed: {r.stderr[-800:]}")
    pk = os.path.join(slot, ".lake", "packages")
    if not os.path.islink(pk):
        os.makedirs(os.path.dirname(pk), exist_ok=True)
        os.symlink(os.path.join(REPO, ".lake", "packages"), pk)
    dst = os.path.join(slot, STMT_CANON_REL)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(os.path.join(REPO, STMT_CANON_REL), dst)
    # the bundle ships no .gitignore: without this, `git add -A` seals
    # .lake/build and every rebuilt .olean fails the scope gate
    with open(os.path.join(slot, ".gitignore"), "w") as fh:
        fh.write(".lake/\n")
    for path, text in skeletons:
        full = os.path.join(slot, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(text)
        add_root_import(slot, driver.path_to_module(path))
    g = ["git", "-c", "user.name=harness", "-c", "user.email=harness@localhost"]
    for c in (["init", "-q"], ["add", "-A"],
              ["commit", "-q", "--allow-empty", "-m", "sealed baseline"]):
        r = subprocess.run(g + c, cwd=slot, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"slot: git {c[0]} failed: {r.stderr[-800:]}")
    return slot



# ── bottom-up plan ───────────────────────────────────────────────────────
def is_fun(data, k):
    """Funs.lean function (not a trait-impl instance record: those are
    @[reducible] dictionaries of methods, never specified)."""
    n = data.get(k, {})
    return ((n.get("code-path") or "").endswith("/Funs.lean")
            and n.get("kind") in ("def", "definition", "opaque")
            and "rust_trait_impl" not in (n.get("attributes") or []))


def callee_order(data, fn, skip):
    """Internal Funs.lean functions `fn` transitively calls, callees before
    callers (DFS post-order), stopping at functions in `skip` (already
    specified: kept top specs, accepted internal specs). Also returns
    {callee: [direct callers within the plan]} and the skipped callees
    actually reached."""
    order, seen, callers, skipped = [], set(), {}, set()
    def visit(f):
        for x in data[f]["dependencies"]:
            if not is_fun(data, x) or x == f:
                continue
            callers.setdefault(x, []).append(f)
            if x in skip:
                skipped.add(x)
                continue
            if x in seen:
                continue
            seen.add(x)
            visit(x)
            order.append(x)
    visit(fn)
    return order, callers, skipped


def camel(seg):
    if seg.isupper() or (seg.replace("_", "").isupper() and "_" in seg):
        return seg  # ONE, LOW_51_BIT_MASK: constants keep their name
    if re.fullmatch(r"[a-z]\d+", seg):
        return seg.upper()  # u64
    return "".join(w[:1].upper() + w[1:] for w in seg.split("_"))


def spec_path_for(fn, full_probe):
    """Where the human repo keeps the spec of `fn` (the file holding
    `<short>_spec`, else the file with most progress theorems about it);
    fallback: derive Specs/<Camel path>/<CamelShort>.lean from the name."""
    short = fn.rsplit(".", 1)[-1]
    by_path = {}
    for k, n in full_probe.items():
        if (n.get("kind") == "theorem" and "progress" in (n.get("attributes") or [])
                and fn in n.get("type-dependencies", []) and n.get("code-path")):
            by_path.setdefault(n["code-path"], []).append(k.rsplit(".", 1)[-1])
    for path, ths in by_path.items():
        if short + "_spec" in ths:
            return path, "human"
    if by_path:
        return max(by_path, key=lambda p: len(by_path[p])), "human"
    segs = fn.removeprefix("probe:").removeprefix("curve25519_dalek.").split(".")
    keep, i = [], 0
    while i < len(segs) - 1:
        if segs[i] == "Insts":
            i += 2  # Insts.<TraitImplName>
            continue
        keep.append(camel(segs[i]))
        i += 1
    return "Curve25519Dalek/Specs/" + "/".join(keep + [camel(short)]) + ".lean", "derived"


def skeleton(fn):
    ns = fn.removeprefix("probe:").rsplit(".", 1)[0]
    return ("import Curve25519Dalek.Funs\n"
            "import Curve25519Dalek.Math.Basic\n\n"
            "open Aeneas Aeneas.Std Result Aeneas.Std.WP\n"
            "open curve25519_dalek\n\n"
            f"namespace {ns}\n\n"
            f"end {ns}\n")


def add_root_import(root_dir, module):
    """Insert `import <module>` into Curve25519Dalek.lean, keeping the
    sorted import block (lake builds only what the root imports)."""
    p = os.path.join(root_dir, ROOT_MODULE)
    lines = open(p).read().splitlines()
    line = f"import {module}"
    if line in lines:
        return False
    imports = [i for i, l in enumerate(lines) if l.startswith("import ")]
    pos = next((i for i in imports if lines[i] > line), imports[-1] + 1 if imports else 0)
    lines.insert(pos, line)
    open(p, "w").write("\n".join(lines) + "\n")
    return True


def load_internal_specs(bundle):
    p = os.path.join(REPO, bundle, INTERNAL_SPECS)
    return json.load(open(p)) if os.path.isfile(p) else {}


def save_internal_specs(bundle, specs):
    p = os.path.join(REPO, bundle, INTERNAL_SPECS)
    with open(p, "w") as fh:
        json.dump(specs, fh, indent=1, sort_keys=True)
        fh.write("\n")


def build_plan(args, row, data):
    """[(mode, fn, path)]: internal spec steps leaves-first, then the top
    spec ("fill"). `fn` is the probe id of the function (top: of the
    theorem). Skips callees that are kept top specs (their sorried lemma
    is in the bundle) or accepted internal specs (internal_specs.json)."""
    closure, funs, math, name, path = row
    top_fn = next((d for d in data["probe:" + name]["dependencies"] if is_fun(data, d)), None)
    if top_fn is None:
        sys.exit(f"{name}: no Funs.lean function in its statement dependencies")
    manifest = json.load(open(os.path.join(REPO, args.bundle, "bundle_manifest.json")))
    top_funs = {"probe:" + f for v in manifest["kept_spec_files"].values() for f in v}
    done = load_internal_specs(args.bundle)
    skip = top_funs | {"probe:" + f for f in done}
    order, callers, skipped = callee_order(data, top_fn, skip)
    full = json.load(open(os.path.join(REPO, args.probe_full)))["data"]
    steps = []
    for f in order:
        p, how = spec_path_for(f, full)
        steps.append({"mode": "spec", "fn": f, "path": p, "path_source": how,
                      "callers": [short_name(c) for c in callers.get(f, [])]})
    steps.append({"mode": "fill", "fn": "probe:" + name, "path": path, "top_fn": top_fn})
    return steps, done, sorted(skipped & top_funs)


def short_name(k):
    return k.removeprefix("probe:").removeprefix("curve25519_dalek.")


def funs_line(data, fn):
    ct = data.get(fn, {}).get("code-text") or {}
    return ct.get("lines-start")


def statement_text(bundle, path, decl_line, sorry_line):
    lines = open(os.path.join(REPO, bundle, path)).read().splitlines()
    return "\n".join(lines[decl_line - 1:sorry_line]).rstrip()


PROMPT_SPEC = """Write and prove a `@[progress]` specification for `{fn}` in {path}.

`{fn}` is defined in Curve25519Dalek/Funs.lean (near line {funs_line}). This is
step {step} of {steps} of a bottom-up plan whose final goal is the top-level
theorem `{top_decl}` in {top_path}:

```lean
{top_stmt}
```

Direct callers of `{fn}` that later steps must specify: {callers}. Design your
statement so it is strong enough for them and for the final goal (bounds and
the `as_Nat`-style value equations the goal needs).
{available}
Rules — violations are auto-rejected by the harness:
- Edit ONLY {path}. No other file. Adding `import` lines to it is fine.
- The file must end up containing at least one theorem tagged `@[progress]`
  whose statement mentions `{fn}`, fully proved. Helper lemmas in the same
  file are fine. The file's `sorry` warning count must not increase: your new
  declarations must be sorry-free.
- Do NOT change or remove any declaration that already exists in the file;
  pre-existing `sorry`s there are other targets, leave them alone.
- Do NOT add `axiom` declarations or `@[implemented_by]` / `@[extern]` attributes.
- `native_decide` IS allowed.

Verify with `lake build` (module: {module}). Finish when it compiles with no
new sorry warning for {path}, or state clearly that you are stuck and why.

End your final message with exactly one line:
  END_REASON:COMPLETE   — the spec is in place and `lake build` passes
  END_REASON:LIMIT      — you cannot finish this step; say why in one line
"""

AVAILABLE_BLOCK = """
Specifications already available (import their modules and use them):
{items}
"""


def available_block(done, top_funs_in_plan):
    items = [f"- {short_name(fn)}: {d['path']} ({', '.join(t.rsplit('.', 1)[-1] for t in d['theorems'])})"
             for fn, d in sorted(done.items())]
    items += [f"- {short_name(fn)}: kept top spec of the bundle (statement fixed, proof `sorry`)"
              for fn in sorted(top_funs_in_plan)]
    return AVAILABLE_BLOCK.format(items="\n".join(items)) if items else ""


# ── main ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bundle", default=BUNDLE)
    ap.add_argument("--probe", default=PROBE)
    ap.add_argument("--probe-full", default=PROBE_FULL,
                    help="human-repo probe; only used to place internal spec files (--bottom-up)")
    ap.add_argument("--list", action="store_true", help="rank candidates and exit")
    ap.add_argument("--target", default="", help="full theorem name (default: smallest closure)")
    ap.add_argument("--bottom-up", action="store_true",
                    help="first one round per unspecified internal callee (spec + proof, "
                         "its own file), leaves first; then the top spec")
    ap.add_argument("--model", default="")
    ap.add_argument("--max-turns", type=int, default=30)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--build-timeout", type=int, default=driver.BUILD_TIMEOUT)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--max-cost-usd", type=float, default=0.0)
    ap.add_argument("--stall-rounds", type=int, default=2)
    ap.add_argument("--bloat-threshold-tokens", type=int, default=200_000)
    ap.add_argument("--auto-reset", dest="auto_reset", action="store_true", default=True)
    ap.add_argument("--no-auto-reset", dest="auto_reset", action="store_false")
    ap.add_argument("--max-auto-resets", type=int, default=1)
    ap.add_argument("--settings", default=driver.OFFLINE_SETTINGS)
    ap.add_argument("--sandbox", choices=("bwrap", "none"), default="bwrap")
    ap.add_argument("--no-isolation", action="store_true")
    ap.add_argument("--run-dir", default="")
    ap.add_argument("--commit", action="store_true", help="commit each accepted step here")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    args.g2 = False  # driver.gate: no trust-base manifests in a bundle slot

    rows = rank_candidates(args.bundle, args.probe)
    if args.list:
        print(f"{'closure':>7} {'funs':>4} {'math':>4}  theorem  (file)")
        for c, f, m, name, path in rows:
            print(f"{str(c):>7} {str(f):>4} {str(m):>4}  {name}  ({path})")
        return
    if args.target:
        row = next((r for r in rows if r[3] == args.target), None)
        if row is None:
            sys.exit(f"--target {args.target}: not a kept top spec (see --list)")
    else:
        row = rows[0]
    closure, funs, math, name, path = row
    line, decl_line = locate(args.bundle, path, name)
    short = name.rsplit(".", 1)[-1]
    module = driver.path_to_module(path)
    top_prompt = driver.PROMPT.format(decl=short, path=path, line=line, module=module)
    print(f"target: {name}\n  file: {args.bundle}/{path}:{line} (decl line {decl_line})\n"
          f"  closure {closure} in-package decls ({funs} Funs, {math} Math)")

    data = json.load(open(os.path.join(REPO, args.probe)))["data"]
    done, top_in_plan = {}, []
    if args.bottom_up:
        steps, done, top_in_plan = build_plan(args, row, data)
    else:
        steps = [{"mode": "fill", "fn": "probe:" + name, "path": path}]
    skeletons = [(s["path"], skeleton(s["fn"])) for s in steps
                 if s["mode"] == "spec" and not os.path.isfile(os.path.join(REPO, args.bundle, s["path"]))]
    skel_paths = {p for p, _ in skeletons}
    top_stmt = statement_text(args.bundle, path, decl_line, line)
    if args.bottom_up:
        print(f"  plan: {len(steps)} step(s)")
        for i, s in enumerate(steps, 1):
            tag = "" if s["mode"] == "fill" else (
                " [new file]" if s["path"] in skel_paths else " [existing file]")
            print(f"    {i}. {s['mode']:4} {short_name(s['fn'])}  ({s['path']}{tag})")

    def step_prompt(i, s, done_now):
        if s["mode"] == "fill":
            avail = available_block(done_now, top_in_plan) if args.bottom_up else ""
            return top_prompt + (avail and "\n" + avail)
        return PROMPT_SPEC.format(
            fn=short_name(s["fn"]), path=s["path"], funs_line=funs_line(data, s["fn"]),
            step=i, steps=len(steps), top_decl=short, top_path=path, top_stmt=top_stmt,
            callers=", ".join(s["callers"]) or "(none: the top-level function itself)",
            available=available_block(done_now, top_in_plan), module=driver.path_to_module(s["path"]))

    if args.dry_run:
        sim = dict(done)
        for i, s in enumerate(steps, 1):
            print(f"\n──── step {i}/{len(steps)} prompt ────\n" + step_prompt(i, s, sim))
            if s["mode"] == "spec":
                sim[s["fn"].removeprefix("probe:")] = {"path": s["path"], "theorems": ["<accepted in step %d>" % i]}
        return
    if not args.model:
        sys.exit("--model is required (the isolated config dir has no default)")
    if not os.path.isfile(args.settings):
        sys.exit(f"settings file not found: {args.settings}")
    settings_path = os.path.abspath(args.settings)

    run_id = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    run_dir = args.run_dir or os.path.join(REPO, "ledger", "runs",
                                           "topspec_" + run_id.replace(":", ""))
    os.makedirs(run_dir, exist_ok=True)
    agentproc.install_signal_handler()

    work = make_bundle_slot(run_dir, args.bundle, skeletons)
    print(f"slot: {os.path.relpath(work, REPO)}; baseline lake build …", flush=True)
    rc, before_counts, base_s = driver.build_sorry_counts(work, args.build_timeout)
    if rc != 0:
        sys.exit(f"baseline lake build failed ({rc}) in {os.path.relpath(work, REPO)}")
    print(f"baseline: {sum(before_counts.values())} sorry decls in "
          f"{len(before_counts)} files, {base_s}s", flush=True)

    env, prefix, isolation = os.environ.copy(), None, {"isolated": not args.no_isolation}
    if not args.no_isolation:
        cfg, seeded = agentproc.make_config_dir(os.path.join(run_dir, "slot0"))
        if not seeded and not any(k in env for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")):
            sys.exit("no credentials: neither ~/.claude/.credentials.json nor ANTHROPIC_API_KEY")
        env = agentproc.isolated_env(env, cfg)
        isolation["credentials_seeded"] = seeded
        if args.sandbox == "bwrap":
            try:
                prefix = agentproc.bwrap_prefix(work, cfg, extra_ro=[settings_path])
            except RuntimeError as e:
                sys.exit(f"--sandbox bwrap: {e} (use --sandbox none for debug)")
            checks = agentproc.sandbox_selftest(prefix, work, cfg, extra_ro=[settings_path])
            failed = [k for k, ok in checks.items() if not ok]
            if failed:
                sys.exit(f"sandbox self-test FAILED: {failed}")
            isolation["sandbox_selftest"] = checks
            print(f"sandbox ok ({len(checks)} checks)", flush=True)

    log = lambda msg: print(f"[topspec] {msg}", flush=True)
    limits = {k: getattr(args, k) for k in (
        "model", "rounds", "max_turns", "timeout", "build_timeout",
        "max_cost_usd", "stall_rounds", "bloat_threshold_tokens",
        "auto_reset", "max_auto_resets")}
    plan_id = run_id
    final = None
    for i, s in enumerate(steps, 1):
        spath, smod = s["path"], driver.path_to_module(s["path"])
        prompt = step_prompt(i, s, done)
        try:
            g1_base, g1_s = driver.stmt_fingerprints([smod], work)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            sys.exit(f"G1 baseline failed for {smod}: {str(e)[-2000:]}")
        log(f"step {i}/{len(steps)} {s['mode']} {short_name(s['fn'])} — {spath}; "
            f"G1 baseline {len(g1_base.get(smod, {}))} declarations, {g1_s}s")
        args.gate_mode = s["mode"]
        args.gate_callee = s["fn"].removeprefix("probe:") if s["mode"] == "spec" else None
        tid = "topspec_" + re.sub(r"[^A-Za-z0-9_.]+", "_", name) + (
            f".s{i}_" + re.sub(r"[^A-Za-z0-9_.]+", "_", short_name(s["fn"])) if len(steps) > 1 else "")
        outcome, detail, rounds, session_ids = driver.run_rounds(
            prompt, tid, spath, before_counts, args, env, settings_path,
            g1_base, work, prefix, log)
        detail.pop("g1_after", None)  # fingerprints incl. used constants: too big for the ledger
        for r in rounds:
            (r.get("detail") or {}).pop("g1_after", None)

        if outcome == "accepted":
            before_counts = detail.get("counts_after", before_counts)
            driver.slot_commit(work, spath, f"step {i}: {s['mode']} {short_name(s['fn'])}")
            dst = os.path.join(REPO, args.bundle, spath)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(work, spath), dst)
            to_add = [os.path.join(args.bundle, spath)]
            if spath in skel_paths and add_root_import(os.path.join(REPO, args.bundle), smod):
                to_add.append(os.path.join(args.bundle, ROOT_MODULE))
            if s["mode"] == "spec":
                done[s["fn"].removeprefix("probe:")] = {
                    "path": spath, "theorems": detail.get("specs", []), "run_id": run_id}
                save_internal_specs(args.bundle, done)
                to_add.append(os.path.join(args.bundle, INTERNAL_SPECS))
            print(driver.sh(["git", "diff", "--", *to_add]).stdout)
            if args.commit:
                what = f"prove {name}" if s["mode"] == "fill" else \
                    f"internal spec {short_name(s['fn'])} (for {name})"
                msg = (f"{args.bundle}: {what}\n\n"
                       f"Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>")
                driver.sh(["git", "add", *to_add])
                driver.sh(["git", "commit", "-q", "-m", msg])
        else:
            mod, new = driver.changed_files(work)
            driver.rollback(mod, new, work)

        record = {
            "run_id": run_id, "bundle": args.bundle, "target": name, "path": path,
            "line": line, "closure": {"total": closure, "funs": funs, "math": math},
            "plan": {"id": plan_id, "step": i, "of": len(steps), "mode": s["mode"],
                     "fn": short_name(s["fn"]), "step_path": spath,
                     "new_file": spath in skel_paths} if args.bottom_up else None,
            "outcome": outcome, "detail": detail, "rounds": rounds,
            "session_ids": session_ids, "g2": "skipped", "limits": limits,
            "isolation": isolation, "slot": os.path.relpath(work, REPO),
            "baseline_build_seconds": base_s,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        }
        with open(LEDGER, "a") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"\nstep {i}/{len(steps)} {outcome}: {short_name(s['fn'])}  ({len(rounds)} round(s)); "
              f"ledger {os.path.relpath(LEDGER, REPO)}")
        final = outcome
        if outcome != "accepted" or agentproc.RECEIVED_SIGNAL is not None:
            if i < len(steps):
                print(f"plan stopped at step {i}; {i - 1} accepted step(s) kept in the bundle")
            break
    if agentproc.RECEIVED_SIGNAL is not None:
        sys.exit(128 + agentproc.RECEIVED_SIGNAL)
    if final != "accepted":
        sys.exit(1)


if __name__ == "__main__":
    main()
