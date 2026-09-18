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
    this checkout.

Ledger: ledger/top_spec_rounds.jsonl (one record per attempt; transcripts
in ledger/transcripts/topspec_*.jsonl like the driver's).

Usage:
  python3 harness/prove_top_spec.py --list
  python3 harness/prove_top_spec.py --dry-run                     # show pick + prompt
  python3 harness/prove_top_spec.py --model claude-sonnet-5       # smallest closure
  python3 harness/prove_top_spec.py --model <id> --target curve25519_dalek.scalar.Scalar.to_bytes_spec
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
def make_bundle_slot(run_dir, bundle):
    """driver.make_slot for the bundle: rsync minus .git and .lake/packages
    (symlinked to the main checkout's), StmtCanon copied in for the G1 gate,
    `git init` + one commit as the sealed baseline."""
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
    g = ["git", "-c", "user.name=harness", "-c", "user.email=harness@localhost"]
    for c in (["init", "-q"], ["add", "-A"],
              ["commit", "-q", "--allow-empty", "-m", "sealed baseline"]):
        r = subprocess.run(g + c, cwd=slot, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"slot: git {c[0]} failed: {r.stderr[-800:]}")
    return slot


# ── main ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bundle", default=BUNDLE)
    ap.add_argument("--probe", default=PROBE)
    ap.add_argument("--list", action="store_true", help="rank candidates and exit")
    ap.add_argument("--target", default="", help="full theorem name (default: smallest closure)")
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
    ap.add_argument("--commit", action="store_true", help="commit an accepted proof here")
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
    prompt = driver.PROMPT.format(decl=short, path=path, line=line, module=module)
    print(f"target: {name}\n  file: {args.bundle}/{path}:{line} (decl line {decl_line})\n"
          f"  closure {closure} in-package decls ({funs} Funs, {math} Math)")
    if args.dry_run:
        print("\n" + prompt)
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

    work = make_bundle_slot(run_dir, args.bundle)
    print(f"slot: {os.path.relpath(work, REPO)}; baseline lake build …", flush=True)
    rc, before_counts, base_s = driver.build_sorry_counts(work, args.build_timeout)
    if rc != 0:
        sys.exit(f"baseline lake build failed ({rc}) in {os.path.relpath(work, REPO)}")
    print(f"baseline: {sum(before_counts.values())} sorry decls in "
          f"{len(before_counts)} files, {base_s}s", flush=True)
    try:
        g1_base, g1_s = driver.stmt_fingerprints([module], work)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        sys.exit(f"G1 baseline failed: {str(e)[-2000:]}")
    print(f"G1 baseline: {len(g1_base.get(module, {}))} declarations, {g1_s}s", flush=True)

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

    tid = "topspec_" + re.sub(r"[^A-Za-z0-9_.]+", "_", name)
    log = lambda msg: print(f"[topspec] {msg}", flush=True)
    outcome, detail, rounds, session_ids = driver.run_rounds(
        prompt, tid, path, before_counts, args, env, settings_path,
        g1_base, work, prefix, log)

    if outcome == "accepted":
        dst = os.path.join(REPO, args.bundle, path)
        shutil.copyfile(os.path.join(work, path), dst)
        print(driver.sh(["git", "diff", "--", os.path.join(args.bundle, path)]).stdout)
        if args.commit:
            msg = (f"{args.bundle}: prove {name}\n\n"
                   f"Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>")
            driver.sh(["git", "add", os.path.join(args.bundle, path)])
            driver.sh(["git", "commit", "-q", "-m", msg])
    else:
        mod, new = driver.changed_files(work)
        driver.rollback(mod, new, work)

    record = {
        "run_id": run_id, "bundle": args.bundle, "target": name, "path": path,
        "line": line, "closure": {"total": closure, "funs": funs, "math": math},
        "outcome": outcome, "detail": detail, "rounds": rounds,
        "session_ids": session_ids, "g2": "skipped",
        "limits": {k: getattr(args, k) for k in (
            "model", "rounds", "max_turns", "timeout", "build_timeout",
            "max_cost_usd", "stall_rounds", "bloat_threshold_tokens",
            "auto_reset", "max_auto_resets")},
        "isolation": isolation, "slot": os.path.relpath(work, REPO),
        "baseline_build_seconds": base_s,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
    }
    with open(LEDGER, "a") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n{outcome}: {name}  ({len(rounds)} round(s)); "
          f"ledger {os.path.relpath(LEDGER, REPO)}")
    if agentproc.RECEIVED_SIGNAL is not None:
        sys.exit(128 + agentproc.RECEIVED_SIGNAL)


if __name__ == "__main__":
    main()
