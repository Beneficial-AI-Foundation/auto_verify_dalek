#!/usr/bin/env python3
"""Fresh replay (DEC-10): re-verify a tree in a clean checkout.

The driver's per-attempt gate runs `lake build` in the working tree the agent
just edited, so it inherits that tree's `.lake/build` cache. A replay rebuilds
the project's own modules from nothing in a fresh `git worktree`, then re-runs
every closure check, so the final claim rests on a build no agent process ever
touched:

  1. `git worktree add --detach <dir> <ref>`; optionally apply the current
     working tree's tracked diff (`--include-worktree-diff`, for runs made
     without `--commit`). Untracked files are never carried over.
  2. dependency packages (`.lake/packages`, ~8 GB of Mathlib/Aeneas .olean)
     are shared by symlink rather than rebuilt; their content digest is
     computed and compared with harness/frozen/packages.sha256 so a tampered
     dependency olean cannot pass unnoticed (`--freeze-packages` records the
     digest from a trusted state; `--skip-packages-check` for quick local use)
  3. `lake build` from an empty `.lake/build`, with a wall-clock bound;
     sorry warnings collected per file and per inventory zone
  4. G2 trust-base gate (harness/gates/g2_trust_base.py, in the worktree)
  5. G1 statement identity of every module listed in
     harness/frozen/statements.json against that frozen baseline
     (`--freeze-statements` records the baseline from a trusted state)

Verdict PASS = build ok ∧ packages digest matches (or skipped) ∧ G2 pass ∧
G1 no missing/changed statement. Zero sorry in a zone is reported, not
required — report.py combines it with the ledger for the whole-T verdict.

Usage:
  python3 harness/replay.py                              # HEAD
  python3 harness/replay.py --include-worktree-diff      # HEAD + uncommitted fills
  python3 harness/replay.py --ref <sha> --out ledger/replay/x.json
  python3 harness/replay.py --freeze-statements --freeze-packages   # once, trusted tree
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FROZEN = os.path.join(REPO, "harness", "frozen")
FROZEN_STMTS = os.path.join(FROZEN, "statements.json")
FROZEN_PKGS = os.path.join(FROZEN, "packages.sha256")
INVENTORY = os.path.join(REPO, ".verilib", "sorry_inventory.json")
STMT_CANON = os.path.join("harness", "gates", "StmtCanon.lean")
SPEC_ZONES = ("specs", "aux")  # modules whose statements are frozen


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def sh(cmd, cwd, timeout=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)


def path_to_module(path):
    return path.removesuffix(".lean").replace("/", ".")


# ── packages digest ──────────────────────────────────────────────────────
def packages_digest(pkg_dir):
    """Aggregate sha256 over (relpath, content) of every regular file under
    .lake/packages, sorted; returns (digest, file_count, seconds)."""
    t0 = time.time()
    h = hashlib.sha256()
    n = 0
    for root, dirs, files in os.walk(pkg_dir):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(root, f)
            if os.path.islink(p):
                continue
            rel = os.path.relpath(p, pkg_dir)
            h.update(rel.encode() + b"\0")
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            h.update(b"\0")
            n += 1
    return h.hexdigest(), n, round(time.time() - t0, 1)


# ── sorry accounting ─────────────────────────────────────────────────────
def sorry_counts(build_stdout):
    counts = {}
    for ln in build_stdout.splitlines():
        if "declaration uses" in ln and "sorry" in ln:
            loc = ln.split(" declaration")[0].removeprefix("warning: ").lstrip("./")
            counts[loc.split(":")[0]] = counts.get(loc.split(":")[0], 0) + 1
    return counts


def zone_of(path, inv):
    for z, locs in inv["locations"].items():
        if any(l.split(":")[0] == path for l in locs):
            return z
    return "outside_inventory"


# ── G1 over frozen statements ───────────────────────────────────────────
def stmt_fingerprints(cwd, modules, timeout=1800):
    p = sh(["nice", "-n", "19", "lake", "env", "lean", "--run", STMT_CANON,
            "--module", ",".join(modules)], cwd, timeout)
    if p.returncode != 0:
        raise RuntimeError((p.stdout + p.stderr)[-2000:])
    fps = {m: {} for m in modules}
    for ln in p.stdout.splitlines():
        if ln.startswith("{"):
            r = json.loads(ln)
            if "error" in r or not r.get("found"):
                raise RuntimeError(f"StmtCanon: {r}")
            fps.setdefault(r["module"], {})[r["name"]] = {
                "kind": r["kind"], "pp": r["pp"],
                # sha, not the canon dump: the frozen file stays small
                "canon_sha256": hashlib.sha256(r["canon"].encode()).hexdigest()}
    return fps


def stmt_diff(base, after):
    missing = sorted(n for n in base if n not in after)
    changed = {n: {"before": base[n]["pp"], "after": after[n]["pp"]}
               for n in base if n in after
               and (base[n]["kind"], base[n]["canon_sha256"])
               != (after[n]["kind"], after[n]["canon_sha256"])}
    return missing, changed


def spec_modules(inv):
    paths = {l.split(":")[0] for z in SPEC_ZONES for l in inv["locations"][z]}
    # every Specs module, not only the ones with a sorry at inventory time
    for root, _, files in os.walk(os.path.join(REPO, "Curve25519Dalek", "Specs")):
        for f in files:
            if f.endswith(".lean"):
                paths.add(os.path.relpath(os.path.join(root, f), REPO))
    return sorted(path_to_module(p) for p in paths)


# ── main ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--include-worktree-diff", action="store_true",
                    help="apply `git diff HEAD` (tracked files) on top of --ref")
    ap.add_argument("--worktree-dir", default="",
                    help="default .tmp/replay/<ts> (gitignored)")
    ap.add_argument("--keep", action="store_true", help="do not remove the worktree")
    ap.add_argument("--out", default="", help="default ledger/replay/<ts>.json")
    ap.add_argument("--build-timeout", type=int, default=3600)
    ap.add_argument("--skip-packages-check", action="store_true")
    ap.add_argument("--freeze-packages", action="store_true",
                    help="write harness/frozen/packages.sha256 from this tree")
    ap.add_argument("--freeze-statements", action="store_true",
                    help="write harness/frozen/statements.json from this replay")
    args = ap.parse_args()

    ts = now_iso()
    wt = os.path.abspath(args.worktree_dir or os.path.join(REPO, ".tmp", "replay", ts))
    out = os.path.abspath(args.out or os.path.join(REPO, "ledger", "replay", f"{ts}.json"))
    inv = json.load(open(INVENTORY))
    rep = {"ts": ts, "ref": args.ref,
           "ref_sha": sh(["git", "rev-parse", args.ref], REPO).stdout.strip(),
           "worktree": os.path.relpath(wt, REPO),
           "include_worktree_diff": args.include_worktree_diff,
           "checks": {}, "verdict": None}
    failures = []

    # 1. worktree
    os.makedirs(os.path.dirname(wt), exist_ok=True)
    r = sh(["git", "worktree", "add", "--detach", wt, args.ref], REPO)
    if r.returncode != 0:
        sys.exit(f"git worktree add failed: {r.stderr}")
    try:
        if args.include_worktree_diff:
            diff = sh(["git", "diff", "HEAD"], REPO).stdout
            rep["worktree_diff_sha256"] = hashlib.sha256(diff.encode()).hexdigest()
            rep["worktree_diff_files"] = sh(["git", "diff", "--name-only", "HEAD"],
                                            REPO).stdout.split()
            if diff:
                a = subprocess.run(["git", "apply", "--index"], cwd=wt, input=diff,
                                   capture_output=True, text=True)
                if a.returncode != 0:
                    sys.exit(f"git apply failed: {a.stderr}")
        rep["tree_sha"] = sh(["git", "write-tree"], wt).stdout.strip()
        untracked = sh(["git", "ls-files", "--others", "--exclude-standard"],
                       REPO).stdout.split()
        rep["untracked_not_carried"] = untracked

        # 2. packages
        src_pkgs = os.path.join(REPO, ".lake", "packages")
        os.makedirs(os.path.join(wt, ".lake"), exist_ok=True)
        os.symlink(src_pkgs, os.path.join(wt, ".lake", "packages"))
        if args.skip_packages_check and not args.freeze_packages:
            rep["checks"]["packages"] = {"skipped": True}
        else:
            print("hashing .lake/packages …", flush=True)
            digest, n, secs = packages_digest(src_pkgs)
            chk = {"digest": digest, "files": n, "seconds": secs}
            if args.freeze_packages:
                with open(FROZEN_PKGS, "w") as fh:
                    fh.write(f"{digest}  .lake/packages ({n} files)\n")
                chk["frozen_written"] = True
            elif os.path.exists(FROZEN_PKGS):
                want = open(FROZEN_PKGS).read().split()[0]
                chk["match"] = want == digest
                if not chk["match"]:
                    failures.append("packages digest differs from frozen")
            else:
                chk["match"] = None
                failures.append("no harness/frozen/packages.sha256 (run --freeze-packages)")
            rep["checks"]["packages"] = chk
            print(f"  {n} files, {secs}s, match={chk.get('match')}", flush=True)

        # 3. build
        print("lake build (fresh .lake/build) …", flush=True)
        t0 = time.time()
        try:
            b = sh(["nice", "-n", "19", "lake", "build"], wt,
                   args.build_timeout)
            build = {"rc": b.returncode, "seconds": round(time.time() - t0, 1)}
            if b.returncode != 0:
                build["tail"] = (b.stdout + b.stderr)[-3000:]
                failures.append("lake build failed")
            counts = sorry_counts(b.stdout)
        except subprocess.TimeoutExpired:
            build = {"rc": "timeout", "seconds": args.build_timeout}
            failures.append("lake build timeout")
            counts = {}
        rep["checks"]["build"] = build
        by_zone = {}
        for f, c in counts.items():
            by_zone[zone_of(f, inv)] = by_zone.get(zone_of(f, inv), 0) + c
        rep["sorry"] = {"total": sum(counts.values()), "by_zone": by_zone,
                        "by_file": counts}
        print(f"  rc={build['rc']} {build['seconds']}s, sorry={rep['sorry']['total']} "
              f"{by_zone}", flush=True)

        if build["rc"] == 0:
            # 4. G2
            g2 = sh(["python3", "harness/gates/g2_trust_base.py", "--skip-build"], wt)
            rep["checks"]["g2"] = {"pass": g2.returncode == 0,
                                   "tail": g2.stdout[-2000:]}
            if g2.returncode != 0:
                failures.append("G2 failed")
            print(f"  G2 {'PASS' if g2.returncode == 0 else 'FAIL'}", flush=True)

            # 5. G1 vs frozen statements
            mods = spec_modules(inv)
            print(f"G1: fingerprinting {len(mods)} modules …", flush=True)
            try:
                fps = stmt_fingerprints(wt, mods)
                if args.freeze_statements:
                    json.dump({"generated": ts, "ref_sha": rep["ref_sha"],
                               "tree_sha": rep["tree_sha"], "modules": fps},
                              open(FROZEN_STMTS, "w"), indent=0, sort_keys=True)
                    rep["checks"]["g1"] = {"frozen_written": True,
                                           "declarations": sum(len(v) for v in fps.values())}
                elif os.path.exists(FROZEN_STMTS):
                    frozen = json.load(open(FROZEN_STMTS))["modules"]
                    missing, changed = {}, {}
                    for m, base in frozen.items():
                        mi, ch = stmt_diff(base, fps.get(m, {}))
                        if mi:
                            missing[m] = mi
                        if ch:
                            changed[m] = ch
                    rep["checks"]["g1"] = {
                        "pass": not missing and not changed,
                        "frozen_declarations": sum(len(v) for v in frozen.values()),
                        "missing": missing, "changed": changed}
                    if missing or changed:
                        failures.append("G1: supplied statements changed")
                    print(f"  G1 {'PASS' if rep['checks']['g1']['pass'] else 'FAIL'}",
                          flush=True)
                else:
                    rep["checks"]["g1"] = {"pass": None}
                    failures.append("no harness/frozen/statements.json (run --freeze-statements)")
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                rep["checks"]["g1"] = {"pass": False, "error": str(e)[-2000:]}
                failures.append("G1 tool error")
    finally:
        if args.keep:
            print(f"worktree kept at {wt}")
        else:
            sh(["git", "worktree", "remove", "--force", wt], REPO)

    rep["failures"] = failures
    rep["verdict"] = "PASS" if not failures else "FAIL"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(rep, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"\nreplay {rep['verdict']}: {failures or 'all checks passed'}")
    print(f"report: {os.path.relpath(out, REPO)}")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
