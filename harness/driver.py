#!/usr/bin/env python3
"""Phase-1 driver loop (plan.md 附:优先级 1).

Per target:  pick sorry → resolve declaration in the CURRENT file → run Claude
Code headless (stream-json transcript saved) → gate → accept/rollback → ledger.

Gate stack per attempt (all must pass to accept):
  a. scope: `git status --porcelain` shows changes ONLY in the target file
  b. no new `axiom`, `@[implemented_by]`, `@[extern]` in the changed file
     (the native_decide hijack path — plan.md §4 policy)
  c. `lake build` exits 0
  d. sorry accounting vs pre-attempt snapshot: target file's sorry-warning
     count strictly decreases; every other file's count unchanged
  e. G2 trust-base gate (harness/gates/g2_trust_base.py --skip-build;
     check 5 is subsumed by d, which is stricter — per-file, both directions)

Rollback never uses destructive git verbs: modified tracked files are
restored via `git show HEAD:<f> > <f>`; new untracked files are removed.

Ledger:  ledger/rounds.jsonl        one record per attempt (see RECORD below)
         ledger/transcripts/*.jsonl raw stream-json, never discarded —
                                    bucket rules can be re-run post-hoc

Usage examples:
  python3 harness/driver.py --zones specs --limit 10 --dry-run
  python3 harness/driver.py --zones specs --limit 10 --commit
  python3 harness/driver.py --match AffineNielsPoint --max-turns 40
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buckets import classify, load_events  # noqa: E402

LEDGER_DIR = os.path.join(REPO, "ledger")
TRANSCRIPTS = os.path.join(LEDGER_DIR, "transcripts")
INVENTORY = os.path.join(REPO, ".verilib", "sorry_inventory.json")

DECL_RE = re.compile(
    r"\s*(?:@\[[^\]]*\]\s*)*(?:private\s+|protected\s+|noncomputable\s+|partial\s+)*"
    r"(theorem|lemma|def|instance|abbrev|example)\s+([^\s:({\[⦃]+)?")
FORBIDDEN_RE = re.compile(r"@\[\s*(implemented_by|extern)\b|^\s*axiom\s", re.M)

PROMPT = """Fill the `sorry` in declaration `{decl}` in {path} (currently near line {line}).

Rules — violations are auto-rejected by the harness:
- Edit ONLY {path}. No other file.
- Do NOT change the statement of `{decl}` or any other declaration; replace only its `sorry` with a proof.
- Do NOT add `axiom` declarations or `@[implemented_by]` / `@[extern]` attributes.
- `native_decide` IS allowed.
- Other `sorry`s in the file are other targets; leave them alone.

Verify with `lake build` (module: {module}). Finish when it compiles with one
fewer sorry warning for {path}, or state clearly that you are stuck and why.
"""


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, **kw)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ── sorry accounting ─────────────────────────────────────────────────────
def build_sorry_counts():
    """lake build → (exit_code, {file: sorry_warning_count})."""
    p = sh(["lake", "build"])
    counts = {}
    for ln in (p.stdout + p.stderr).splitlines():
        if "declaration uses `sorry`" in ln or "declaration uses 'sorry'" in ln:
            loc = ln.split(" declaration")[0]
            loc = loc.removeprefix("warning: ").lstrip("./")
            f = loc.split(":")[0]
            counts[f] = counts.get(f, 0) + 1
    return p.returncode, counts


# ── target resolution (robust to line drift from earlier accepts) ───────
def resolve_target(loc):
    """inventory 'path:line:col' → (path, decl_name, current_line) or None if filled."""
    path, line = loc.split(":")[0], int(loc.split(":")[1])
    full = os.path.join(REPO, path)
    lines = open(full).read().splitlines()
    sorry_lines = [i + 1 for i, l in enumerate(lines)
                   if re.search(r"\bsorry\b", l) and not l.lstrip().startswith("--")]
    if not sorry_lines:
        return None
    cur = min(sorry_lines, key=lambda x: abs(x - line))
    for i in range(cur - 1, -1, -1):
        m = DECL_RE.match(lines[i])
        if m and m.group(2):
            return path, m.group(2), cur
    return path, f"<decl@{path}:{cur}>", cur


def path_to_module(path):
    return path.removesuffix(".lean").replace("/", ".")


# ── rollback without destructive git verbs ──────────────────────────────
# Untracked files present when the driver starts (e.g. harness scripts not yet
# committed) are NOT the agent's doing: snapshot them once and gate/rollback
# only on the increment. Without this, every attempt is scope-rejected and —
# worse — rollback() would delete the pre-existing files.
BASELINE_UNTRACKED = set()


def snapshot_untracked():
    global BASELINE_UNTRACKED
    _, new = changed_files()
    BASELINE_UNTRACKED = set(new)


def changed_files():
    out = sh(["git", "status", "--porcelain"]).stdout
    mod, new = [], []
    for ln in out.splitlines():
        st, f = ln[:2], ln[3:].strip().strip('"')
        if f.startswith((".verilib/", "ledger/")):
            continue
        if "?" in st:
            if f not in BASELINE_UNTRACKED:
                new.append(f)
        else:
            mod.append(f)
    return mod, new


def rollback(mod, new):
    for f in mod:
        blob = sh(["git", "show", f"HEAD:{f}"])
        if blob.returncode == 0:
            open(os.path.join(REPO, f), "w").write(blob.stdout)
    for f in new:  # only agent-created files (baseline untracked excluded)
        p = os.path.join(REPO, f)
        if os.path.isfile(p):
            os.remove(p)
        elif os.path.isdir(p):  # porcelain lists a fully-untracked dir as `dir/`
            shutil.rmtree(p)


# ── agent invocation ─────────────────────────────────────────────────────
def run_agent(prompt, transcript_path, args):
    cmd = ["claude", "-p", prompt,
           "--output-format", "stream-json", "--verbose",
           "--max-turns", str(args.max_turns),
           "--allowedTools",
           "Read,Grep,Glob,Edit,Write,Bash(lake build*),Bash(lake env*),Bash(grep*)"]
    if args.model:
        cmd += ["--model", args.model]
    t0 = time.time()
    with open(transcript_path, "w") as fh:
        p = subprocess.run(cmd, cwd=REPO, stdout=fh, stderr=subprocess.PIPE,
                           text=True, timeout=args.timeout)
    return p.returncode, time.time() - t0, p.stderr[-2000:]


# ── gates ────────────────────────────────────────────────────────────────
def gate(target_path, before_counts):
    mod, new = changed_files()
    if new or set(mod) - {target_path}:
        return "rejected_scope", {"modified": mod, "new": new}
    if mod:  # target actually touched — scan forbidden constructs
        diff = sh(["git", "diff", "--unified=0", "--", target_path]).stdout
        added = "\n".join(l[1:] for l in diff.splitlines()
                          if l.startswith("+") and not l.startswith("+++"))
        if FORBIDDEN_RE.search(added):
            return "rejected_forbidden_attr", {}
    rc, after = build_sorry_counts()
    if rc != 0:
        return "rejected_build", {}
    if after.get(target_path, 0) >= before_counts.get(target_path, 0):
        return "rejected_sorry_remains", {"before": before_counts.get(target_path, 0),
                                          "after": after.get(target_path, 0)}
    others_before = {f: c for f, c in before_counts.items() if f != target_path}
    others_after = {f: c for f, c in after.items() if f != target_path}
    if others_before != others_after:
        return "rejected_sorry_migration", {
            "delta": {f: (others_before.get(f, 0), others_after.get(f, 0))
                      for f in set(others_before) ^ set(others_after)
                      | {f for f in others_before if others_before.get(f) != others_after.get(f)}}}
    g2 = sh(["python3", "harness/gates/g2_trust_base.py", "--skip-build"])
    if g2.returncode != 0:
        return "rejected_g2", {"g2_tail": g2.stdout[-1500:]}
    return "accepted", {"counts_after": after}


# ── main loop ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zones", default="specs,aux")
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--match", default="", help="substring filter on location")
    ap.add_argument("--model", default="")
    ap.add_argument("--max-turns", type=int, default=30)
    ap.add_argument("--timeout", type=int, default=1800, help="seconds per attempt")
    ap.add_argument("--commit", action="store_true",
                    help="git commit each accepted fill")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve targets + print prompts, no agent, no build")
    args = ap.parse_args()

    os.makedirs(TRANSCRIPTS, exist_ok=True)
    inv = json.load(open(INVENTORY))
    targets = [loc for z in args.zones.split(",")
               for loc in inv["locations"][z.strip()]]
    if args.match:
        targets = [t for t in targets if args.match in t]
    if args.limit:
        targets = targets[:args.limit]
    print(f"{len(targets)} target(s), zones={args.zones}")

    before_counts = {}
    if not args.dry_run:
        mod, _ = changed_files()
        if mod:
            sys.exit(f"working tree not clean (tracked changes: {mod}); "
                     f"commit or restore first")
        snapshot_untracked()  # pre-existing untracked files are not the agent's
        print("baseline build …", flush=True)
        rc, before_counts = build_sorry_counts()
        if rc != 0:
            sys.exit("baseline lake build failed — fix before running driver")
        print(f"baseline: {sum(before_counts.values())} sorry decls "
              f"in {len(before_counts)} files")

    accepted = 0
    for i, loc in enumerate(targets):
        res = resolve_target(loc)
        if res is None:
            print(f"[{i+1}/{len(targets)}] {loc}: no sorry left, skip")
            continue
        path, decl, line = res
        prompt = PROMPT.format(decl=decl, path=path, line=line,
                               module=path_to_module(path))
        print(f"[{i+1}/{len(targets)}] {loc} → `{decl}` (line {line})")
        if args.dry_run:
            continue

        tid = re.sub(r"[^A-Za-z0-9_.]+", "_", loc)
        tpath = os.path.join(TRANSCRIPTS, f"{tid}.jsonl")
        try:
            rc, wall, err_tail = run_agent(prompt, tpath, args)
            agent_error = None if rc == 0 else f"exit {rc}: {err_tail}"
        except subprocess.TimeoutExpired:
            agent_error, wall = "timeout", args.timeout

        if agent_error:
            outcome, detail = "agent_error", {"error": agent_error}
            mod, new = changed_files()
            rollback(mod, new)
        else:
            outcome, detail = gate(path, before_counts)
            if outcome == "accepted":
                before_counts = detail.pop("counts_after")
                accepted += 1
                if args.commit:
                    sh(["git", "add", path])
                    sh(["git", "commit", "-m",
                        f"phase1: fill {decl} ({loc})\n\n"
                        f"Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"])
            else:
                mod, new = changed_files()
                rollback(mod, new)

        try:
            events = load_events(tpath)
            analysis = classify(events, rejected=(outcome != "accepted"))
        except Exception as e:
            analysis = {"error": f"transcript parse failed: {e}"}

        record = {
            "ts": now_iso(), "target": loc, "decl": decl, "path": path,
            "outcome": outcome, "detail": detail,
            "wall_seconds": round(wall, 1),
            "model": args.model or "default", "max_turns": args.max_turns,
            "transcript": os.path.relpath(tpath, REPO),
            **({"buckets": analysis.get("buckets"),
                "usage_totals": analysis.get("usage_totals"),
                "assistant_turns": analysis.get("assistant_turns"),
                "result": analysis.get("result")}
               if "error" not in analysis else {"analysis_error": analysis["error"]}),
        }
        with open(os.path.join(LEDGER_DIR, "rounds.jsonl"), "a") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        usage = record.get("usage_totals") or {}
        print(f"    {outcome}"
              + (f" | out={usage.get('output_tokens')}"
                 f" turns={record.get('assistant_turns')}" if usage else ""))

    if not args.dry_run:
        print(f"\ndone: {accepted}/{len(targets)} accepted; "
              f"ledger at ledger/rounds.jsonl")


if __name__ == "__main__":
    main()
