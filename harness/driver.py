#!/usr/bin/env python3
"""Phase-1 driver loop (plan.md 附:优先级 1).

Per target:  pick sorry → resolve declaration in the CURRENT file → run Claude
Code headless (stream-json transcript saved) → gate → accept/rollback → ledger.

Agent invocation lives in harness/agentproc.py (session UUID + --resume rounds,
process-group kill, wall-clock deadline, signal handling, optional wire
proxy — ported from CryptoProver run.py). Multi-round policy here:
  * round 1 starts a fresh session pinned to an explicit UUID; rounds 2..N
    `--resume` it with the gate verdict as feedback, so the agent keeps its
    exploration context (failed tactics, half-built lemmas).
  * only "not done yet" rejections continue (rejected_build,
    rejected_sorry_remains). Policy violations (scope / forbidden attr /
    sorry migration / g2) abort the target immediately: they require a
    rollback, and resuming after a rollback would desync the agent's view
    of the tree.
  * rollback still happens exactly once, after the final round's verdict.

Gate stack per attempt (all must pass to accept):
  a. scope: `git status --porcelain` shows changes ONLY in the target file
  b. no new `axiom`, `@[implemented_by]`, `@[extern]` in the changed file
     (the native_decide hijack path — plan.md §4 policy)
  c. `lake build` exits 0 within --build-timeout (default 1200s; a
     timeout is rejected_kernel_budget — N3 minimal, plan.md §6)
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
import signal
import subprocess
import sys
import time


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buckets import classify, load_events  # noqa: E402
import agentproc  # noqa: E402  (harness/agentproc.py — subprocess layer)

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
BUILD_TIMEOUT = 1200  # seconds; fixed so runs on different machines are comparable


def build_sorry_counts(timeout=BUILD_TIMEOUT):
    """lake build → (exit_code | "timeout", {file: sorry_warning_count}, wall_s).

    N3 minimal version (plan.md §6): a `decide`-style kernel blow-up passes
    elaboration but can run for hours; Lean's maxHeartbeats does not bound
    the kernel, so only a wall clock does. lake is spawned in its own
    process group and the whole group is SIGKILLed on timeout — plain
    `subprocess.run(timeout=)` would kill `lake` and orphan the `lean`
    workers, which keep burning cores.
    """
    t0 = time.time()
    proc = subprocess.Popen(["lake", "build"], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        return "timeout", {}, round(time.time() - t0, 1)
    counts = {}
    for ln in out.splitlines():
        if "declaration uses `sorry`" in ln or "declaration uses 'sorry'" in ln:
            loc = ln.split(" declaration")[0]
            loc = loc.removeprefix("warning: ").lstrip("./")
            f = loc.split(":")[0]
            counts[f] = counts.get(f, 0) + 1
    return rc, counts, round(time.time() - t0, 1)


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


# ── agent invocation (multi-round; subprocess mechanics in agentproc.py) ─────
# No `lake env`: the offline settings deny it (it can run arbitrary binaries
# under the toolchain env), and the agent only needs `lake build`.
ALLOWED_TOOLS = ("Read,Grep,Glob,Edit,Write,"
                 "Bash(lake build*),Bash(grep*)")
OFFLINE_SETTINGS = os.path.join(REPO, ".claude", "settings-offline.json")

# Gate rejections that mean "not done yet" — the same session is resumed
# with this feedback. Everything else is a policy violation: abort.
FEEDBACK = {
    "rejected_build": (
        "The harness gate rejected this round: `lake build` fails after "
        "your edit. Fix the build; the target file must compile. "
        "All original rules still apply."),
    "rejected_sorry_remains": (
        "The harness gate rejected this round: the target file's `sorry` "
        "warning count did not decrease — the target is still unproven. "
        "Keep working on the same declaration. All original rules still "
        "apply."),
}


def run_rounds(prompt, tid, path, before_counts, args, env, settings_path):
    """Round 1 fresh session, rounds 2..N --resume with gate feedback.

    Returns (outcome, detail, rounds, session_id). No rollback here: the
    caller rolls back once, on any non-accepted final outcome. Each round's
    transcript is ledger/transcripts/{tid}.r{n}.jsonl.
    """
    session_id = agentproc.new_session_id()
    rounds = []
    outcome, detail = "agent_error", {"error": "no rounds ran"}
    for rnd in range(1, args.rounds + 1):
        tpath = os.path.join(TRANSCRIPTS, f"{tid}.r{rnd}.jsonl")
        status, rc, wall, result, prov = agentproc.run_round(
            prompt, tpath, cwd=REPO, session_id=session_id,
            resume=(rnd > 1), model=args.model, max_turns=args.max_turns,
            allowed_tools=ALLOWED_TOOLS, deadline_seconds=args.timeout,
            continue_message=FEEDBACK.get(outcome), env=env,
            settings_path=settings_path)

        if status != "ok":
            outcome, detail = "agent_error", {"error": status}
        elif rc != 0:
            outcome, detail = "agent_error", {"error": f"exit {rc}"}
        else:
            outcome, detail = gate(path, before_counts, args.build_timeout)

        try:
            analysis = classify(load_events(tpath),
                                rejected=(outcome != "accepted"))
        except Exception as e:
            analysis = {"error": f"transcript parse failed: {e}"}
        rounds.append({
            "round": rnd, "outcome": outcome,
            "wall_seconds": round(wall, 1), "status": status,
            "transcript": os.path.relpath(tpath, REPO),
            "provenance": prov,
            # actual models billed (the isolated config dir has no user
            # `model` setting, so "default" here means claude's default)
            "models_used": sorted((result or {}).get("modelUsage") or {}),
            "cost_usd": (result or {}).get("total_cost_usd"),
            "num_turns": (result or {}).get("num_turns"),
            **({"usage_totals": analysis.get("usage_totals"),
                "assistant_turns": analysis.get("assistant_turns"),
                "buckets": analysis.get("buckets")}
               if "error" not in analysis
               else {"analysis_error": analysis["error"]}),
        })
        if outcome == "accepted" or outcome not in FEEDBACK \
                or agentproc.RECEIVED_SIGNAL is not None:
            break
    return outcome, detail, rounds, session_id


# ── gates ────────────────────────────────────────────────────────────────
def gate(target_path, before_counts, build_timeout=BUILD_TIMEOUT):
    mod, new = changed_files()
    if new or set(mod) - {target_path}:
        return "rejected_scope", {"modified": mod, "new": new}
    if mod:  # target actually touched — scan forbidden constructs
        diff = sh(["git", "diff", "--unified=0", "--", target_path]).stdout
        added = "\n".join(l[1:] for l in diff.splitlines()
                          if l.startswith("+") and not l.startswith("+++"))
        if FORBIDDEN_RE.search(added):
            return "rejected_forbidden_attr", {}
    rc, after, build_s = build_sorry_counts(build_timeout)
    b = {"gate_build_seconds": build_s}
    if rc == "timeout":
        # policy violation, not "not done yet": resuming would just make
        # the agent try another blow-up. Rolled back like any rejection.
        return "rejected_kernel_budget", {**b, "build_timeout": build_timeout}
    if rc != 0:
        return "rejected_build", b
    if after.get(target_path, 0) >= before_counts.get(target_path, 0):
        return "rejected_sorry_remains", {**b,
                                          "before": before_counts.get(target_path, 0),
                                          "after": after.get(target_path, 0)}
    others_before = {f: c for f, c in before_counts.items() if f != target_path}
    others_after = {f: c for f, c in after.items() if f != target_path}
    if others_before != others_after:
        return "rejected_sorry_migration", {**b,
            "delta": {f: (others_before.get(f, 0), others_after.get(f, 0))
                      for f in set(others_before) ^ set(others_after)
                      | {f for f in others_before if others_before.get(f) != others_after.get(f)}}}
    g2 = sh(["python3", "harness/gates/g2_trust_base.py", "--skip-build"])
    if g2.returncode != 0:
        return "rejected_g2", {**b, "g2_tail": g2.stdout[-1500:]}
    return "accepted", {**b, "counts_after": after}


# ── main loop ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zones", default="specs,aux")
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--match", default="", help="substring filter on location")
    ap.add_argument("--model", default="")
    ap.add_argument("--max-turns", type=int, default=30, help="per round")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="seconds per ROUND (wall clock, process-group kill)")
    ap.add_argument("--build-timeout", type=int, default=BUILD_TIMEOUT,
                    help="seconds for each harness-side `lake build` (baseline "
                         "and gate); exceeding it in the gate is "
                         "rejected_kernel_budget (N3 minimal)")
    ap.add_argument("--rounds", type=int, default=1,
                    help="max claude rounds per target; rounds >1 resume the "
                         "same session with gate feedback (default 1 = old "
                         "single-shot behavior)")
    ap.add_argument("--wire-log", action="store_true",
                    help="record raw API requests via a localhost proxy "
                         "(ledger/wire/wire_requests.jsonl); best-effort")
    ap.add_argument("--settings", default=OFFLINE_SETTINGS,
                    help="claude --settings file (network deny-list); "
                         "default .claude/settings-offline.json")
    ap.add_argument("--run-dir", default="",
                    help="per-run evidence dir holding the isolated "
                         "CLAUDE_CONFIG_DIR (default ledger/runs/<utc-ts>)")
    ap.add_argument("--no-isolation", action="store_true",
                    help="DEBUG ONLY: reuse the operator's ~/.claude "
                         "(memory, plugins, MCP, local settings leak in); "
                         "the ledger marks such records isolated=false")
    ap.add_argument("--commit", action="store_true",
                    help="git commit each accepted fill")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve targets + print prompts, no agent, no build")
    args = ap.parse_args()

    os.makedirs(TRANSCRIPTS, exist_ok=True)
    agentproc.install_signal_handler()
    env = os.environ.copy()
    if not os.path.isfile(args.settings):
        sys.exit(f"settings file not found: {args.settings}")
    settings_path = os.path.abspath(args.settings)
    isolation = {"isolated": not args.no_isolation,
                 "settings": os.path.relpath(settings_path, REPO),
                 "settings_sha256": agentproc.sha256_file(settings_path),
                 "setting_sources": "user", "strict_mcp_config": True}
    if args.no_isolation:
        print("[driver] WARNING: --no-isolation — agent shares ~/.claude "
              "with interactive sessions", flush=True)
    elif not args.dry_run:
        run_dir = args.run_dir or os.path.join(
            LEDGER_DIR, "runs",
            now_iso().replace(":", "").replace("+0000", "Z"))
        cfg, seeded = agentproc.make_config_dir(run_dir)
        if not seeded and not any(k in env for k in
                                  ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")):
            sys.exit("no credentials: neither ~/.claude/.credentials.json "
                     "nor ANTHROPIC_API_KEY — the isolated agent cannot "
                     "authenticate")
        env = agentproc.isolated_env(env, cfg)
        isolation.update({"config_dir": os.path.relpath(cfg, REPO),
                          "credentials_seeded": seeded})
        print(f"[driver] isolated CLAUDE_CONFIG_DIR={cfg}", flush=True)
    if args.wire_log and not args.dry_run:
        agentproc.start_wire_proxy(os.path.join(LEDGER_DIR, "wire"), env)
    inv = json.load(open(INVENTORY))
    targets = [loc for z in args.zones.split(",")
               for loc in inv["locations"][z.strip()]]
    if args.match:
        targets = [t for t in targets if args.match in t]
    if args.limit:
        targets = targets[:args.limit]
    print(f"{len(targets)} target(s), zones={args.zones}")

    before_counts, baseline_s = {}, None
    if not args.dry_run:
        mod, _ = changed_files()
        if mod:
            sys.exit(f"working tree not clean (tracked changes: {mod}); "
                     f"commit or restore first")
        snapshot_untracked()  # pre-existing untracked files are not the agent's
        print("baseline build …", flush=True)
        rc, before_counts, baseline_s = build_sorry_counts(args.build_timeout)
        if rc == "timeout":
            sys.exit(f"baseline lake build exceeded --build-timeout "
                     f"{args.build_timeout}s; raise it explicitly")
        if rc != 0:
            sys.exit("baseline lake build failed — fix before running driver")
        print(f"baseline: {sum(before_counts.values())} sorry decls "
              f"in {len(before_counts)} files, {baseline_s}s build")
        if baseline_s > args.build_timeout / 3:
            print(f"[driver] WARNING: baseline build {baseline_s}s is over a "
                  f"third of --build-timeout {args.build_timeout}s; accepted "
                  f"proofs only make it slower", flush=True)

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
        outcome, detail, rounds, session_id = run_rounds(
            prompt, tid, path, before_counts, args, env, settings_path)

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

        out_tokens = sum((r.get("usage_totals") or {}).get("output_tokens")
                         or 0 for r in rounds)
        record = {
            "ts": now_iso(), "target": loc, "decl": decl, "path": path,
            "outcome": outcome, "detail": detail,
            "session_id": session_id,
            "isolation": isolation,
            "rounds_run": len(rounds), "max_rounds": args.rounds,
            "wall_seconds": round(sum(r["wall_seconds"] for r in rounds), 1),
            "output_tokens_total": out_tokens,
            "model": args.model or "default", "max_turns": args.max_turns,
            "build_timeout": args.build_timeout,
            "baseline_build_seconds": baseline_s,
            "rounds": rounds,
        }
        with open(os.path.join(LEDGER_DIR, "rounds.jsonl"), "a") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"    {outcome} | rounds={len(rounds)}"
              + (f" out={out_tokens}" if out_tokens else ""))

        if agentproc.RECEIVED_SIGNAL is not None:
            print("[driver] interrupted — rollback + ledger persisted; "
                  "exiting")
            sys.exit(128 + agentproc.RECEIVED_SIGNAL)

    if not args.dry_run:
        print(f"\ndone: {accepted}/{len(targets)} accepted; "
              f"ledger at ledger/rounds.jsonl")


if __name__ == "__main__":
    main()
