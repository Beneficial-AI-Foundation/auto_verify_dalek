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
  * stop rules (DEC-16): --rounds × --timeout (per-target wall bound),
    --max-cost-usd, agent END_REASON:LIMIT, stall (target file unchanged
    for --stall-rounds rounds) and context bloat → session reset with a
    compact round history, at most --max-auto-resets times, then stop.
    All limits can come from --run-config JSON and are recorded per ledger
    record under `limits`.
  * rollback still happens exactly once, after the final round's verdict.

Gate stack per attempt (all must pass to accept):
  a. scope: `git status --porcelain` shows changes ONLY in the target file
  b. no new `axiom`, `@[implemented_by]`, `@[extern]` in the changed file
     (the native_decide hijack path — plan.md §4 policy)
  c. `lake build` exits 0 within --build-timeout (default 1200s; a
     timeout is rejected_kernel_budget — N3 minimal, plan.md §6)
  c'. G1 statement identity (harness/gates/StmtCanon.lean --module):
     every constant declared in the target module before the attempt must
     still exist with the same kind and α-invariant canonical statement
     (agent-territory definitions δ-unfolded, so re-defining a helper
     cannot hide a change). Added declarations are allowed. Baseline is
     fingerprinted once per run over all target modules and refreshed
     for a module after each accept.
  d. sorry accounting vs pre-attempt snapshot: target file's sorry-warning
     count strictly decreases; every other file's count unchanged
  e. G2 trust-base gate (harness/gates/g2_trust_base.py --skip-build;
     check 5 is subsumed by d, which is stricter — per-file, both directions)

Rollback never uses destructive git verbs: modified tracked files are
restored via `git show HEAD:<f> > <f>`; new untracked files are removed.

Whole-T verdict (DEC-10) is NOT decided here: run harness/replay.py (fresh
worktree rebuild + G2 + G1 vs frozen statements) and harness/report.py
(inventory × ledger × tree × replay) after the batch.

Ledger:  ledger/rounds.jsonl        one record per attempt (see RECORD below)
    Every record carries provenance (DEC-17): `environment` (run-level:
    git HEAD/untracked list, lean-toolchain, lake-manifest/lakefile/
    inventory sha, lean/lake/claude versions, OS, CPU, RAM, harness file
    shas, prompt template sha) and `provenance` (per target: git HEAD at
    attempt start — drifts under --commit — and the rendered prompt sha).
    `models_used` is the union of billed model ids over all rounds, from
    the API result's `modelUsage`, not the requested --model.
         ledger/transcripts/*.jsonl raw stream-json, never discarded —
                                    bucket rules can be re-run post-hoc

Usage examples:
  python3 harness/driver.py --zones specs --limit 10 --dry-run
  python3 harness/driver.py --zones specs --limit 10 --commit
  python3 harness/driver.py --match AffineNielsPoint --max-turns 40
"""
import argparse
import datetime
import hashlib
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

End your final message with exactly one line:
  END_REASON:COMPLETE   — the proof is in place and `lake build` passes
  END_REASON:LIMIT      — you cannot finish this target; say why in one line
"""
END_REASON_RE = re.compile(r"(?m)^\s*END_REASON:(COMPLETE|LIMIT)\s*$", re.I)


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


def _file_sha(path):
    try:
        return agentproc.sha256_file(os.path.join(REPO, path))
    except OSError:
        return None


def _history_block(rounds):
    lines = [f"round {r['round']}: {r['outcome']}"
             + (f" ({json.dumps(r['detail'], ensure_ascii=False)[:200]})"
                if r.get('detail') else "")
             for r in rounds]
    return ("Round history so far (a previous session worked on this target; "
            "its edits were kept in the file, its context was not):\n  "
            + "\n  ".join(lines))


# ── provenance (DEC-17) ──────────────────────────────────────────────────
def _cmd_out(cmd, cwd=REPO):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=30)
        return (r.stdout or r.stderr).strip() if r.returncode == 0 \
            else f"<exit {r.returncode}>"
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"<{type(e).__name__}>"


def _read(path):
    try:
        with open(os.path.join(REPO, path)) as fh:
            return fh.read().strip()
    except OSError:
        return None


def environment_snapshot():
    """Run-level environment record (DEC-17). Everything an auditor needs to
    re-create the machine side of a run: repository revision, Lean toolchain
    and dependency lock, tool versions, hardware, OS. Per-record items that
    drift within a run (HEAD after --commit, prompt hash) live in
    `record_provenance`."""
    import platform
    cpu = None
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    mem_kb = None
    try:
        with open("/proc/meminfo") as fh:
            mem_kb = int(fh.readline().split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return {
        "git_head": _cmd_out(["git", "rev-parse", "HEAD"]),
        "git_branch": _cmd_out(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        "git_describe": _cmd_out(["git", "describe", "--always", "--dirty"]),
        # untracked files are invisible to HEAD but part of the input
        "git_untracked": _cmd_out(
            ["git", "ls-files", "--others", "--exclude-standard"]).splitlines(),
        "lean_toolchain": _read("lean-toolchain"),
        "lake_manifest_sha256": agentproc.sha256_file(
            os.path.join(REPO, "lake-manifest.json")),
        "lakefile_sha256": agentproc.sha256_file(
            os.path.join(REPO, "lakefile.toml")),
        "inventory_sha256": agentproc.sha256_file(INVENTORY),
        "lean_version": _cmd_out(["lean", "--version"]),
        "lake_version": _cmd_out(["lake", "--version"]),
        "claude_version": _cmd_out(["claude", "--version"]),
        "python_version": platform.python_version(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": cpu,
        "cpu_count": os.cpu_count(),
        "mem_total_kb": mem_kb,
        "driver_sha256": agentproc.sha256_file(os.path.abspath(__file__)),
        "agentproc_sha256": agentproc.sha256_file(agentproc.__file__),
        "prompt_template_sha256": hashlib.sha256(PROMPT.encode()).hexdigest(),
    }


def record_provenance(prompt):
    """Per-record items that can change between targets in one run."""
    return {
        "git_head": _cmd_out(["git", "rev-parse", "HEAD"]),
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
    }


def run_rounds(prompt, tid, path, before_counts, args, env, settings_path,
               g1_base=None):
    """Multi-round attempt on one target. Stop rules (DEC-16), ported from
    CryptoProver run.py and adapted to one-sorry targets:

      * --rounds            hard cap on agent rounds
      * --timeout           wall clock per round (process-group kill); the
                            per-target bound is rounds × timeout
      * --max-cost-usd      cumulative reported cost cap per target (0 = off)
      * END_REASON:LIMIT    agent's honest give-up ends the attempt
      * stall               --stall-rounds consecutive rounds that leave the
                            target file byte-identical → session reset
                            (fresh context + compact round history); after
                            --max-auto-resets, stop
      * bloat               a session whose cumulative cache-creation tokens
                            exceed --bloat-threshold-tokens is reset (context
                            degradation is the dominant failure mode in the
                            CryptoProver runs)
      Policy violations (scope / forbidden attr / migration / g2 / kernel
      budget) abort immediately, as before. CryptoProver's plateau guard is
      not ported: with a single sorry per target the progress metric is
      binary, so "no new low for N rounds" collapses into --rounds.

    Returns (outcome, detail, rounds, session_ids). Each round's transcript
    is ledger/transcripts/{tid}.r{n}.jsonl.
    """
    session_id = agentproc.new_session_id()
    session_ids = [session_id]
    rounds = []
    outcome, detail = "agent_error", {"error": "no rounds ran"}
    cost_total = 0.0
    session_cc_tokens = 0
    stall_run = 0
    resets = 0
    fresh = True
    continue_message = None
    for rnd in range(1, args.rounds + 1):
        if fresh and rounds:  # session reset: fresh context + history
            round_prompt = prompt + "\n\n" + _history_block(rounds)
        else:
            round_prompt = prompt
        sha_before = _file_sha(path)
        tpath = os.path.join(TRANSCRIPTS, f"{tid}.r{rnd}.jsonl")
        status, rc, wall, result, prov = agentproc.run_round(
            round_prompt, tpath, cwd=REPO, session_id=session_id,
            resume=not fresh, model=args.model, max_turns=args.max_turns,
            allowed_tools=ALLOWED_TOOLS,
            deadline_seconds=args.timeout,
            continue_message=continue_message, env=env,
            settings_path=settings_path,
            sandbox_prefix=getattr(args, "sandbox_prefix", None))
        was_fresh, fresh = fresh, False
        result = result or {}

        if status != "ok":
            outcome, detail = "agent_error", {"error": status}
        elif rc != 0:
            outcome, detail = "agent_error", {"error": f"exit {rc}"}
        else:
            outcome, detail = gate(path, before_counts, args.build_timeout,
                                   g1_base)

        m = END_REASON_RE.search(result.get("result") or "")
        end_reason = m.group(1).upper() if m else None
        try:
            analysis = classify(load_events(tpath),
                                rejected=(outcome != "accepted"))
        except Exception as e:
            analysis = {"error": f"transcript parse failed: {e}"}
        usage = analysis.get("usage_totals") or {}
        cost = result.get("total_cost_usd")
        cost_total += float(cost or 0)
        session_cc_tokens += usage.get("cache_creation_input_tokens", 0) or 0
        sha_after = _file_sha(path)
        edited = sha_after != sha_before
        stall_run = 0 if edited else stall_run + 1

        rounds.append({
            "round": rnd, "outcome": outcome, "detail": detail,
            "wall_seconds": round(wall, 1), "status": status,
            "session_id": session_id, "fresh_session": was_fresh,
            "transcript": os.path.relpath(tpath, REPO),
            "provenance": prov,
            "end_reason": end_reason,
            "target_file_edited": edited,
            # actual models billed (the isolated config dir has no user
            # `model` setting, so "default" here means claude's default)
            "models_used": sorted(result.get("modelUsage") or {}),
            "cost_usd": cost,
            "num_turns": result.get("num_turns"),
            "session_cache_creation_tokens": session_cc_tokens,
            **({"usage_totals": usage,
                "assistant_turns": analysis.get("assistant_turns"),
                "buckets": analysis.get("buckets")}
               if "error" not in analysis
               else {"analysis_error": analysis["error"]}),
        })

        # ── stop rules ──
        if outcome == "accepted" or outcome not in FEEDBACK \
                or agentproc.RECEIVED_SIGNAL is not None:
            break
        if end_reason == "LIMIT":
            outcome, detail = "agent_limit", {
                "gate_outcome": outcome, "gate_detail": detail}
            break
        if args.max_cost_usd and cost_total >= args.max_cost_usd:
            outcome, detail = "budget_exhausted", {
                "kind": "cost_usd", "cost_total": round(cost_total, 4),
                "max_cost_usd": args.max_cost_usd}
            break
        stall = args.stall_rounds and stall_run >= args.stall_rounds
        bloat = session_cc_tokens > args.bloat_threshold_tokens
        if stall or bloat:
            if not args.auto_reset or resets >= args.max_auto_resets:
                outcome, detail = "stalled", {
                    "gate_outcome": outcome, "stall_rounds": stall_run,
                    "bloat": bloat, "resets": resets}
                break
            resets += 1
            session_id = agentproc.new_session_id()
            session_ids.append(session_id)
            session_cc_tokens = 0
            stall_run = 0
            fresh = True
            rounds[-1]["reset_after"] = {
                "cause": ["stall"] * stall + ["bloat"] * bloat,
                "reset_no": resets}
            print(f"    reset→fresh session ({rounds[-1]['reset_after']})",
                  flush=True)
            continue_message = None
        else:
            continue_message = FEEDBACK[outcome]
            if end_reason == "COMPLETE":
                continue_message = ("You declared END_REASON:COMPLETE but "
                                    + continue_message)
    return outcome, detail, rounds, session_ids


# ── G1: statement identity (DEC-10 "unchanged supplied statements") ─────
STMT_CANON = os.path.join("harness", "gates", "StmtCanon.lean")


def stmt_fingerprints(modules, timeout=600):
    """{module: {name: {kind, canon, pp}}} for every user-facing constant
    declared in `modules`, via StmtCanon --module (needs current .olean
    files: run after `lake build`). Returns (fps, seconds) or raises
    RuntimeError with the tool's tail."""
    t0 = time.time()
    p = subprocess.run(["lake", "env", "lean", "--run", STMT_CANON,
                        "--module", ",".join(modules)],
                       cwd=REPO, capture_output=True, text=True,
                       timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError((p.stdout + p.stderr)[-2000:])
    fps = {m: {} for m in modules}
    for ln in p.stdout.splitlines():
        if not ln.startswith("{"):
            continue
        r = json.loads(ln)
        if "error" in r or not r.get("found"):
            raise RuntimeError(f"StmtCanon: {r}")
        fps.setdefault(r["module"], {})[r["name"]] = {
            "kind": r["kind"], "canon": r["canon"], "pp": r["pp"]}
    return fps, round(time.time() - t0, 1)


def stmt_diff(base, after):
    """Baseline names that vanished or whose (kind, canon) changed. Added
    names are allowed (helper lemmas)."""
    missing = sorted(n for n in base if n not in after)
    changed = {n: {"before": base[n]["pp"], "after": after[n]["pp"],
                   "kind": (base[n]["kind"], after[n]["kind"])}
               for n in base if n in after
               and (base[n]["kind"], base[n]["canon"])
               != (after[n]["kind"], after[n]["canon"])}
    return missing, changed


# ── gates ────────────────────────────────────────────────────────────────
def gate(target_path, before_counts, build_timeout=BUILD_TIMEOUT,
         g1_base=None):
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
    if g1_base is not None:
        mod_name = path_to_module(target_path)
        try:
            fps, g1_s = stmt_fingerprints([mod_name])
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            return "rejected_g1_error", {**b, "g1_error": str(e)[-1500:]}
        b["g1_seconds"] = g1_s
        missing, changed = stmt_diff(g1_base.get(mod_name, {}),
                                     fps.get(mod_name, {}))
        if missing or changed:
            return "rejected_statement_changed", {
                **b, "missing": missing, "changed": changed}
        b["g1_after"] = fps[mod_name]
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
    ap.add_argument("--model", default="",
                    help="REQUIRED (flag or run-config): the isolated config "
                         "dir carries no user model setting, so an unpinned "
                         "run uses whatever claude's built-in default is")
    ap.add_argument("--run-id", default="",
                    help="batch label written to every ledger record "
                         "(default: driver start time, UTC); rerunning a "
                         "target under a new run-id keeps attempts separable")
    ap.add_argument("--max-turns", type=int, default=30, help="per round")
    ap.add_argument("--timeout", type=int, default=900,
                    help="seconds per ROUND (wall clock, process-group kill); "
                         "per-target bound = --rounds × --timeout")
    ap.add_argument("--build-timeout", type=int, default=BUILD_TIMEOUT,
                    help="seconds for each harness-side `lake build` (baseline "
                         "and gate); exceeding it in the gate is "
                         "rejected_kernel_budget (N3 minimal)")
    ap.add_argument("--run-config", default="",
                    help="JSON file of limit defaults (keys = long flag names "
                         "with underscores); CLI flags override; recorded in "
                         "the ledger `limits` block (DEC-16)")
    ap.add_argument("--max-cost-usd", type=float, default=0.0,
                    help="cumulative reported cost cap per target; 0 = off")
    ap.add_argument("--stall-rounds", type=int, default=2,
                    help="consecutive rounds leaving the target file "
                         "byte-identical before a session reset; 0 disables")
    ap.add_argument("--bloat-threshold-tokens", type=int, default=200_000,
                    help="session cumulative cache-creation tokens that "
                         "trigger a preemptive session reset")
    ap.add_argument("--auto-reset", dest="auto_reset", action="store_true",
                    default=True)
    ap.add_argument("--no-auto-reset", dest="auto_reset", action="store_false",
                    help="on stall/bloat stop instead of resetting the session")
    ap.add_argument("--max-auto-resets", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=5,
                    help="max claude rounds per target; rounds >1 resume the "
                         "same session with gate feedback (CryptoProver "
                         "default 5; 1 = single-shot)")
    ap.add_argument("--wire-log", action="store_true",
                    help="record raw API requests via a localhost proxy "
                         "(ledger/wire/wire_requests.jsonl); best-effort")
    ap.add_argument("--settings", default=OFFLINE_SETTINGS,
                    help="claude --settings file (network deny-list); "
                         "default .claude/settings-offline.json")
    ap.add_argument("--run-dir", default="",
                    help="per-run evidence dir holding the isolated "
                         "CLAUDE_CONFIG_DIR (default ledger/runs/<utc-ts>)")
    ap.add_argument("--sandbox", choices=("bwrap", "none"), default="bwrap",
                    help="filesystem sandbox for the agent process (DEC-08): "
                         "bwrap = private mount namespace, empty $HOME, repo "
                         "without .git/ledger/harness; none = host filesystem "
                         "(debug only, marked in the ledger)")
    ap.add_argument("--no-isolation", action="store_true",
                    help="DEBUG ONLY: reuse the operator's ~/.claude "
                         "(memory, plugins, MCP, local settings leak in); "
                         "the ledger marks such records isolated=false")
    ap.add_argument("--commit", action="store_true",
                    help="git commit each accepted fill")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve targets + print prompts, no agent, no build")
    if "--run-config" in sys.argv:
        cfg_path = sys.argv[sys.argv.index("--run-config") + 1]
        ap.set_defaults(**json.load(open(cfg_path)))
    args = ap.parse_args()
    if not args.model:
        sys.exit("--model is required (or `model` in --run-config): "
                 "see DEC-13; the isolated agent has no default model setting")
    run_id = args.run_id or now_iso().replace(":", "").replace("+0000", "Z")
    LIMIT_KEYS = ("model", "rounds", "max_turns", "timeout",
                  "max_cost_usd", "build_timeout", "stall_rounds",
                  "bloat_threshold_tokens", "auto_reset", "max_auto_resets")
    limits = {k: getattr(args, k) for k in LIMIT_KEYS}
    if args.run_config:
        limits["run_config"] = os.path.relpath(os.path.abspath(args.run_config), REPO)
        limits["run_config_sha256"] = agentproc.sha256_file(args.run_config)

    environment = environment_snapshot()
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
        isolation["sandbox"] = "none"
        print("[driver] WARNING: --no-isolation — agent shares ~/.claude "
              "with interactive sessions and sees the host filesystem",
              flush=True)
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
        if args.sandbox == "bwrap":
            try:
                prefix = agentproc.bwrap_prefix(REPO, cfg)
            except RuntimeError as e:
                sys.exit(f"--sandbox bwrap: {e} (use --sandbox none for debug)")
            print("[driver] sandbox self-test …", flush=True)
            checks = agentproc.sandbox_selftest(prefix, REPO, cfg)
            failed = [k for k, ok in checks.items() if not ok]
            isolation.update({"sandbox": "bwrap",
                              "sandbox_hidden": list(agentproc.SANDBOX_HIDDEN),
                              "sandbox_selftest": checks})
            if failed:
                sys.exit(f"sandbox self-test FAILED: {failed}")
            args.sandbox_prefix = prefix
            print(f"[driver] sandbox ok ({len(checks)} checks)", flush=True)
        else:
            isolation["sandbox"] = "none"
            print("[driver] WARNING: --sandbox none — agent sees the host "
                  "filesystem (.git history, sibling repos, caches)",
                  flush=True)
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

    before_counts, baseline_s, g1_base = {}, None, None
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
        target_mods = sorted({path_to_module(resolve_target(t)[0])
                              for t in targets if resolve_target(t)})
        print(f"G1 baseline: fingerprinting {len(target_mods)} module(s) …",
              flush=True)
        try:
            g1_base, g1_s = stmt_fingerprints(target_mods)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            sys.exit(f"G1 baseline failed: {str(e)[-2000:]}")
        print(f"G1 baseline: {sum(len(v) for v in g1_base.values())} "
              f"declarations, {g1_s}s", flush=True)
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
        prov = record_provenance(prompt)
        outcome, detail, rounds, session_ids = run_rounds(
            prompt, tid, path, before_counts, args, env, settings_path,
            g1_base)

        if outcome == "accepted":
            before_counts = detail.pop("counts_after")
            g1_base[path_to_module(path)] = detail.pop("g1_after")
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
            "ts": now_iso(), "run_id": run_id,
            "target": loc, "decl": decl, "path": path,
            "outcome": outcome, "detail": detail,
            "session_ids": session_ids,
            "isolation": isolation,
            "limits": limits,
            "environment": environment,
            "provenance": prov,
            "models_used": sorted({m for r in rounds
                                   for m in r.get("models_used") or []}),
            "rounds_run": len(rounds), "max_rounds": args.rounds,
            "wall_seconds": round(sum(r["wall_seconds"] for r in rounds), 1),
            "output_tokens_total": out_tokens,
            "model": args.model,
            "baseline_build_seconds": baseline_s,
            "rounds": rounds,
        }
        with open(os.path.join(LEDGER_DIR, "rounds.jsonl"), "a") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"    {outcome} | rounds={len(rounds)} "
              f"sessions={len(session_ids)}"
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
