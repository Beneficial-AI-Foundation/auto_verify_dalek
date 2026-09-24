#!/usr/bin/env python3
"""Phase-1 driver loop (plan.md 附:优先级 1).

Per target:  pick sorry → resolve declaration in the CURRENT file → run Claude
Code headless (stream-json transcript saved) → gate → accept/rollback → ledger.

Agent invocation lives in harness/agentproc.py (session UUID + --resume rounds,
process-group kill, wall-clock deadline, signal handling, optional wire
proxy — ported from CryptoProver run.py). Multi-round policy here:
  * round 1 starts a fresh session pinned to an explicit UUID; rounds 2..N
    `--resume` it with the gate verdict as feedback, so the agent keeps its
    exploration context (failed tactics, half-built lemmas). The feedback
    carries the gate's diagnostics (feedback_message / diagnostics_block):
    `error: file:line:col` lines classified by kind, the modules a
    timed-out build never finished, any `maxHeartbeats` the agent raised,
    and a hint per kind (shrink the context / split into lemmas, do not
    raise heartbeats). Also recorded per round under `feedback`.
  * only "not done yet" rejections continue (rejected_build,
    rejected_sorry_remains, rejected_no_spec, rejected_kernel_budget).
    Policy violations (scope / forbidden attr / sorry migration / g2)
    abort the target immediately: they require a rollback, and resuming
    after a rollback would desync the agent's view of the tree.
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
     timeout is rejected_kernel_budget — N3 minimal, plan.md §6 — and
     resumes like a failing build while rounds remain)
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

Workspaces: the agent never runs in this checkout. Each --jobs slot is a
sealed copy (see make_slot); accepted files are copied back here (and
committed with --commit). Targets are grouped by file per slot.

Usage examples:
  python3 harness/driver.py --zones specs --limit 10 --dry-run
  python3 harness/driver.py --zones specs --jobs 2 --model <id>
  python3 harness/driver.py --zones specs --limit 10 --commit
  python3 harness/driver.py --path Curve25519Dalek/Specs/Scalar/Scalar --max-turns 40
  python3 harness/driver.py --zones specs --strip-comments targets   # anti-leak (see strip_comments.py)
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buckets import classify, load_events  # noqa: E402
import agentproc  # noqa: E402  (harness/agentproc.py — subprocess layer)
import strip_comments  # noqa: E402  (anti-leak comment strip + merge-back)

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


def sh(cmd, work=None, **kw):
    return subprocess.run(cmd, cwd=work or REPO, capture_output=True,
                          text=True, **kw)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ── sorry accounting ─────────────────────────────────────────────────────
BUILD_TIMEOUT = 1200  # seconds; fixed so runs on different machines are comparable


def build_sorry_counts(work, timeout=BUILD_TIMEOUT, include_output=False):
    """lake build → (exit_code | "timeout", {file: sorry_warning_count}, wall_s).

    N3 minimal version (plan.md §6): a `decide`-style kernel blow-up passes
    elaboration but can run for hours; Lean's maxHeartbeats does not bound
    the kernel, so only a wall clock does. lake is spawned in its own
    process group and the whole group is SIGKILLed on timeout — plain
    `subprocess.run(timeout=)` would kill `lake` and orphan the `lean`
    workers, which keep burning cores.
    """
    t0 = time.time()
    # nice -n 19: gate builds are batch work; don't starve the host (or the
    # other --jobs slot). The timeout stays wall-clock, so on a loaded
    # machine a niced build can hit it sooner — the budget includes that.
    proc = subprocess.Popen(["nice", "-n", "19", "lake", "build"], cwd=work,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    out = ""
    try:
        out, _ = proc.communicate(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # the pipe still holds what lake printed before the kill: which
        # module it was building tells the next round where the blow-up is
        out, _ = proc.communicate()
        result = ("timeout", {}, round(time.time() - t0, 1))
        return (*result, out or "") if include_output else result
    counts = {}
    for ln in out.splitlines():
        if "declaration uses `sorry`" in ln or "declaration uses 'sorry'" in ln:
            loc = ln.split(" declaration")[0]
            loc = loc.removeprefix("warning: ").lstrip("./")
            f = loc.split(":")[0]
            counts[f] = counts.get(f, 0) + 1
    result = (rc, counts, round(time.time() - t0, 1))
    return (*result, out) if include_output else result


# ── gate diagnostics (fed back into the next round's prompt) ─────────────
# The bare verdict ("lake build fails") sent the 2026-09-22 as_bytes run in
# circles: the build tail is cut at 4000 chars, so an `omega` counterexample
# listing hid the `error: file:line:col:` header, and the agent's answer to a
# heartbeat timeout was to raise `maxHeartbeats`. Feed back the error lines
# (location + first message line, a few per file so one noisy file cannot
# crowd out the others — CryptoProver's diversification), and a short hint
# for the two failure modes that actually recur: resource blow-ups and omega
# counterexamples. Everything else is `other`, no hint.
ERROR_LINE_RE = re.compile(
    r"(?:^|\n)error: (?:\./)*([^:\n]+\.lean):(\d+):(\d+): ([^\n]*)")
HEARTBEATS_RE = re.compile(r"set_option\s+maxHeartbeats\s+(\d+)")
MAX_ERRORS_FED_BACK = 8
MAX_ERRORS_PER_FILE = 3

ERROR_KINDS = (  # first match wins; anything else is "other"
    ("resource", re.compile(r"maximum number of heartbeats|\(deterministic\) timeout"
                            r"|maximum recursion depth")),
    ("omega_failed", re.compile(r"omega could not prove")),
)

HINTS = {
    "resource": (
        "A heartbeat/recursion timeout is charged to the whole declaration and "
        "raising `maxHeartbeats` does not fix it (the gate has a fixed wall "
        "clock). Shrink the context with `clear * - h1 h2 ...` right before "
        "`omega`/`scalar_tac`/`simp`, or move the slow step into its own lemma."),
    "omega_failed": (
        "`omega` found a counterexample: the atoms in its `where` list (e.g. "
        "`(a.set i x)[k]!`, `z / 2^51`) are opaque to it. Rewrite them first "
        "or state the needed relation as a hypothesis, then run omega in a "
        "standalone lemma over just those hypotheses."),
}

KERNEL_BUDGET_HINT = (
    "The gate's `lake build` did not finish within the wall-clock limit and "
    "was killed; `maxHeartbeats` does not bound this, so raising it is never "
    "the fix. Split the slow declaration into lemmas with small contexts and "
    "avoid `decide` on large terms.")

HEARTBEATS_RAISED_HINT = (
    "Revert the `maxHeartbeats` increase; it is not the fix and it makes "
    "every build slower.")


def classify_error(message):
    for kind, rx in ERROR_KINDS:
        if rx.search(message):
            return kind
    return "other"


def parse_build_errors(build_out, limit=MAX_ERRORS_FED_BACK,
                       per_file=MAX_ERRORS_PER_FILE):
    """`error: file:line:col: msg` lines of a lake build → deduplicated
    [{file, line, col, kind, message}] in build order, at most `per_file`
    per file and `limit` overall."""
    seen, per, errs = set(), {}, []
    for f, ln, col, msg in ERROR_LINE_RE.findall(build_out or ""):
        f = f.lstrip("./")
        key = (f, int(ln), int(col))
        if key in seen or per.get(f, 0) >= per_file:
            continue
        seen.add(key)
        per[f] = per.get(f, 0) + 1
        errs.append({"file": f, "line": int(ln), "col": int(col),
                     "kind": classify_error(msg), "message": msg.strip()})
        if len(errs) >= limit:
            break
    return errs


def unfinished_modules(build_out, editable_paths):
    """Editable modules lake did not report finished (`Built` / `Replayed`)
    before the output ended. Non-interactive lake prints a job only on
    completion, so after a timeout kill these are where the build was
    stuck (or downstream of it)."""
    finished = set(re.findall(
        r"\[\d+/\d+\] (?:Built|Replayed|Compiled|Ran) (\S+)", build_out or ""))
    return [path_to_module(p) for p in editable_paths
            if path_to_module(p) not in finished]


def heartbeat_raises(added_lines):
    """`set_option maxHeartbeats N` values the agent introduced."""
    return sorted({int(v) for v in HEARTBEATS_RE.findall(added_lines or "")})


def diagnostics_block(outcome, detail):
    """Human-readable gate diagnostics for the next round's prompt (and the
    reset history). Empty string when there is nothing to say."""
    lines, hints = [], []
    errs = detail.get("errors") or []
    if errs:
        secs = detail.get("gate_build_seconds")
        lines.append("Gate `lake build`" + (f" ({secs:.0f}s)" if secs else "")
                     + " errors, in build order:")
        for e in errs:
            lines.append(f"  {e['file']}:{e['line']}:{e['col']}: {e['message']}")
        if detail.get("errors_truncated"):
            lines.append("  ... (more errors omitted)")
        for kind in dict.fromkeys(e["kind"] for e in errs):
            if kind in HINTS:
                hints.append(HINTS[kind])
    if outcome == "rejected_kernel_budget":
        stuck = detail.get("unfinished") or []
        lines.append(f"Gate `lake build` killed at the "
                     f"{detail.get('build_timeout')}s wall-clock limit"
                     + ("; modules not finished: " + ", ".join(stuck)
                        if stuck else "") + ".")
        hints.append(KERNEL_BUDGET_HINT)
    raised = detail.get("heartbeats_raised") or []
    if raised:
        lines.append("Your edit sets `maxHeartbeats` to "
                     + ", ".join(str(v) for v in raised) + ".")
        hints.append(HEARTBEATS_RAISED_HINT)
    if not lines:
        return ""
    out = "\n".join(lines)
    if hints:
        out += "\nHints:\n" + "\n".join("- " + h for h in dict.fromkeys(hints))
    return out


# ── target resolution (robust to line drift from earlier accepts) ───────
def resolve_target(loc, work=REPO):
    """inventory 'path:line:col' → (path, decl_name, current_line) or None if filled."""
    path, line = loc.split(":")[0], int(loc.split(":")[1])
    full = os.path.join(work, path)
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


AENEAS_HEADER = "THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS"


def is_aeneas_generated(full_path):
    """Aeneas extraction output (Funs.lean, Types.lean): its comments are the
    generator banner and `Source:` pointers, never proof content (DEC-20)."""
    with open(full_path, encoding="utf-8") as fh:
        return AENEAS_HEADER in "".join(fh.readline() for _ in range(3))


# ── slot workspaces (one per parallel job) ───────────────────────────────
# Every agent works in its own sealed copy of the tree, never in the
# operator's checkout:
#   * rsync of the tracked+untracked tree (clean tracked tree is required)
#     minus .git, ledger/, .lake/packages; .lake/build is copied so the slot
#     starts warm (no rebuild);
#   * .lake/packages is a symlink to the main checkout's — 8.5 GB of
#     mathlib/aeneas shared read-only (bwrap binds the target ro; the
#     sandbox self-test asserts it is not writable);
#   * `git init` + one commit: a sealed history with exactly the baseline,
#     so scope checks (`git status`), forbidden-attr diffs and rollback
#     (`git show HEAD:`) run unchanged against the slot, and nothing in the
#     slot's object store points back at the real history;
#   * every accept is committed in the slot at once, so a later rejected
#     target in the same file rolls back to the last accept, not to the
#     baseline. (Without slots this required --commit on the main tree.)
# Targets are grouped by file and a whole file group goes to one slot, so
# two slots never edit the same file and merge-back is a plain copy.
SLOT_EXCLUDES = (".git", "ledger", ".lake/packages", ".claude/settings.local.json")


def make_slot(run_dir, i, strip_paths=()):
    """Build slot i. `strip_paths` (repo-relative .lean files) are comment-
    stripped in the slot *before* the sealed baseline commit, so the agent's
    whole visible history is comment-free (strip_comments.py; the operator's
    checkout is untouched). Returns (slot_dir, strip_report)."""
    slot = os.path.join(run_dir, f"slot{i}", "work")
    os.makedirs(slot, exist_ok=True)
    cmd = ["rsync", "-a", "--delete"]
    for e in SLOT_EXCLUDES:
        cmd += ["--exclude", "/" + e]
    cmd += [REPO + "/", slot + "/"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"slot {i}: rsync failed: {r.stderr[-800:]}")
    pk = os.path.join(slot, ".lake", "packages")
    if not os.path.islink(pk):
        os.makedirs(os.path.dirname(pk), exist_ok=True)
        os.symlink(os.path.join(REPO, ".lake", "packages"), pk)
    strip_report = {}
    if strip_paths:
        try:
            strip_report = strip_comments.strip_files(strip_paths, root=slot)
        except ValueError as e:
            sys.exit(f"slot {i}: comment strip failed: {e}")
    g = ["git", "-c", "user.name=harness", "-c", "user.email=harness@localhost"]
    for c in (["init", "-q"], ["add", "-A"],
              ["commit", "-q", "--allow-empty", "-m", "sealed baseline"]):
        r = subprocess.run(g + c, cwd=slot, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"slot {i}: git {c[0]} failed: {r.stderr[-800:]}")
    return slot, strip_report


def changed_files(work):
    out = sh(["git", "status", "--porcelain"], work).stdout
    mod, new = [], []
    for ln in out.splitlines():
        st, f = ln[:2], ln[3:].strip().strip('"')
        if f.startswith((".verilib/", "ledger/")):
            continue
        (new if "?" in st else mod).append(f)
    return mod, new


def rollback(mod, new, work):
    """Never uses destructive git verbs: tracked files are restored via
    `git show HEAD:<f>`; agent-created files are removed."""
    for f in mod:
        blob = sh(["git", "show", f"HEAD:{f}"], work)
        if blob.returncode == 0:
            open(os.path.join(work, f), "w").write(blob.stdout)
    for f in new:
        p = os.path.join(work, f)
        if os.path.isfile(p):
            os.remove(p)
        elif os.path.isdir(p):  # porcelain lists a fully-untracked dir as `dir/`
            shutil.rmtree(p)


def slot_commit(work, path, msg):
    """Commit one path or an atomic batch of paths in a sealed slot."""
    paths = [path] if isinstance(path, str) else list(path)
    sh(["git", "add", "--", *paths], work)
    sh(["git", "-c", "user.name=harness", "-c", "user.email=harness@localhost",
        "commit", "-q", "-m", msg], work)


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
    "rejected_no_spec": (
        "The harness gate rejected this round: the file compiles without "
        "`sorry`, but it contains no theorem tagged `@[progress]` whose "
        "statement mentions the target function. Add and prove such a "
        "specification. All original rules still apply."),
    "rejected_kernel_budget": (
        "The harness gate rejected this round: its `lake build` did not "
        "finish within the wall-clock limit and was killed. Make the build "
        "fast again (see the diagnostics below); the proof must compile "
        "within the gate's budget. All original rules still apply."),
}


def _file_sha(path, work):
    try:
        return agentproc.sha256_file(os.path.join(work, path))
    except OSError:
        return None


def feedback_message(outcome, detail, timeout=None, end_reason=None):
    """The message a FEEDBACK-rejected round is resumed with: the fixed
    verdict text, the round-end circumstance, then the gate diagnostics
    (error locations, timeout kind, hints) — see diagnostics_block."""
    msg = FEEDBACK[outcome]
    if end_reason == "COMPLETE":
        msg = "You declared END_REASON:COMPLETE but " + msg
    elif detail.get("deadline_exhausted") and timeout:
        msg = (f"The previous round was killed at the {timeout}s wall-clock "
               "limit; your last command may not have finished. Re-check the "
               "file state before continuing. " + msg)
    diag = diagnostics_block(outcome, detail)
    if diag:
        msg += "\n\n" + diag
    return msg


def _history_block(rounds):
    lines = []
    for r in rounds:
        detail = r.get("detail") or {}
        brief = {k: v for k, v in detail.items()
                 if k not in ("build_error_tail", "g1_after", "errors",
                              "result_specs")}
        lines.append(f"round {r['round']}: {r['outcome']}"
                     + (f" ({json.dumps(brief, ensure_ascii=False)[:200]})"
                        if brief else ""))
        diag = diagnostics_block(r["outcome"], detail)
        if diag:  # locations + hints only; the hints repeat, keep the first
            lines.extend("  " + ln for ln in diag.split("\nHints:")[0].splitlines())
    hints = dict.fromkeys(
        h for r in rounds
        for h in diagnostics_block(r["outcome"], r.get("detail") or {})
        .split("\nHints:\n")[1:2])
    return ("Round history so far (a previous session worked on this target; "
            "its edits were kept in the file, its context was not):\n  "
            + "\n  ".join(lines)
            + ("\nHints:\n" + "\n".join(hints) if hints else ""))


# ── seal (DEC-12): hash the main checkout at run start ──────────────────
# `git_head` covers tracked content only when the tree is clean; the gate's
# own inputs (harness/frozen/*, limits JSON, settings) may be untracked and
# HEAD says nothing about them. So every non-ignored file is hashed once at
# run start and re-hashed before each target and at the end. Two digests:
#   input_tree_sha256  over INPUT_PREFIXES — what the agent or a gate reads.
#                      An unexplained change here breaks the seal: the record
#                      is marked seal.input_ok=false (the run is not aborted;
#                      classification of invalidation is DEC "what event
#                      invalidates a run", still open).
#   tree_sha256        over everything non-ignored. A change outside the input
#                      set is recorded as drift, not a violation (README edits).
# Accepted merge-backs legitimately change target files in the main checkout;
# the expected manifest is updated with the post-accept hash so they do not
# count as violations.
INPUT_PREFIXES = ("Curve25519Dalek/", "Curve25519Dalek.lean", "Utils/",
                  "Utils.lean", "lakefile.toml", "lake-manifest.json",
                  "lean-toolchain", "harness/", ".verilib/sorry_inventory.json",
                  ".claude/settings-offline.json", "curve25519-dalek/")
SEAL_EXCLUDE = ("ledger/",)


def is_input(path):
    return path.startswith(INPUT_PREFIXES)


def tree_manifest():
    """{path: sha256} for every tracked or untracked-not-ignored file."""
    out = sh(["git", "ls-files", "--cached", "--others", "--exclude-standard",
              "-z"]).stdout
    man = {}
    for f in out.split("\0"):
        if not f or f.startswith(SEAL_EXCLUDE):
            continue
        full = os.path.join(REPO, f)
        if os.path.isfile(full) and not os.path.islink(full):
            man[f] = agentproc.sha256_file(full)
    return man


def _digest(man, pred=lambda p: True):
    h = hashlib.sha256()
    for f in sorted(man):
        if pred(f):
            h.update(f"{f}\0{man[f]}\n".encode())
    return h.hexdigest()


def seal_digests(man):
    return {"input_tree_sha256": _digest(man, is_input),
            "tree_sha256": _digest(man),
            "files": len(man), "input_files": sum(map(is_input, man))}


def seal_check(expected):
    """Re-hash the main checkout and diff against `expected` (path→sha).
    Returns {input_ok, violations, drift} where violations are input-set
    paths that changed/appeared/vanished and drift the same outside it."""
    now = tree_manifest()
    changed = sorted(set(expected) ^ set(now)
                     | {f for f in expected if f in now and expected[f] != now[f]})
    viol = [f for f in changed if is_input(f)]
    drift = [f for f in changed if not is_input(f)]
    return {"input_ok": not viol, "violations": viol, "drift": drift,
            **seal_digests(now)}


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
               g1_base, work, sandbox_prefix, log, editable_paths=None):
    """Multi-round attempt on one target. Stop rules (DEC-16), ported from
    CryptoProver run.py and adapted to one-sorry targets:

      * --rounds            hard cap on agent rounds
      * --timeout           wall clock per round (process-group kill); the
                            per-target bound is rounds × timeout. Like max
                            turns below, a deadline kill is not an
                            agent_error: the gate runs on what's on disk and
                            the session is resumed next round
      * --max-cost-usd      cumulative reported cost cap per target (0 = off)
      * END_REASON:LIMIT    agent's honest give-up ends the attempt
      * max turns           a round that dies of --max-turns (claude exits 1,
                            subtype error_max_turns) is not an agent_error:
                            the gate runs on what's on disk and a FEEDBACK
                            rejection resumes the session next round
      * stall               --stall-rounds consecutive rounds that leave the
                            target file byte-identical → session reset
                            (fresh context + compact round history); after
                            --max-auto-resets, stop
      * bloat               a session whose cumulative cache-creation tokens
                            exceed --bloat-threshold-tokens is reset (context
                            degradation is the dominant failure mode in the
                            CryptoProver runs)
      Policy violations (scope / forbidden attr / migration / g2) abort
      immediately, as before. CryptoProver's plateau guard is
      not ported: with a single sorry per target the progress metric is
      binary, so "no new low for N rounds" collapses into --rounds.

    Returns (outcome, detail, rounds, session_ids). Each round's transcript
    is ledger/transcripts/{tid}.r{n}.jsonl.
    """
    editable_paths = tuple(dict.fromkeys(editable_paths or [path]))
    if path not in editable_paths:
        raise ValueError("path must be included in editable_paths")
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
        sha_before = {p: _file_sha(p, work) for p in editable_paths}
        tpath = os.path.join(TRANSCRIPTS, f"{tid}.r{rnd}.jsonl")
        status, rc, wall, result, prov = agentproc.run_round(
            round_prompt, tpath, cwd=work, session_id=session_id,
            resume=not fresh, model=args.model, max_turns=args.max_turns,
            allowed_tools=ALLOWED_TOOLS,
            deadline_seconds=args.timeout,
            continue_message=continue_message, env=env,
            settings_path=settings_path, sandbox_prefix=sandbox_prefix)
        was_fresh, fresh = fresh, False
        result = result or {}

        cut_off = None
        if status == "deadline":
            cut_off = "deadline_exhausted"
        elif rc != 0 and result.get("subtype") == "error_max_turns":
            cut_off = "max_turns_exhausted"
        if status not in ("ok", "deadline"):
            outcome, detail = "agent_error", {"error": status}
        elif cut_off:
            # Ran out of --max-turns or of the --timeout wall clock mid-work
            # — not a failure, the round just ended early. Gate whatever is
            # on disk: a FEEDBACK rejection (build fails / sorry remains)
            # resumes the same session next round (claude's session file is
            # written incrementally, so it survives the SIGKILL); a finished
            # proof is accepted as usual.
            outcome, detail = gate(work, path, before_counts,
                                   args.build_timeout, g1_base,
                                   g2=getattr(args, "g2", True),
                                   mode=getattr(args, "gate_mode", "fill"),
                                   callee=getattr(args, "gate_callee", None),
                                   editable_paths=editable_paths,
                                   callees=getattr(args, "gate_callees", None),
                                   pure_callees=getattr(args, "gate_pure_callees", ()))
            detail[cut_off] = True
        elif rc != 0:
            outcome, detail = "agent_error", {"error": f"exit {rc}"}
        else:
            outcome, detail = gate(work, path, before_counts,
                                   args.build_timeout, g1_base,
                                   g2=getattr(args, "g2", True),
                                   mode=getattr(args, "gate_mode", "fill"),
                                   callee=getattr(args, "gate_callee", None),
                                   editable_paths=editable_paths,
                                   callees=getattr(args, "gate_callees", None),
                                   pure_callees=getattr(args, "gate_pure_callees", ()))

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
        sha_after = {p: _file_sha(p, work) for p in editable_paths}
        edited_paths = sorted(p for p in editable_paths
                              if sha_after[p] != sha_before[p])
        edited = bool(edited_paths)
        stall_run = 0 if edited else stall_run + 1

        rounds.append({
            "round": rnd, "outcome": outcome, "detail": detail,
            "wall_seconds": round(wall, 1), "status": status,
            "session_id": session_id, "fresh_session": was_fresh,
            "transcript": os.path.relpath(tpath, REPO),
            "provenance": prov,
            "end_reason": end_reason,
            "target_file_edited": edited,
            "edited_files": edited_paths,
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
            log(f"    reset→fresh session ({rounds[-1]['reset_after']})")
            continue_message = None
        else:
            continue_message = feedback_message(
                outcome, detail, timeout=args.timeout, end_reason=end_reason)
            rounds[-1]["feedback"] = continue_message
    return outcome, detail, rounds, session_ids


# ── G1: statement identity (DEC-10 "unchanged supplied statements") ─────
STMT_CANON = os.path.join("harness", "gates", "StmtCanon.lean")


def stmt_fingerprints(modules, work, timeout=600):
    """{module: {name: {kind, canon, pp}}} for every user-facing constant
    declared in `modules`, via StmtCanon --module (needs current .olean
    files: run after `lake build`). Returns (fps, seconds) or raises
    RuntimeError with the tool's tail."""
    t0 = time.time()
    p = subprocess.run(["nice", "-n", "19",
                        "lake", "env", "lean", "--run", STMT_CANON,
                        "--module", ",".join(modules)],
                       cwd=work, capture_output=True, text=True,
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
            "kind": r["kind"], "canon": r["canon"], "pp": r["pp"],
            "consts": [c["name"] for c in r.get("consts", [])]}
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


def progress_specs_for(callee, fps_module, target_path, work, require_progress=True):
    """Theorems of the target module whose statement uses the constant
    `callee` and that carry `@[progress]` in the source (attribute block
    directly before the declaration). Names as StmtCanon prints them.
    require_progress=False (a pure, non-`Result` function: `@[progress]`
    does not apply) accepts any theorem whose statement uses `callee`."""
    if not callee:
        return []
    try:
        src = open(os.path.join(work, target_path), encoding="utf-8").read()
    except OSError:
        return []
    out = []
    for name, fp in fps_module.items():
        if fp.get("kind") != "theorem" or callee not in fp.get("consts", []):
            continue
        short = re.escape(name.rsplit(".", 1)[-1])
        if not require_progress or re.search(r"@\[[^\]]*\bprogress\b[^\]]*\]\s*(?:@\[[^\]]*\]\s*)*"
                     r"(?:private\s+|protected\s+)?theorem\s+(?:[\w.]*\.)?" + short + r"(?![\w'])", src):
            out.append(name)
    return sorted(out)


# ── gates ────────────────────────────────────────────────────────────────
def gate(work, target_path, before_counts, build_timeout=BUILD_TIMEOUT,
         g1_base=None, g2=True, mode="fill", callee=None,
         editable_paths=None, callees=None, pure_callees=()):
    """g2=False skips the G2 trust-base gate (harness/gates/g2_trust_base.py
    needs the main checkout's frozen manifests; a bundle workspace has
    neither — prove_top_spec.py). Recorded in the verdict detail.

    mode="fill" (default): the target file's sorry count must strictly
    decrease. mode="spec" (legacy one-file mode): the target file's sorry
    count must not increase and
    the file must contain at least one `@[progress]` theorem whose
    statement mentions the constant `callee` (checked on the G1 fingerprints' used constants, so
    g1_base must be given, {} for a fresh file).

    mode="joint" accepts an explicit set of editable paths. `target_path` is
    the fixed top-spec file; its sorry count must decrease, every other
    editable file may not gain sorry, and `callees` maps each planned
    function name to the spec file that must contain its progress theorem.
    `pure_callees` names functions (in `callee`/`callees`) that do not
    return `Result`: any proved theorem about them counts, `@[progress]`
    is not required. Existing declarations in every editable module
    remain G1-identical."""
    pure_callees = set(pure_callees or ())
    editable_paths = tuple(dict.fromkeys(editable_paths or [target_path]))
    editable_set = set(editable_paths)
    if target_path not in editable_set:
        return "rejected_scope", {"error": "top target is not editable",
                                  "target_path": target_path,
                                  "editable_paths": list(editable_paths)}
    mod, new = changed_files(work)
    outside = (set(mod) | set(new)) - editable_set
    # Joint skeletons are created before the sealed baseline. Any file first
    # appearing during the agent session is therefore outside the contract.
    if new or outside:
        return "rejected_scope", {"modified": mod, "new": new,
                                  "outside": sorted(outside),
                                  "editable_paths": list(editable_paths)}
    added = ""
    if mod:  # scan added lines in every changed allowlisted file
        diff = sh(["git", "diff", "--unified=0", "--", *sorted(mod)], work).stdout
        added = "\n".join(l[1:] for l in diff.splitlines()
                          if l.startswith("+") and not l.startswith("+++"))
        if FORBIDDEN_RE.search(added):
            return "rejected_forbidden_attr", {}
    rc, after, build_s, build_out = build_sorry_counts(
        work, build_timeout, include_output=True)
    b = {"gate_build_seconds": build_s}
    raised = heartbeat_raises(added)
    if raised:  # diagnostics only; the feedback tells the agent to revert
        b["heartbeats_raised"] = raised
    if rc == "timeout":
        # "not done yet" like a failing build: the session is resumed with
        # the unfinished modules and the split-don't-raise-heartbeats hint
        # (2026-09-22 as_bytes r3 ended here with the diagnostics unread).
        return "rejected_kernel_budget", {
            **b, "build_timeout": build_timeout,
            "unfinished": unfinished_modules(build_out, editable_paths),
            "errors": parse_build_errors(build_out)}
    if rc != 0:
        # only `error:` lines: a failing build also replays every file's
        # `sorry` warnings, which would list the whole package as broken
        paths = sorted(set(re.findall(
            r"(?:^|\n)error: (?:\./)*([^:\n]+\.lean):\d+",
            build_out)))
        errors = parse_build_errors(build_out)
        return "rejected_build", {
            **b, "broken_files": paths,
            "errors": errors,
            "errors_truncated": len(parse_build_errors(
                build_out, limit=MAX_ERRORS_FED_BACK + 1,
                per_file=MAX_ERRORS_FED_BACK + 1)) > len(errors),
            "build_error_tail": build_out[-4000:]}
    if g1_base is not None:
        modules = [path_to_module(p) for p in editable_paths]
        try:
            fps, g1_s = stmt_fingerprints(modules, work)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            return "rejected_g1_error", {**b, "g1_error": str(e)[-1500:]}
        b["g1_seconds"] = g1_s
        missing, changed = {}, {}
        for mod_name in modules:
            mi, ch = stmt_diff(g1_base.get(mod_name, {}),
                               fps.get(mod_name, {}))
            if mi:
                missing[mod_name] = mi
            if ch:
                changed[mod_name] = ch
        if missing or changed:
            return "rejected_statement_changed", {
                **b, "missing": missing, "changed": changed}
        b["g1_after"] = fps
    if mode == "spec":
        # no NEW sorry: pre-existing sorried theorems in the file (a kept
        # top spec sharing the file) are other targets, G1 keeps them
        if after.get(target_path, 0) > before_counts.get(target_path, 0):
            return "rejected_sorry_remains", {**b, "mode": mode,
                                              "before": before_counts.get(target_path, 0),
                                              "after": after.get(target_path, 0)}
        fps_module = b.get("g1_after", {}).get(path_to_module(target_path), {})
        specs = progress_specs_for(callee, fps_module, target_path, work,
                                   require_progress=callee not in pure_callees)
        if not specs:
            return "rejected_no_spec", {**b, "mode": mode, "callee": callee,
                                        "pure": callee in pure_callees}
        b["specs"] = specs
    elif mode == "joint":
        if after.get(target_path, 0) >= before_counts.get(target_path, 0):
            return "rejected_sorry_remains", {
                **b, "mode": mode, "path": target_path,
                "before": before_counts.get(target_path, 0),
                "after": after.get(target_path, 0)}
        result_specs = {}
        fps_all = b.get("g1_after", {})
        for planned_fn, spec_path in sorted((callees or {}).items()):
            specs = progress_specs_for(
                planned_fn, fps_all.get(path_to_module(spec_path), {}),
                spec_path, work,
                require_progress=planned_fn not in pure_callees)
            if not specs:
                return "rejected_no_spec", {
                    **b, "mode": mode, "callee": planned_fn,
                    "path": spec_path, "pure": planned_fn in pure_callees}
            result_specs[planned_fn] = [
                {"theorem": n,
                 "pp": fps_all[path_to_module(spec_path)][n]["pp"]}
                for n in specs]
        b["result_specs"] = result_specs
        for editable in editable_paths:
            if editable == target_path:
                continue
            if after.get(editable, 0) > before_counts.get(editable, 0):
                return "rejected_sorry_remains", {
                    **b, "mode": mode, "path": editable,
                    "before": before_counts.get(editable, 0),
                    "after": after.get(editable, 0)}
    elif after.get(target_path, 0) >= before_counts.get(target_path, 0):
        return "rejected_sorry_remains", {**b,
                                          "before": before_counts.get(target_path, 0),
                                          "after": after.get(target_path, 0)}
    exempt_sorry_paths = editable_set if mode == "joint" else {target_path}
    others_before = {f: c for f, c in before_counts.items()
                     if f not in exempt_sorry_paths}
    others_after = {f: c for f, c in after.items()
                    if f not in exempt_sorry_paths}
    if others_before != others_after:
        return "rejected_sorry_migration", {**b,
            "delta": {f: (others_before.get(f, 0), others_after.get(f, 0))
                      for f in set(others_before) ^ set(others_after)
                      | {f for f in others_before if others_before.get(f) != others_after.get(f)}}}
    if not g2:
        return "accepted", {**b, "g2": "skipped", "counts_after": after}
    g2 = sh(["python3", os.path.join(work, "harness", "gates",
                                     "g2_trust_base.py"), "--skip-build"], work)
    if g2.returncode != 0:
        return "rejected_g2", {**b, "g2_tail": g2.stdout[-1500:]}
    return "accepted", {**b, "counts_after": after}


# ── main loop ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zones", default="specs,aux")
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--path", default="",
                    help="keep only targets in this .lean file or under "
                         "this directory (path prefix on whole components, "
                         "not a substring: Specs/Scalar/Scalar does not "
                         "catch Scalar52)")
    ap.add_argument("--model", default="",
                    help="claude --model; REQUIRED (the isolated config "
                         "dir carries no user model setting, so an unpinned "
                         "run would silently use claude's default)")
    ap.add_argument("--run-id", default="",
                    help="tag written into every ledger record (default: "
                         "UTC timestamp)")
    ap.add_argument("--max-turns", type=int, default=30, help="per round")
    ap.add_argument("--timeout", type=int, default=900,
                    help="wall-clock seconds per round (process-group kill)")
    ap.add_argument("--build-timeout", type=int, default=BUILD_TIMEOUT,
                    help="seconds for each harness-side `lake build` (baseline "
                         "and gate); exceeding it is rejected_kernel_budget")
    ap.add_argument("--run-config", default="",
                    help="JSON with limits (model, rounds, max_turns, timeout, "
                         "build_timeout, max_cost_usd, stall_rounds, "
                         "bloat_threshold_tokens, max_auto_resets, jobs); "
                         "CLI flags override")
    ap.add_argument("--max-cost-usd", type=float, default=0.0,
                    help="per-target cumulative reported cost cap (0 = off)")
    ap.add_argument("--stall-rounds", type=int, default=2,
                    help="consecutive rounds with the target file unchanged "
                         "before a session reset (0 = off)")
    ap.add_argument("--bloat-threshold-tokens", type=int, default=200_000,
                    help="session cache-creation tokens that trigger a "
                         "session reset")
    ap.add_argument("--auto-reset", dest="auto_reset", action="store_true",
                    default=True)
    ap.add_argument("--no-auto-reset", dest="auto_reset", action="store_false",
                    help="stop on stall/bloat instead of resetting the session")
    ap.add_argument("--max-auto-resets", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=5,
                    help="max agent rounds per target (round 1 fresh, then "
                         "--resume with gate feedback)")
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel agents; each gets its own sealed slot "
                         "workspace + sandbox + CLAUDE_CONFIG_DIR. Targets "
                         "are grouped by file; one file never spans slots")
    ap.add_argument("--strip-comments", choices=("off", "targets", "project"),
                    default="off",
                    help="anti-leak: remove every comment (docstrings, module "
                         "docs, `--`, `/- -/`) from the .lean files the agent "
                         "sees, in each sealed slot only (strip_comments.py). "
                         "`targets` = the files of the selected targets; "
                         "`project` = every hand-written .lean under "
                         "Curve25519Dalek/ and Utils/ — Aeneas-generated files "
                         "(Funs, Types) are skipped, their comments are source "
                         "pointers, not proofs (slots then rebuild the changed "
                         "modules once; DEC-20). "
                         "Accepted proofs are merged back into the commented "
                         "operator files. Default off.")
    ap.add_argument("--wire-log", action="store_true",
                    help="record raw API requests via a localhost proxy "
                         "(ledger/wire/)")
    ap.add_argument("--settings", default=OFFLINE_SETTINGS,
                    help="claude --settings file (network deny-list); "
                         "default .claude/settings-offline.json")
    ap.add_argument("--run-dir", default="",
                    help="directory for this run's slots and isolated "
                         "CLAUDE_CONFIG_DIRs (default ledger/runs/<utc-ts>)")
    ap.add_argument("--sandbox", choices=("bwrap", "none"), default="bwrap",
                    help="filesystem sandbox for the agent process (DEC-08): "
                         "bwrap = private mount namespace, empty $HOME, slot "
                         "without .git/harness; none = host filesystem "
                         "(debug only, marked in the ledger)")
    ap.add_argument("--no-isolation", action="store_true",
                    help="debug: share the operator's ~/.claude with the agent "
                         "(memory, plugins, MCP, local settings leak in); "
                         "records are marked isolated=false")
    ap.add_argument("--commit", action="store_true",
                    help="git commit each accepted fill in the main checkout")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.run_config:
        cfg = json.load(open(args.run_config))
        for k, v in cfg.items():
            if getattr(args, k, None) == ap.get_default(k):
                setattr(args, k, v)
    if not args.model:
        sys.exit("--model is required (or `model` in --run-config): "
                 "see DEC-13; the isolated agent has no default model setting")
    if args.jobs < 1:
        sys.exit("--jobs must be >= 1")

    LIMIT_KEYS = ("model", "rounds", "max_turns", "timeout",
                  "build_timeout", "max_cost_usd", "stall_rounds",
                  "bloat_threshold_tokens", "auto_reset", "max_auto_resets",
                  "jobs")
    limits = {k: getattr(args, k) for k in LIMIT_KEYS}
    if args.run_config:
        limits["run_config"] = os.path.relpath(os.path.abspath(args.run_config), REPO)
        limits["run_config_sha256"] = agentproc.sha256_file(args.run_config)
    run_id = args.run_id or now_iso()

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
                 "setting_sources": "user", "strict_mcp_config": True,
                 "tools": agentproc.tool_names(ALLOWED_TOOLS),
                 "allowed_tools": ALLOWED_TOOLS,
                 "disable_slash_commands": True,
                 "sandbox": "none" if args.no_isolation else args.sandbox,
                 "slots": True}
    if args.no_isolation:
        print("[driver] WARNING: --no-isolation — agent shares ~/.claude "
              "with interactive sessions and sees the host filesystem",
              flush=True)
    if args.sandbox == "none" and not args.no_isolation:
        print("[driver] WARNING: --sandbox none — agent sees the host "
              "filesystem (.git history, sibling repos, caches)", flush=True)
    if args.wire_log and not args.dry_run:
        agentproc.start_wire_proxy(os.path.join(LEDGER_DIR, "wire"), env)

    inv = json.load(open(INVENTORY))
    zones = [z.strip() for z in args.zones.split(",")]
    bad = [z for z in zones if z not in inv["locations"]]
    if bad:
        sys.exit(f"unknown zone(s) {bad}; inventory has: "
                 f"{sorted(inv['locations'])}")
    targets = [loc for z in zones for loc in inv["locations"][z]]
    if args.path:
        want = args.path.rstrip("/")
        targets = [t for t in targets
                   if t.split(":")[0] == want
                   or t.split(":")[0].startswith(want + "/")]
    if args.limit:
        targets = targets[:args.limit]
    print(f"{len(targets)} target(s), zones={args.zones}, jobs={args.jobs}")

    if args.dry_run:
        for i, loc in enumerate(targets):
            res = resolve_target(loc)
            if res is None:
                print(f"[{i+1}/{len(targets)}] {loc}: no sorry left, skip")
                continue
            path, decl, line = res
            print(f"[{i+1}/{len(targets)}] {loc} → `{decl}` (line {line})")
        return

    # ── baseline on the main checkout ──
    mod, _ = changed_files(REPO)
    if mod:
        sys.exit(f"working tree not clean (tracked changes: {mod}); "
                 f"commit or restore first")
    run_dir = args.run_dir or os.path.join(
        LEDGER_DIR, "runs", now_iso().replace(":", "").replace("+0000", "Z"))
    os.makedirs(run_dir, exist_ok=True)
    expected_manifest = tree_manifest()
    seal = seal_digests(expected_manifest)
    seal["manifest"] = os.path.relpath(
        os.path.join(run_dir, "tree_manifest.json"), REPO)
    with open(os.path.join(run_dir, "tree_manifest.json"), "w") as fh:
        json.dump(expected_manifest, fh, indent=0, sort_keys=True)
    environment["seal"] = seal
    print(f"seal: {seal['input_files']} input files "
          f"{seal['input_tree_sha256'][:12]}…, {seal['files']} files total "
          f"{seal['tree_sha256'][:12]}…", flush=True)
    print("baseline build …", flush=True)
    rc, before_counts, baseline_s = build_sorry_counts(REPO, args.build_timeout)
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
        g1_base, g1_s = stmt_fingerprints(target_mods, REPO)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        sys.exit(f"G1 baseline failed: {str(e)[-2000:]}")
    print(f"G1 baseline: {sum(len(v) for v in g1_base.values())} "
          f"declarations, {g1_s}s", flush=True)
    if baseline_s > args.build_timeout / 3:
        print(f"[driver] WARNING: baseline build {baseline_s}s is over a "
              f"third of --build-timeout {args.build_timeout}s; accepted "
              f"proofs only make it slower", flush=True)

    # ── anti-leak comment strip: which files lose their comments in slots ──
    strip_paths = []
    if args.strip_comments == "targets":
        strip_paths = sorted({loc.split(":")[0] for loc in targets})
    elif args.strip_comments == "project":
        for root_dir in ("Curve25519Dalek", "Utils"):
            for d, _, fs in os.walk(os.path.join(REPO, root_dir)):
                strip_paths += [os.path.relpath(os.path.join(d, f), REPO)
                                for f in fs if f.endswith(".lean")]
        strip_paths += ["Curve25519Dalek.lean", "Utils.lean"]
        strip_paths = sorted(p for p in strip_paths
                             if os.path.isfile(os.path.join(REPO, p))
                             and not is_aeneas_generated(os.path.join(REPO, p)))
    if strip_paths:
        print(f"[driver] --strip-comments {args.strip_comments}: "
              f"{len(strip_paths)} file(s) lose their comments in every slot",
              flush=True)

    # ── slots: sealed workspace + config dir + sandbox per job ──
    slots = []
    for i in range(args.jobs):
        work, strip_report = make_slot(run_dir, i, strip_paths)
        strip_summary = None
        if strip_paths:
            # The stripped tree must still build with exactly the baseline's
            # sorry counts — a strip bug must never masquerade as progress.
            # This also warms the slot's .lake/build for the changed modules.
            rc, counts, warm_s = build_sorry_counts(work, args.build_timeout)
            if rc != 0 or counts != before_counts:
                sys.exit(f"slot {i}: stripped tree differs from baseline "
                         f"(build rc={rc}, sorry counts "
                         f"{'equal' if counts == before_counts else 'differ'}) "
                         f"— comment strip is not semantics-preserving here")
            strip_summary = {
                "scope": args.strip_comments,
                "files": len(strip_report),
                "comments": sum(r["comments"] for r in strip_report.values()),
                "comment_lines": sum(r["comment_lines"]
                                     for r in strip_report.values()),
                "bytes_removed": sum(r["bytes_removed"]
                                     for r in strip_report.values()),
                "warm_build_s": warm_s,
                "stripped_tree_sha256": hashlib.sha256("".join(
                    f"{p}\0{r['sha256_after']}\n"
                    for p, r in sorted(strip_report.items())).encode()
                ).hexdigest()}
            with open(os.path.join(run_dir, f"slot{i}", "strip_report.json"),
                      "w") as fh:
                json.dump(strip_report, fh, indent=1, sort_keys=True)
            print(f"[driver] slot {i}: stripped {strip_summary['comments']} "
                  f"comments / {strip_summary['comment_lines']} lines in "
                  f"{strip_summary['files']} files; warm build {warm_s}s, "
                  f"sorry counts unchanged", flush=True)
        slot = {"i": i, "work": work, "env": env, "prefix": None,
                "strip": strip_summary,
                "isolation": dict(isolation,
                                  work=os.path.relpath(work, REPO))}
        if not args.no_isolation:
            cfg, seeded = agentproc.make_config_dir(
                os.path.join(run_dir, f"slot{i}"))
            if not seeded and not any(
                    k in env for k in ("ANTHROPIC_API_KEY",
                                       "ANTHROPIC_AUTH_TOKEN")):
                sys.exit("no credentials: neither ~/.claude/.credentials.json "
                         "nor ANTHROPIC_API_KEY — the isolated agent cannot "
                         "authenticate")
            slot["env"] = agentproc.isolated_env(env, cfg)
            slot["isolation"].update({
                "config_dir": os.path.relpath(cfg, REPO),
                "credentials_seeded": seeded})
            if args.sandbox == "bwrap":
                try:
                    prefix = agentproc.bwrap_prefix(
                        work, cfg, extra_ro=[settings_path])
                except RuntimeError as e:
                    sys.exit(f"--sandbox bwrap: {e} "
                             f"(use --sandbox none for debug)")
                checks = agentproc.sandbox_selftest(
                    prefix, work, cfg, extra_ro=[settings_path])
                failed = [k for k, ok in checks.items() if not ok]
                slot["isolation"].update({
                    "sandbox_hidden": list(agentproc.SANDBOX_HIDDEN),
                    "sandbox_selftest": checks})
                if failed:
                    sys.exit(f"slot {i}: sandbox self-test FAILED: {failed}")
                slot["prefix"] = prefix
        slots.append(slot)
        print(f"[driver] slot {i}: {os.path.relpath(work, REPO)}"
              + (f" sandbox ok ({len(slot['isolation']['sandbox_selftest'])} "
                 f"checks)" if slot["prefix"] else ""), flush=True)

    # ── work queue: file groups, inventory order ──
    groups, by_path = [], {}
    for loc in targets:
        path = loc.split(":")[0]
        if path not in by_path:
            by_path[path] = []
            groups.append(by_path[path])
        by_path[path].append(loc)
    queue = list(groups)
    lock = threading.Lock()          # queue, ledger, merge-back, counters
    state = {"accepted": 0, "done": 0, "n": len(targets)}
    common = {"expected_manifest": expected_manifest,
              "before_counts": before_counts, "g1_base": g1_base,
              "baseline_s": baseline_s, "run_id": run_id, "limits": limits,
              "environment": environment, "settings_path": settings_path,
              "file_owner": {}}    # path → slot index (DEC-19)

    def worker(slot):
        my_counts = dict(before_counts)
        my_g1 = copy.deepcopy(g1_base)
        while agentproc.RECEIVED_SIGNAL is None:
            with lock:
                if not queue:
                    return
                group = queue.pop(0)
                # DEC-19 tripwire: a file group must be owned by exactly one
                # slot for the whole run. The queue pop makes that true by
                # construction today; this guard turns a future regression
                # (grouping bug) into a loud stop instead of a silent
                # clobbering merge-back.
                gpath = group[0].split(":")[0]
                owner = common["file_owner"].setdefault(gpath, slot["i"])
                if owner != slot["i"]:
                    print(f"[driver] GROUPING BUG (DEC-19): {gpath} assigned "
                          f"to slot {slot['i']} but owned by slot {owner}; "
                          f"skipping group — fix the driver and rerun",
                          flush=True)
                    continue
            for loc in group:
                if agentproc.RECEIVED_SIGNAL is not None:
                    return
                process_target(slot, loc, my_counts, my_g1, args, common,
                               lock, state)

    threads = [threading.Thread(target=worker, args=(sl,), daemon=True,
                                name=f"slot{sl['i']}") for sl in slots]
    for t in threads:
        t.start()
    for t in threads:
        while t.is_alive():
            t.join(timeout=1.0)

    final = seal_check(expected_manifest)
    if not final["input_ok"]:
        print(f"[driver] SEAL BROKEN at end of run: input files changed "
              f"outside accepted merge-backs: {final['violations']}", flush=True)
    elif final["drift"]:
        print(f"[driver] seal ok; drift outside the input set: "
              f"{final['drift']}", flush=True)
    else:
        print("[driver] seal ok: tree identical to run start "
              "(plus accepted merge-backs)", flush=True)
    if agentproc.RECEIVED_SIGNAL is not None:
        print("[driver] interrupted — rollback + ledger persisted; exiting")
        sys.exit(128 + agentproc.RECEIVED_SIGNAL)
    print(f"\ndone: {state['accepted']}/{state['n']} accepted; "
          f"ledger at ledger/rounds.jsonl")


def process_target(slot, loc, my_counts, my_g1, args, common, lock, state):
    """One target in one slot: resolve → rounds → accept (slot commit +
    merge-back to the main checkout) or rollback → ledger record."""
    work, i = slot["work"], slot["i"]

    def log(msg):
        print(f"[s{i}] {msg}", flush=True)

    with lock:
        state["done"] += 1
        k = state["done"]
    res = resolve_target(loc, work)
    if res is None:
        log(f"[{k}/{state['n']}] {loc}: no sorry left, skip")
        return
    path, decl, line = res
    prompt = PROMPT.format(decl=decl, path=path, line=line,
                           module=path_to_module(path))
    log(f"[{k}/{state['n']}] {loc} → `{decl}` (line {line})")
    tid = re.sub(r"[^A-Za-z0-9_.]+", "_", loc)
    prov = record_provenance(prompt)
    with lock:
        prov["seal"] = seal_check(common["expected_manifest"])
    if not prov["seal"]["input_ok"]:
        log(f"    SEAL BROKEN before this target: input files changed: "
            f"{prov['seal']['violations']}")
    outcome, detail, rounds, session_ids = run_rounds(
        prompt, tid, path, my_counts, args, slot["env"],
        common["settings_path"], my_g1, work, slot["prefix"], log)

    if outcome == "accepted":
        # DEC-19 merge-back guard: we never merge code. The copy below is
        # only legal while the operator tree's copy of `path` still has the
        # hash this run last wrote (or started with). A mismatch means
        # someone else — another slot (grouping bug) or a human (seal
        # violation) — changed the file mid-run: do not clobber, roll the
        # job back, record the conflict. Fix the cause and rerun.
        msg = (f"phase1: fill {decl} ({loc})\n\n"
               f"Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>")
        with lock:  # merge-back: this slot owns every target in `path`
            repo_file = os.path.join(REPO, path)
            expected = common["expected_manifest"].get(path)
            found = (agentproc.sha256_file(repo_file)
                     if os.path.exists(repo_file) else None)
            new_text = None
            if found != expected:
                outcome = "rejected_merge_conflict"
                detail["merge_conflict"] = {
                    "path": path, "expected_sha256": expected,
                    "found_sha256": found}
            elif slot.get("strip"):
                # The slot's file is comment-free; replay the agent's edit
                # onto the commented operator file (strip_comments.merge_back
                # checks that the result carries exactly the accepted code).
                try:
                    new_text = strip_comments.merge_back(
                        open(repo_file, encoding="utf-8").read(),
                        open(os.path.join(work, path), encoding="utf-8").read())
                except (strip_comments.MergeError, ValueError) as e:
                    outcome = "rejected_merge_back_failed"
                    detail["merge_back_failed"] = {"path": path,
                                                   "error": str(e)[-2000:]}
            else:
                new_text = open(os.path.join(work, path), encoding="utf-8").read()
            if new_text is not None:
                my_counts.clear()
                my_counts.update(detail.pop("counts_after"))
                my_g1[path_to_module(path)] = detail.pop("g1_after")
                slot_commit(work, path, msg)
                with open(repo_file, "w", encoding="utf-8") as fh:
                    fh.write(new_text)
                common["expected_manifest"][path] = agentproc.sha256_file(
                    repo_file)
                if args.commit:
                    sh(["git", "add", path])
                    sh(["git", "commit", "-q", "-m", msg])
                state["accepted"] += 1
        if outcome == "rejected_merge_conflict":
            log(f"    MERGE CONFLICT (DEC-19): {path} changed in the "
                f"operator tree outside accepted merge-backs — job rolled "
                f"back, nothing copied")
            mod, new = changed_files(work)
            rollback(mod, new, work)
        elif outcome == "rejected_merge_back_failed":
            log(f"    MERGE-BACK FAILED: the agent's edit to the stripped "
                f"{path} could not be replayed onto the commented file — job "
                f"rolled back, nothing copied "
                f"({detail['merge_back_failed']['error'][:200]})")
            mod, new = changed_files(work)
            rollback(mod, new, work)
    else:
        mod, new = changed_files(work)
        rollback(mod, new, work)

    out_tokens = sum((r.get("usage_totals") or {}).get("output_tokens")
                     or 0 for r in rounds)
    record = {
        "ts": now_iso(), "run_id": common["run_id"],
        "target": loc, "decl": decl, "path": path,
        "outcome": outcome, "detail": detail,
        "session_ids": session_ids,
        "slot": i,
        "isolation": slot["isolation"],
        "comment_strip": slot.get("strip"),
        "limits": common["limits"],
        "environment": common["environment"],
        "provenance": prov,
        "models_used": sorted({m for r in rounds
                               for m in r.get("models_used") or []}),
        "rounds_run": len(rounds), "max_rounds": args.rounds,
        "wall_seconds": round(sum(r["wall_seconds"] for r in rounds), 1),
        "output_tokens_total": out_tokens,
        "model": args.model,
        "baseline_build_seconds": common["baseline_s"],
        "rounds": rounds,
    }
    with lock, open(os.path.join(LEDGER_DIR, "rounds.jsonl"), "a") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    log(f"    {outcome} | rounds={len(rounds)} sessions={len(session_ids)}"
        + (f" out={out_tokens}" if out_tokens else ""))


if __name__ == "__main__":
    main()
