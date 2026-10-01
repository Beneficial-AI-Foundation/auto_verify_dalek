"""Reuse partial proofs across runs (docs/PLAN-SEED-PARTIALS.md).

A rejected joint run leaves `partials/attempt-N/` in its run dir. This
module turns such a draft into a *compiling* skeleton for the next run of
the same target:

  * `decl_blocks(text)`      split a Lean file into declaration blocks
  * `inventory(text)`        per-declaration {name, line, sorry, progress}
  * `sanitize(text, errors)` heartbeat raises removed; a declaration whose
                             proof errors gets `sorry`; one whose statement
                             errors is deleted with everything that names it
  * `file_state(...)`        what `save_partial_snapshot` writes to state.json
  * `candidates(...)`        ranked seeds for a target from the ledger
  * `apply_seed(...)`        write, build, re-sanitize (≤ MAX_SANITIZE_ROUNDS),
                             commit into the slot; drop a file that never
                             compiles

Nothing here touches the bundle: seeds live in ledger/runs/ and in the slot.
"""
import hashlib
import json
import os
import re

import driver

MAX_SANITIZE_ROUNDS = 3
MAX_SEED_BLOCK_LINES = 40

DECL_START_RE = re.compile(
    r"^(?:private\s+|protected\s+|noncomputable\s+)*"
    r"(?:theorem|lemma|def|abbrev|instance|example)\b\s*(?P<name>[^\s:({\[]*)")
BLOCK_END_RE = re.compile(r"^(?:end\b|namespace\b|section\b|open\b|import\b|variable\b)")
ATTR_LINE_RE = re.compile(r"^\s*(?:@\[|set_option\s|open\s.*\sin\s*$|/--|--)")
HEARTBEAT_LINE_RE = re.compile(r"^\s*set_option\s+maxHeartbeats\s+\d+(?:\s+in)?\s*$")
PROOF_START_RE = re.compile(r":=\s*(?:by\b|$)")
SORRY_RE = re.compile(r"\bsorry\b")


# ── parsing ──────────────────────────────────────────────────────────────
def _comment_lines(lines):
    """Set of line indices inside a `/- … -/` or `/-- … -/` block comment."""
    inside, depth = set(), 0
    for i, ln in enumerate(lines):
        opened = depth > 0
        depth += ln.count("/-") - ln.count("-/")
        if opened or depth > 0 or "/-" in ln:
            inside.add(i)
        depth = max(depth, 0)
    return inside


def decl_blocks(text):
    """[{name, kind, start, decl, end, lines}] with 0-based line indices:
    `start` is the first attribute / docstring line, `decl` the line with
    the `theorem` keyword, `end` one past the last line of the block."""
    lines = text.splitlines()
    comment = _comment_lines(lines)
    starts = []
    for i, ln in enumerate(lines):
        m = DECL_START_RE.match(ln)
        if m and i not in comment:
            starts.append((i, m.group("name") or f"<anon@{i + 1}>"))

    def lead(decl):
        start = decl
        while start > 0 and (ATTR_LINE_RE.match(lines[start - 1])
                             or (start - 1) in comment):
            start -= 1
        return start

    blocks = []
    for k, (decl, name) in enumerate(starts):
        start = lead(decl)
        end = lead(starts[k + 1][0]) if k + 1 < len(starts) else len(lines)
        for j in range(decl + 1, end):
            if BLOCK_END_RE.match(lines[j]) and j not in comment:
                end = j
                break
        kind = re.search(r"\b(theorem|lemma|def|abbrev|instance|example)\b",
                         lines[decl]).group(1)
        blocks.append({"name": name, "kind": kind, "start": start,
                       "decl": decl, "end": end, "lines": lines[start:end]})
    return blocks


def proof_start(block):
    """Index (within block['lines']) of the line where the proof begins,
    None for a term-mode proof we cannot locate."""
    rel_decl = block["decl"] - block["start"]
    for i in range(rel_decl, len(block["lines"])):
        if PROOF_START_RE.search(block["lines"][i]):
            return i
    return None


def inventory(text):
    """[{name, kind, line (1-based), sorry, progress}] for every declaration."""
    out = []
    for b in decl_blocks(text):
        body = "\n".join(b["lines"])
        out.append({"name": b["name"], "kind": b["kind"], "line": b["decl"] + 1,
                    "sorry": bool(SORRY_RE.search(body)),
                    "progress": bool(re.search(r"@\[[^\]]*\bprogress\b", body))})
    return out


# ── sanitizing ───────────────────────────────────────────────────────────
def sanitize(text, errors):
    """(new_text, report). `errors`: [{line, ...}] 1-based lines in this
    file. report = {heartbeats_removed, sorried: [names], dropped: [names]}."""
    lines = text.splitlines()
    hb = [i for i, ln in enumerate(lines) if HEARTBEAT_LINE_RE.match(ln)]
    blocks = decl_blocks(text)
    errs = [(int(e["line"]) - 1, e.get("col")) for e in errors or []]
    sorried, dropped = [], []
    for b in blocks:
        hits = [(l, c) for l, c in errs if b["start"] <= l < b["end"]]
        if not hits:
            continue
        ps = proof_start(b)
        if ps is None:
            dropped.append(b["name"])
            continue
        pl = b["start"] + ps
        pc = PROOF_START_RE.search(b["lines"][ps]).start()  # 0-based, like Lean's col
        in_stmt = any(l < pl or (l == pl and c is not None and int(c) < pc) for l, c in hits)
        (dropped if in_stmt else sorried).append(b["name"])
    # cascade: anything later that names a dropped declaration goes too
    changed = True
    while changed:
        changed = False
        for b in blocks:
            if b["name"] in dropped or b["name"].startswith("<anon"):
                continue
            body = "\n".join(b["lines"])
            for d in dropped:
                if d.startswith("<anon"):
                    continue
                short = d.rsplit(".", 1)[-1]
                if re.search(r"(?<![\w.'])" + re.escape(short) + r"(?![\w'])", body) \
                        and b["decl"] > next(x["decl"] for x in blocks if x["name"] == d):
                    dropped.append(b["name"])
                    if b["name"] in sorried:
                        sorried.remove(b["name"])
                    changed = True
                    break
    out, i = [], 0
    by_start = {b["start"]: b for b in blocks}
    while i < len(lines):
        b = by_start.get(i)
        if b is None:
            if i not in hb:
                out.append(lines[i])
            i += 1
            continue
        if b["name"] in dropped:
            i = b["end"]
            continue
        blines = [ln for j, ln in enumerate(b["lines"]) if j + b["start"] not in hb]
        if b["name"] in sorried:
            ps = proof_start({"decl": b["decl"], "start": b["start"], "lines": blines})
            head = blines[:ps]
            m = PROOF_START_RE.search(blines[ps])
            head.append(blines[ps][:m.start()] + ":= by")
            head.append("  sorry")
            blines = head
        out.extend(blines)
        # keep one blank line between blocks
        if out and out[-1].strip():
            out.append("")
        i = b["end"]
    return "\n".join(out).rstrip("\n") + "\n", {
        "heartbeats_removed": len(hb), "sorried": sorried, "dropped": dropped}


def sanitize_all_proofs(text):
    """Every theorem/lemma proof replaced by `sorry` (defs kept): the
    statements-only skeleton, used when a build times out and no error
    location says which proof is the heavy one."""
    errs = []
    for b in decl_blocks(text):
        if b["kind"] in ("theorem", "lemma", "example"):
            ps = proof_start(b)
            if ps is not None:
                errs.append({"line": b["start"] + ps + 1})
    return sanitize(text, errs)


# ── snapshot state ───────────────────────────────────────────────────────
def file_state(path, text, rounds):
    """state.json entry for one editable file, from the last round's gate
    verdict (no new build)."""
    last = (rounds or [{}])[-1]
    detail = last.get("detail") or {}
    outcome = last.get("outcome")
    module = driver.path_to_module(path)
    compiles = None
    sorry_count = None
    if "counts_after" in detail:
        compiles = True
        sorry_count = detail["counts_after"].get(path, 0)
    elif outcome == "rejected_build" and "broken_files" in detail:
        # Absence of an error is not evidence Lake finished this module.
        compiles = False if path in detail["broken_files"] else None
    elif outcome == "rejected_kernel_budget" and "unfinished" in detail:
        compiles = False if module in detail["unfinished"] else None
    # anything else (scope / deadline / old records without diagnostics):
    # unknown; the seed build decides
    errors = [e for e in (detail.get("errors") or []) if e.get("file") == path]
    inv = inventory(text)
    if sorry_count is None and compiles:
        sorry_count = sum(1 for d in inv if d["sorry"])
    return {"path": path, "compiles": compiles, "sorry_count": sorry_count,
            "last_outcome": outcome, "errors": errors, "decls": inv}


def notes_text(rounds, transcripts_root):
    """notes.md: per round the verdict, circumstances and the agent's final
    message (from the transcript's `result` event, tolerant of junk lines)."""
    parts = []
    for r in rounds or []:
        detail = r.get("detail") or {}
        parts.append(f"## round {r.get('round')}: {r.get('outcome')}")
        parts.append(f"wall {r.get('wall_seconds')}s, turns {r.get('num_turns')}, "
                     f"status {r.get('status')}, END_REASON {r.get('end_reason')}")
        diag = driver.diagnostics_block(r.get("outcome"), detail)
        if diag:
            parts.append("```\n" + diag + "\n```")
        final = final_message(os.path.join(transcripts_root, r.get("transcript") or ""))
        if final:
            parts.append("Agent's final message:\n```\n" + final[-2000:] + "\n```")
        parts.append("")
    return "\n".join(parts)


def final_message(transcript_path):
    if not transcript_path or not os.path.isfile(transcript_path):
        return ""
    last = ""
    with open(transcript_path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            try:
                ev = json.loads(ln)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("type") == "result" and ev.get("result"):
                last = ev["result"]
    return last


# ── selection ────────────────────────────────────────────────────────────
def candidates(ledger_path, target, planned_by_path, repo, explicit=None):
    """Per planned spec path, the ranked list of seeds:
    [{path, run_id, run_dir, attempt, file, compiles, proved, decls, errors}].
    `planned_by_path`: {path: sorted short fn names} of the current plan;
    a partial qualifies for a path when its manifest lists the same set.
    `explicit`: "RUN_DIR[/attempt-N]" restricts to that partial."""
    found = {p: [] for p in planned_by_path}
    if not os.path.isfile(ledger_path):
        return found
    with open(ledger_path) as fh:
        records = [json.loads(l) for l in fh if l.strip()]
    for rec in records:
        if rec.get("target") != target or not rec.get("partial_manifest"):
            continue
        if (rec.get("plan") or {}).get("mode") != "joint":
            continue
        man_path = os.path.join(repo, rec["partial_manifest"])
        if not os.path.isfile(man_path):
            continue
        attempt_dir = os.path.dirname(man_path)
        run_dir = os.path.dirname(os.path.dirname(attempt_dir))
        if explicit and not _matches_explicit(explicit, run_dir, attempt_dir, repo):
            continue
        manifest = json.load(open(man_path))
        state = {}
        sp = os.path.join(attempt_dir, "state.json")
        if os.path.isfile(sp):
            state = {s["path"]: s for s in json.load(open(sp)).get("files", [])}
        for f in manifest.get("files", []):
            path = f["path"]
            if path not in planned_by_path or not f.get("changed"):
                continue
            if sorted(f.get("functions") or []) != sorted(planned_by_path[path]):
                continue
            src = os.path.join(attempt_dir, "files", path)
            if not os.path.isfile(src):
                continue
            text = open(src, encoding="utf-8").read()
            st = state.get(path) or file_state(path, text, rec.get("rounds"))
            inv = st.get("decls") or inventory(text)
            last = (rec.get("rounds") or [{}])[-1]
            note = f"{last.get('outcome')}, END_REASON {last.get('end_reason')}"
            errs = st.get("errors") or []
            if errs:
                note += "; last errors: " + "; ".join(
                    f"line {e.get('line')} {e.get('kind')}: {e.get('message', '')[:80]}"
                    for e in errs[:2])
            found[path].append({
                "note": note,
                "path": path, "run_id": rec["run_id"],
                "run_dir": os.path.relpath(run_dir, repo),
                "attempt": manifest.get("attempt", 1), "file": src,
                "compiles": st.get("compiles"),
                "proved": sum(1 for d in inv if not d["sorry"]),
                "decls": len(inv), "errors": st.get("errors") or [],
            })
    for path in found:
        found[path].sort(key=lambda c: (
            {True: 2, None: 1, False: 0}[c["compiles"]], c["proved"], c["decls"],
            c["run_id"]), reverse=True)
    return found


def _matches_explicit(explicit, run_dir, attempt_dir, repo):
    want = explicit.rstrip("/")
    for cand in (run_dir, attempt_dir):
        if os.path.abspath(cand) == os.path.abspath(os.path.join(repo, want)) \
                or os.path.abspath(cand) == os.path.abspath(want):
            return True
    return False


# ── application ──────────────────────────────────────────────────────────
def apply_seed(work, chosen, build_timeout, log=print):
    """Write each chosen seed file into the slot, sanitize until the slot
    builds, commit. `chosen`: {path: candidate}. Returns
    (seed_record, before_counts) where seed_record is the ledger's
    `plan.seed` value and before_counts the post-seed sorry counts.
    Files that never compile are restored to the skeleton and reported."""
    texts, reports = {}, {}
    for path, c in chosen.items():
        raw = open(c["file"], encoding="utf-8").read()
        text, rep = sanitize(raw, c.get("errors") or [])
        texts[path] = text
        reports[path] = {"source_run": c["run_id"], "attempt": c["attempt"],
                         "sha256_raw": hashlib.sha256(raw.encode()).hexdigest(),
                         "sanitize_rounds": [rep], "dropped_file": False}
    for path, text in texts.items():
        with open(os.path.join(work, path), "w", encoding="utf-8") as fh:
            fh.write(text)
    counts = {}
    for rnd in range(MAX_SANITIZE_ROUNDS + 1):
        rc, counts, secs, out = driver.build_sorry_counts(work, build_timeout, include_output=True)
        log(f"seed build {rnd}: rc={rc} {secs}s")
        if rc == 0:
            break
        errs = driver.parse_build_errors(out, limit=10_000, per_file=10_000) if rc != "timeout" else []
        by_file = {}
        for e in errs:
            by_file.setdefault(e["file"], []).append(e)
        stuck = [p for p in texts if p in by_file]
        foreign = [f for f in by_file if f not in texts]
        if rc == "timeout" and rnd < MAX_SANITIZE_ROUNDS and not any(
                r.get("all_proofs") for rep in reports.values() for r in rep["sanitize_rounds"]):
            # no location to blame: keep the statements, drop every proof
            for p in list(texts):
                text, rep = sanitize_all_proofs(texts[p])
                rep["all_proofs"] = True
                reports[p]["sanitize_rounds"].append(rep)
                texts[p] = text
                with open(os.path.join(work, p), "w", encoding="utf-8") as fh:
                    fh.write(text)
            continue
        if rc == "timeout" or foreign or not stuck or rnd == MAX_SANITIZE_ROUNDS:
            # give up on every seeded file still in play: restore skeletons
            for p in texts:
                driver.sh(["git", "checkout", "--", p], work)
                reports[p]["dropped_file"] = True
                reports[p]["drop_reason"] = ("timeout" if rc == "timeout" else
                                             "errors_outside_seed" if foreign else
                                             "still_failing")
            rc, counts, secs, out = driver.build_sorry_counts(work, build_timeout, include_output=True)
            if rc != 0:
                raise RuntimeError(f"slot does not build after dropping seeds: {out[-1500:]}")
            texts = {}
            break
        for p in stuck:
            text, rep = sanitize(texts[p], by_file[p])
            reports[p]["sanitize_rounds"].append(rep)
            if text == texts[p]:  # sanitizer found nothing to change: drop
                driver.sh(["git", "checkout", "--", p], work)
                reports[p]["dropped_file"] = True
                reports[p]["drop_reason"] = "unsanitizable"
                del texts[p]
                continue
            texts[p] = text
            with open(os.path.join(work, p), "w", encoding="utf-8") as fh:
                fh.write(text)
    files = []
    for path, rep in reports.items():
        entry = {"path": path, **rep}
        if not rep["dropped_file"]:
            final = open(os.path.join(work, path), encoding="utf-8").read()
            inv = inventory(final)
            entry.update({
                "sha256": hashlib.sha256(final.encode()).hexdigest(),
                "decls_proved": [d["name"] for d in inv if not d["sorry"]],
                "decls_sorried": [d["name"] for d in inv if d["sorry"]],
                "decls_dropped": sorted({n for r in rep["sanitize_rounds"] for n in r["dropped"]}),
            })
        files.append(entry)
    kept = [f["path"] for f in files if not f["dropped_file"]]
    if kept:
        driver.slot_commit(work, kept, "seed: " + ", ".join(
            f"{f['source_run']}/attempt-{f['attempt']}" for f in files if not f["dropped_file"]))
    return {"files": files}, counts


def seed_block(seed_record, notes_by_path=None):
    """Prompt text describing the seeded files (capped)."""
    lines = []
    for f in seed_record.get("files", []):
        if f.get("dropped_file"):
            continue
        lines.append(f"- {f['path']} (from run {f['source_run']}, attempt {f['attempt']}): "
                     f"{len(f['decls_proved'])} declaration(s) proved, "
                     f"{len(f['decls_sorried'])} with `sorry`, "
                     f"{len(f['decls_dropped'])} dropped (did not elaborate).")
        if f["decls_proved"]:
            lines.append("    proved: " + ", ".join(_short(n) for n in f["decls_proved"]))
        if f["decls_sorried"]:
            lines.append("    sorry:  " + ", ".join(_short(n) for n in f["decls_sorried"]))
        if f["decls_dropped"]:
            lines.append("    dropped: " + ", ".join(_short(n) for n in f["decls_dropped"]))
        note = (notes_by_path or {}).get(f["path"])
        if note:
            lines.append("    that run ended: " + note.strip().replace("\n", " ")[:300])
    if not lines:
        return ""
    lines = lines[:MAX_SEED_BLOCK_LINES]
    return ("\nSeeded draft from an earlier, rejected run of this target. It is in the\n"
            "files already; it compiles; every `sorry` in it is yours to remove.\n"
            + "\n".join(lines) + "\n"
            "Rules for seeded files: every `sorry` must be gone at the end; you may\n"
            "rewrite, split or delete any seeded declaration; do not assume a seeded\n"
            "statement is the right one — check it against the callers.\n")


def _short(name):
    return name.rsplit(".", 1)[-1]
