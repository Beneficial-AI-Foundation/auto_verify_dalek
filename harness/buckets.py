#!/usr/bin/env python3
"""Token bucket classifier for Claude Code stream-json transcripts (plan.md §11).

Five buckets over OUTPUT tokens, plus an input-side re-ingestion measure:

  productive   generation that survives: turns whose tool calls include
               Edit/Write, and final no-tool text turns (summary/answer)
  diagnostic   redirect after verifier feedback: turns whose tool calls run
               the verifier (Bash: lake/lean), and no-tool turns immediately
               following an error tool_result
  retrieval    turns whose tool calls are Read/Grep/Glob/loogle/leansearch/
               web search — one lookup replacing one generation
  dead_end     attempt-level override: if the driver REJECTED the attempt
               (build fail / G2 fail / scope violation), ALL output tokens of
               the attempt land here; the per-turn split is still reported
               under `turn_buckets_raw` for later re-analysis
  reingestion  input-side: sum of (input + cache_read + cache_creation)
               tokens over every assistant message AFTER the first — the cost
               of re-feeding context the model already saw. cache_read portion
               reported separately (it is the cheap part; plan §11 predicts
               computed-minimal-context RAISES its share)

Stream-json quirks this must survive (verified against a live transcript,
claude CLI 2.1.227):
  * one assistant event is emitted PER CONTENT BLOCK, with message.id and the
    full usage object repeated verbatim — naive per-event summing multiplies
    tokens by the block count.  → events are merged by message.id first.
  * usage.output_tokens on assistant events is a stream-start snapshot
    (single digits), NOT the final count; the authoritative totals live in
    the final `result` event.  → per-message output is ESTIMATED from content
    size (chars/4) and the estimates are scaled so they sum to the result
    event's output_tokens.  Input-side fields (input, cache_read,
    cache_creation) are known at request time and are correct per message.

Mixed turns (several tool categories) split their output share equally
across the matched categories. Rules are deliberately simple + deterministic:
raw transcripts are always kept, so the rules can be revised post-hoc.

Usage:  python3 harness/buckets.py <transcript.jsonl> [--rejected]
Import: classify(events, rejected=False) -> dict
"""
import json
import sys

EDIT_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}
DIAG_TOOLS = {"Bash", "BashOutput"}  # in this harness Bash ≈ lake build / lean
RETR_TOOLS = {"Read", "Grep", "Glob", "WebSearch", "WebFetch", "LS", "ToolSearch"}
RETR_PREFIXES = ("mcp__probe-lean__", "mcp__lean-lsp__")  # loogle/leansearch/goal etc.

CHARS_PER_TOKEN = 4.0  # coarse, only used for RELATIVE weight between messages


def _turn_categories(tool_names, prev_result_was_error):
    cats = set()
    for t in tool_names:
        if t in EDIT_TOOLS:
            cats.add("productive")
        elif t in DIAG_TOOLS:
            cats.add("diagnostic")
        elif t in RETR_TOOLS or t.startswith(RETR_PREFIXES):
            cats.add("retrieval")
        else:
            cats.add("productive")  # unknown tool: count against generation
    if not tool_names:
        cats.add("diagnostic" if prev_result_was_error else "productive")
    return cats


def _content_chars(block):
    t = block.get("type")
    if t == "text":
        return len(block.get("text") or "")
    if t == "thinking":
        return len(block.get("thinking") or "")
    if t == "tool_use":
        try:
            return len(json.dumps(block.get("input", {}), ensure_ascii=False))
        except (TypeError, ValueError):
            return 0
    return 0


def _merge_messages(events):
    """Group assistant events by message.id → ordered turn list; track the
    error-flag of the tool_result that PRECEDED each turn; grab result event."""
    turns, by_id = [], {}
    prev_result_was_error = False
    result_event = None
    for ev in events:
        etype = ev.get("type")
        if etype == "assistant":
            msg = ev.get("message", {})
            mid = msg.get("id") or id(msg)  # defensive: no id → unique key
            if mid not in by_id:
                turn = {"usage": msg.get("usage") or {}, "tool_names": [],
                        "chars": 0, "prev_error": prev_result_was_error}
                by_id[mid] = turn
                turns.append(turn)
            turn = by_id[mid]
            for b in msg.get("content", []):
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    turn["tool_names"].append(b.get("name", ""))
                turn["chars"] += _content_chars(b)
        elif etype == "user":
            content = ev.get("message", {}).get("content", [])
            if isinstance(content, list):
                prev_result_was_error = any(
                    isinstance(b, dict) and b.get("type") == "tool_result"
                    and b.get("is_error") for b in content)
        elif etype == "result":
            result_event = ev
    return turns, result_event


def classify(events, rejected=False):
    turns, result_event = _merge_messages(events)
    result_usage = (result_event or {}).get("usage") or {}

    # input side: request-time fields on the message are accurate
    totals = {"input_tokens": 0, "output_tokens": 0,
              "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    reingestion = reingestion_cache_read = 0
    for i, t in enumerate(turns):
        u = t["usage"]
        for k in ("input_tokens", "cache_creation_input_tokens",
                  "cache_read_input_tokens"):
            totals[k] += u.get(k, 0) or 0
        if i > 0:
            reingestion += sum((u.get(k, 0) or 0) for k in
                               ("input_tokens", "cache_read_input_tokens",
                                "cache_creation_input_tokens"))
            reingestion_cache_read += u.get("cache_read_input_tokens", 0) or 0

    # output side: per-event output_tokens is a stream-start snapshot →
    # estimate per-turn weight from content size, scale to authoritative total
    out_total = result_usage.get("output_tokens")
    est = [max(t["chars"] / CHARS_PER_TOKEN, 1.0) for t in turns]
    est_sum = sum(est) or 1.0
    if out_total is None:  # no result event (crash/timeout): keep raw estimate
        out_total = round(est_sum)
    totals["output_tokens"] = out_total
    for k in ("input_tokens", "cache_creation_input_tokens",
              "cache_read_input_tokens"):
        if k in result_usage:  # authoritative when present
            totals[k] = result_usage[k]

    turn_buckets = {"productive": 0.0, "diagnostic": 0.0, "retrieval": 0.0}
    for t, w in zip(turns, est):
        cats = _turn_categories(t["tool_names"], t["prev_error"])
        share = w / est_sum * out_total
        for c in cats:
            turn_buckets[c] += share / len(cats)

    if rejected:
        buckets = {"productive": 0, "diagnostic": 0, "retrieval": 0,
                   "dead_end": out_total}
    else:
        buckets = {k: round(v) for k, v in turn_buckets.items()}
        buckets["dead_end"] = 0
    buckets["reingestion_input"] = reingestion
    buckets["reingestion_cache_read"] = reingestion_cache_read

    return {
        "buckets": buckets,
        "turn_buckets_raw": {k: round(v) for k, v in turn_buckets.items()},
        "usage_totals": totals,
        "assistant_turns": len(turns),
        "result": {k: (result_event or {}).get(k) for k in
                   ("total_cost_usd", "num_turns", "duration_ms", "subtype")}
                  if result_event else None,
    }


def load_events(path):
    events = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    rejected = "--rejected" in sys.argv
    print(json.dumps(classify(load_events(args[0]), rejected=rejected),
                     indent=2, ensure_ascii=False))
