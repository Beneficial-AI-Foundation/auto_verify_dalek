#!/usr/bin/env python3
"""Whole-T completion report (DEC-10).

The driver's ledger has one record per attempt; success of the EXPERIMENT is
a statement about the whole declared target set T, not about single records.
This script joins three sources and prints one verdict:

  inventory   .verilib/sorry_inventory.json — the declared T (by --zones)
  ledger      ledger/rounds.jsonl — latest attempt per target
              (optionally restricted to --run-id)
  tree        the current working tree: does the target's file still carry
              its sorry? (same resolution rule as the driver)
  replay      optional harness/replay.py report (--replay FILE): a fresh
              rebuild + G2 + G1 on a clean checkout

Verdict COMPLETE requires all of:
  * every target in T filled (no sorry left at its location)
  * a replay report given, verdict PASS, and its sorry count in the selected
    zones is zero
Otherwise INCOMPLETE, with the gap listed. The numbers are what DEC-10 asks
for ("whole declared task complete, unchanged statements, no new trusted
assumptions, fresh replay"); spec-quality checks for agent-authored
statements (phase 2) are out of scope here.

Usage:
  python3 harness/report.py                       # all zones specs,aux; all ledger
  python3 harness/report.py --run-id 2026-08-26T…  --zones specs
  python3 harness/report.py --replay ledger/replay/2026-…json --json out.json
"""
import argparse
import json
import os
import sys
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from driver import resolve_target, INVENTORY, LEDGER_DIR  # noqa: E402


def load_ledger(run_id):
    path = os.path.join(LEDGER_DIR, "rounds.jsonl")
    if not os.path.exists(path):
        return {}
    latest = {}
    for ln in open(path):
        ln = ln.strip()
        if not ln:
            continue
        r = json.loads(ln)
        if run_id and r.get("run_id") != run_id:
            continue
        latest[r["target"]] = r  # file order == time order
    return latest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zones", default="specs,aux")
    ap.add_argument("--run-id", default="", help="restrict ledger to one run")
    ap.add_argument("--replay", default="", help="replay.py report JSON")
    ap.add_argument("--json", default="", help="write machine-readable report")
    ap.add_argument("--show", type=int, default=20,
                    help="max unresolved targets to list (0 = all)")
    args = ap.parse_args()

    inv = json.load(open(INVENTORY))
    zones = [z.strip() for z in args.zones.split(",")]
    ledger = load_ledger(args.run_id)

    per_zone = {}
    unresolved = []
    totals = Counter()
    cost = tokens = wall = 0.0
    for z in zones:
        st = Counter()
        outcomes = Counter()
        for loc in inv["locations"][z]:
            filled = resolve_target(loc) is None
            rec = ledger.get(loc)
            st["total"] += 1
            if filled:
                st["filled"] += 1
                st["filled_by_ledger" if rec and rec["outcome"] == "accepted"
                   else "filled_outside_ledger"] += 1
            else:
                st["open"] += 1
                if rec is None:
                    st["never_attempted"] += 1
                    unresolved.append((z, loc, "never_attempted"))
                else:
                    outcomes[rec["outcome"]] += 1
                    unresolved.append((z, loc, rec["outcome"]))
            if rec:
                cost += float(rec.get("cost_usd") or sum(
                    float(x.get("cost_usd") or 0) for x in rec.get("rounds", [])))
                tokens += rec.get("output_tokens_total") or 0
                wall += rec.get("wall_seconds") or 0
        per_zone[z] = {k: st.get(k, 0) for k in
                       ("total", "filled", "filled_by_ledger",
                        "filled_outside_ledger", "open", "never_attempted")}
        per_zone[z]["latest_outcomes_of_open"] = dict(outcomes)
        totals.update({k: v for k, v in st.items()})

    replay = None
    replay_ok = False
    if args.replay:
        replay = json.load(open(args.replay))
        zone_sorry = sum(replay.get("sorry", {}).get("by_zone", {}).get(z, 0)
                         for z in zones)
        replay_ok = replay.get("verdict") == "PASS" and zone_sorry == 0
        replay_summary = {"file": args.replay, "verdict": replay.get("verdict"),
                          "ref_sha": replay.get("ref_sha"),
                          "sorry_in_zones": zone_sorry,
                          "failures": replay.get("failures")}
    else:
        replay_summary = None

    gaps = []
    if totals["open"]:
        gaps.append(f"{totals['open']} of {totals['total']} targets still open")
    if replay is None:
        gaps.append("no fresh replay supplied (--replay)")
    elif not replay_ok and replay_summary:
        gaps.append(f"replay {replay_summary['verdict']}, "
                    f"sorry_in_zones={replay_summary['sorry_in_zones']}, "
                    f"failures={replay_summary['failures']}")
    verdict = "COMPLETE" if not gaps else "INCOMPLETE"

    print(f"T = zones {zones}: {totals['total']} targets; "
          f"ledger records: {len(ledger)}"
          + (f" (run_id={args.run_id})" if args.run_id else ""))
    for z, s in per_zone.items():
        print(f"  {z:>6}: {s['filled']}/{s['total']} filled "
              f"(ledger {s.get('filled_by_ledger', 0)}, outside ledger "
              f"{s.get('filled_outside_ledger', 0)}), open {s['open']} "
              f"(never attempted {s.get('never_attempted', 0)}, "
              f"latest outcomes {s['latest_outcomes_of_open']})")
    print(f"  spend over matched records: ${cost:.2f}, "
          f"{int(tokens)} output tokens, {wall / 3600:.1f} h agent wall")
    if replay_summary:
        print(f"  replay: {replay_summary['verdict']} @ {replay_summary['ref_sha'][:10]}"
              f" sorry_in_zones={replay_summary['sorry_in_zones']}")
    if unresolved:
        show = unresolved if not args.show else unresolved[:args.show]
        print(f"  unresolved ({len(unresolved)}, showing {len(show)}):")
        for z, loc, why in show:
            print(f"    [{z}] {loc}  {why}")
    print(f"\nVERDICT: {verdict}" + (f" — {'; '.join(gaps)}" if gaps else ""))

    if args.json:
        json.dump({"zones": zones, "run_id": args.run_id or None,
                   "per_zone": per_zone, "totals": dict(totals),
                   "spend": {"cost_usd": round(cost, 4), "output_tokens": int(tokens),
                             "wall_seconds": round(wall, 1)},
                   "replay": replay_summary, "unresolved": unresolved,
                   "gaps": gaps, "verdict": verdict},
                  open(args.json, "w"), indent=1, ensure_ascii=False)
    sys.exit(0 if verdict == "COMPLETE" else 1)


if __name__ == "__main__":
    main()
