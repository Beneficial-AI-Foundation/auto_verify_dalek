#!/usr/bin/env python3
"""Per-node token/model usage of a dynamic run, read from graph.json alone.

    python3 harness/usage_report.py ledger/runs/<run>/graph.json [--json]

New runs carry `history[*].usage` on every node. Older graphs (no history on
accepted nodes) are reconstructed from `events[*].rounds`, which hold the same
round records. Tokens are per model because subscription plans meter tokens per
model; `cost_usd` is the SDK's list-price figure, a yardstick only.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dynamic_proof as dag  # noqa: E402

COLS = ('output_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens', 'thinking_tokens')
LABEL = dict(zip(COLS, ('out', 'cache_w', 'cache_r', 'think')))


def attempts(graph):
    """(node id, attempt record) pairs; history first, events as fallback."""
    out = []
    for key, node in graph['nodes'].items():
        hist = [h for h in node.get('history', []) if 'usage' in h]
        if hist:
            out.extend((key, h) for h in hist)
            continue
        events = [e for e in graph['events'] if e.get('node') == key and 'rounds' in e]
        for i, e in enumerate(events, 1):
            out.append((key, dict(attempt=f'{key}#{i}', outcome=e['outcome'], rounds=len(e['rounds']),
                                  sessions=e.get('sessions', []), usage=dag.usage_summary(e['rounds']))))
    return out


def fmt(n):
    return f'{n / 1000:.1f}k' if n >= 1000 else str(n)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('graph', type=Path)
    ap.add_argument('--json', action='store_true', help='machine-readable output')
    args = ap.parse_args()
    graph = json.loads(args.graph.read_text())
    rows = attempts(graph)
    if args.json:
        json.dump([dict(node=k, **h) for k, h in rows], sys.stdout, indent=1)
        print()
        return
    print(f"{'node':5} {'fn':38} {'att':>4} {'outcome':24} {'turns':>5} {'out':>7} {'cache_w':>8} {'cache_r':>8} {'think':>7} {'$':>6} models")
    per_model = defaultdict(lambda: {k: 0 for k in dag.TOKEN_KEYS})
    for key, h in rows:
        u = h['usage']
        t = u['tokens']
        for m, v in u['models'].items():
            for k in dag.TOKEN_KEYS:
                per_model[m][k] += v[k]
        fn = graph['nodes'][key]['fn'].removeprefix('probe:').removeprefix('curve25519_dalek.')
        print(f"{key:5} {fn[-38:]:38} {str(h['attempt']):>4} {h['outcome'][:24]:24} {u['assistant_turns']:5} "
              f"{fmt(t['output_tokens']):>7} {fmt(t['cache_creation_input_tokens']):>8} "
              f"{fmt(t['cache_read_input_tokens']):>8} {fmt(t['thinking_tokens']):>7} {u['cost_usd']:6.2f} "
              + ','.join(u['models']))
    print()
    print('per model:')
    for m, v in sorted(per_model.items()):
        print(f"  {m:28} " + '  '.join(f"{LABEL[c]}={fmt(v[c])}" for c in COLS))
    run = graph.get('usage') or dag.usage_summary(
        [r for e in graph['events'] for r in (e.get('rounds') or [])])
    print(f"run: attempts={len(rows)} turns={run['assistant_turns']} "
          f"output={fmt(run['tokens']['output_tokens'])} cost_usd={run['cost_usd']}")


if __name__ == '__main__':
    main()
