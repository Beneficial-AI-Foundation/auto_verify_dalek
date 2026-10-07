#!/usr/bin/env bash
# Dynamic per-node proof run for EdwardsPoint.double_spec.
#
#   bash harness/run_double_dynamic.sh            # new run (fails if RUN_DIR has a graph.json)
#   bash harness/run_double_dynamic.sh --dry-run  # print the initial graph, no model calls
#   bash harness/run_double_dynamic.sh --resume   # continue the checkpoint in RUN_DIR
#
# Edit RUN_DIR for a new run; a run directory is never reused.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_DIR=ledger/runs/double_dynamic_01
TARGET=curve25519_dalek.edwards.EdwardsPoint.double_spec

ARGS=(
  --bottom-up --dynamic
  --target "$TARGET"
  --model claude-opus-5-5
  --rounds 2 --max-turns 120 --timeout 1200
  --max-node-retries 1 --max-refinements 2 --max-spec-revisions 2
  --max-node-attempts 40
  --run-dir "$RUN_DIR"
)

case "${1:-}" in
  --dry-run) exec python3 harness/prove_top_spec.py "${ARGS[@]}" --dry-run ;;
  --resume)  ARGS+=(--resume-dynamic) ;;
  "") ;;
  *) echo "usage: $0 [--dry-run|--resume]" >&2; exit 2 ;;
esac

mkdir -p "$(dirname "$RUN_DIR")"
exec python3 harness/prove_top_spec.py "${ARGS[@]}" 2>&1 | tee -a "$RUN_DIR.log"
