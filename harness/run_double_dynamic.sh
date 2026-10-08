#!/usr/bin/env bash
# Dynamic per-node proof run for EdwardsPoint.double_spec.
#
#   bash harness/run_double_dynamic.sh            # new run (fails if RUN_DIR has a graph.json)
#   bash harness/run_double_dynamic.sh --dry-run  # print the initial graph, no model calls
#   bash harness/run_double_dynamic.sh --resume   # continue the checkpoint in RUN_DIR
#
# A real run never executes on main/master: a new run creates the branch
# exp/double-dynamic-<stamp> from the current clean HEAD and records it in
# $RUN_DIR.branch; --resume switches back to that recorded branch. Published
# proofs therefore land on the experiment branch, never on main.
#
# Edit RUN_DIR for a new run; a run directory is never reused.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_DIR=ledger/runs/double_dynamic_01
TARGET=curve25519_dalek.edwards.EdwardsPoint.double_spec
BRANCH_FILE="$RUN_DIR.branch"

ARGS=(
  --bottom-up --dynamic
  --target "$TARGET"
  --model claude-opus-5-5
  --rounds 2 --max-turns 120 --timeout 1200
  --max-node-retries 1 --max-refinements 2 --max-spec-revisions 2
  --max-node-attempts 40
  --run-dir "$RUN_DIR"
)

require_clean() {
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "error: working tree has tracked changes; commit or restore first" >&2
    git status --short --untracked-files=no >&2
    exit 1
  fi
}

case "${1:-}" in
  --dry-run)
    exec python3 harness/prove_top_spec.py "${ARGS[@]}" --dry-run ;;
  --resume)
    [ -f "$RUN_DIR/graph.json" ] || { echo "error: $RUN_DIR/graph.json missing; nothing to resume" >&2; exit 1; }
    if [ -f "$BRANCH_FILE" ]; then
      BRANCH=$(cat "$BRANCH_FILE")
      if [ "$(git branch --show-current)" != "$BRANCH" ]; then
        require_clean
        git switch "$BRANCH"
      fi
    else  # run started before branches were recorded: move it onto one now
      require_clean
      BRANCH="exp/double-dynamic-$(date -u +%Y%m%dT%H%M%SZ)"
      git switch -c "$BRANCH"
      echo "$BRANCH" > "$BRANCH_FILE"
    fi
    ARGS+=(--resume-dynamic) ;;
  "")
    [ -f "$BRANCH_FILE" ] && { echo "error: $BRANCH_FILE exists; use --resume or change RUN_DIR" >&2; exit 1; }
    require_clean
    BRANCH="exp/double-dynamic-$(date -u +%Y%m%dT%H%M%SZ)"
    git switch -c "$BRANCH"
    mkdir -p "$(dirname "$BRANCH_FILE")"
    echo "$BRANCH" > "$BRANCH_FILE" ;;
  *) echo "usage: $0 [--dry-run|--resume]" >&2; exit 2 ;;
esac

echo "branch: $(git branch --show-current)"
exec python3 harness/prove_top_spec.py "${ARGS[@]}" 2>&1 | tee -a "$RUN_DIR.log"
