#!/usr/bin/env bash
# Dynamic per-node proof run for one top-level spec.
#
#   bash harness/run_dynamic.sh <name> [--dry-run|--resume] [extra prove_top_spec args]
#
#   <name>   short target name from the table below (e.g. double, scalar_invert)
#            or a full theorem name (curve25519_dalek....._spec)
#   RUN=<id> run id; default <name>_dynamic_01. Run dir: ledger/runs/$RUN
#
#   bash harness/run_dynamic.sh scalar_invert --dry-run   # print graph, no model calls
#   bash harness/run_dynamic.sh scalar_invert             # new run on a fresh exp/ branch
#   RUN=scalar_invert_dynamic_02 bash harness/run_dynamic.sh scalar_invert
#   bash harness/run_dynamic.sh scalar_invert --resume    # continue the checkpoint
#
# A real run never executes on main/master: a new run creates the branch
# exp/<name>-dynamic-<stamp> from the current clean HEAD and records it in
# $RUN_DIR.branch; --resume switches back to that recorded branch. Published
# proofs therefore land on the experiment branch, never on main.
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A TARGETS=(
  [double]=curve25519_dalek.edwards.EdwardsPoint.double_spec
  [scalar_invert]=curve25519_dalek.scalar.Scalar.invert_spec
  [is_small_order]=curve25519_dalek.edwards.EdwardsPoint.is_small_order_spec
  [montgomery_mul]=curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint.mul_spec
  [elligator_encode]=curve25519_dalek.montgomery.elligator_encode_spec
  [to_edwards]=curve25519_dalek.montgomery.MontgomeryPoint.to_edwards_spec
)

NAME="${1:-}"
[ -n "$NAME" ] || { echo "usage: $0 <name|theorem> [--dry-run|--resume] [extra args]" >&2
                    echo "names: ${!TARGETS[*]}" >&2; exit 2; }
shift
if [ -n "${TARGETS[$NAME]:-}" ]; then
  TARGET="${TARGETS[$NAME]}"
else
  TARGET="$NAME"; NAME="${TARGET##*.}"; NAME="${NAME%_spec}"
fi
RUN="${RUN:-${NAME}_dynamic_01}"
RUN_DIR="ledger/runs/$RUN"
BRANCH_FILE="$RUN_DIR.branch"

ARGS=(
  --bottom-up --dynamic
  --target "$TARGET"
  --model "${MODEL:-claude-opus-5-5}"
  --rounds 2 --max-turns 120 --timeout 1200
  --max-node-retries "${NODE_RETRIES:-1}" --max-refinements 2 --max-spec-revisions 2
  --max-node-attempts "${NODE_ATTEMPTS:-60}"
  --run-dir "$RUN_DIR"
)

require_clean() {
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "error: working tree has tracked changes; commit or restore first" >&2
    git status --short --untracked-files=no >&2
    exit 1
  fi
}

MODE="${1:-}"
case "$MODE" in
  --dry-run)
    shift
    exec python3 harness/prove_top_spec.py "${ARGS[@]}" --dry-run "$@" ;;
  --resume)
    shift
    [ -f "$RUN_DIR/graph.json" ] || { echo "error: $RUN_DIR/graph.json missing; nothing to resume" >&2; exit 1; }
    if [ -f "$BRANCH_FILE" ]; then
      BRANCH=$(cat "$BRANCH_FILE")
      if [ "$(git branch --show-current)" != "$BRANCH" ]; then
        require_clean
        git switch "$BRANCH"
      fi
    else  # run started before branches were recorded: move it onto one now
      require_clean
      BRANCH="exp/${NAME}-dynamic-$(date -u +%Y%m%dT%H%M%SZ)"
      git switch -c "$BRANCH"
      echo "$BRANCH" > "$BRANCH_FILE"
    fi
    ARGS+=(--resume-dynamic) ;;
  *)
    [ -f "$BRANCH_FILE" ] && { echo "error: $BRANCH_FILE exists; use --resume or RUN=<other id>" >&2; exit 1; }
    require_clean
    BRANCH="exp/${NAME}-dynamic-$(date -u +%Y%m%dT%H%M%SZ)"
    git switch -c "$BRANCH"
    mkdir -p "$(dirname "$BRANCH_FILE")"
    echo "$BRANCH" > "$BRANCH_FILE" ;;
esac

echo "target: $TARGET"
echo "run:    $RUN_DIR"
echo "branch: $(git branch --show-current)"
exec python3 harness/prove_top_spec.py "${ARGS[@]}" "$@" 2>&1 | tee -a "$RUN_DIR.log"
