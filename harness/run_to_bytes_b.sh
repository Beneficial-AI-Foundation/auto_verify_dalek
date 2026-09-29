#!/usr/bin/env bash
# Run B baseline, or add --fv-skills for the pinned FVS headless adapter.
set -euo pipefail
FV_ARGS=()
case "${1:-}" in
  "") ;;
  --fv-skills) FV_ARGS=(--fv-skills); shift ;;
  *) echo "Usage: bash harness/run_to_bytes_b.sh [--fv-skills]" >&2; exit 2 ;;
esac
if (( $# )); then
  echo "Usage: bash harness/run_to_bytes_b.sh [--fv-skills]" >&2
  exit 2
fi

# Change these settings here when starting a new experiment series.
MODEL=claude-sonnet-5
TIMEOUT_SECONDS=3600
MAX_TURNS=300

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Reserve a unique parent; the Python runner needs a nonexistent child.
mkdir -p ledger/runs
EXPERIMENT_ROOT="$(mktemp -d "$REPO_ROOT/ledger/runs/to_bytes_b_$(date -u +%Y%m%dT%H%M%SZ)_XXXXXX")"
RUN_DIR="$EXPERIMENT_ROOT/attempt"
printf 'Model: %s\nResults: %s\n' "$MODEL" "$RUN_DIR"

python3 -u harness/prove_to_bytes_b.py \
  --run \
  --model "$MODEL" \
  --timeout "$TIMEOUT_SECONDS" \
  --max-turns "$MAX_TURNS" \
  --run-dir "$RUN_DIR" \
  "${FV_ARGS[@]}" \
  2>&1 | tee "$EXPERIMENT_ROOT/run.log"
