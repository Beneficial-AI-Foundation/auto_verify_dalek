#!/usr/bin/env bash
# Experiment runner. `bash harness/exp.sh` with no arguments runs the experiment
# configured below, start to finish:
#   exp branch  ->  $SCRIPT --commit  ->  stop on the exp branch for inspection
# Then by hand: `exp.sh finish "msg"` squashes it into ONE commit on main and keeps
# the raw per-fill history at tag exp-raw/<name>; `exp.sh abort` drops it.
# main history is never rewritten.
#
# ======================= EDIT HERE: the experiment to run =======================
# SCRIPT: harness/driver.py         many targets in this checkout (--zones/--path/--limit)
#         harness/prove_top_spec.py ONE top spec of the bundle dalek-top-spec-only (--target)
SCRIPT=harness/prove_top_spec.py
EXP_NAME=""                       # empty = top-spec-<YYYYmmdd-HHMM>
EXP_MSG="top-spec round: ProjectivePoint identity_spec, bottom-up joint (from_limbs, ONE, ZERO), claude-sonnet-5"
DRIVER_ARGS=(
  --target curve25519_dalek.IdentityCurveModelsProjectivePoint.identity_spec
  --bottom-up                     # joint: all missing internal spec files + top file, one session, one gate
  # --stepwise                    # A/B control: one session per internal callee, published step by step
  --model claude-sonnet-5
  --rounds 3
  --max-turns 30
  # --dry-run                     # no fee; print the plan and every step's prompt
)
# Previous driver.py configuration, kept for reference:
#   SCRIPT=harness/driver.py
#   EXP_MSG="top-spec round: Scalar, claude-sonnet-5, limit 3"
#   DRIVER_ARGS=(--zones specs,aux --path Curve25519Dalek/Specs/Scalar/Scalar --jobs 2 --model claude-sonnet-5 --limit 3)
# DEC-20: the checkout is already comment-free (harness/strip_comments.py strip
# --in-place; last commented tree: commit 66753cb), so no --strip-comments here.
# ================================================================================
#
# Manual subcommands (same flow, step by step):
#   harness/exp.sh start [name]        create exp/<name> from main and switch to it
#   harness/exp.sh finish "message"    squash exp branch into ONE commit on main,
#                                      keep raw history as tag exp-raw/<name>, delete branch
#   harness/exp.sh abort               drop the exp branch, return to main untouched
#   harness/exp.sh status              show current exp branch and commits ahead of main
#   harness/exp.sh run [-n name] [-m msg] [-s script] -- <script args>
#                                      same as no-arg run but with explicit args
#                                      (-s defaults to $SCRIPT above).
#                                      script failure leaves you on the exp branch (finish/abort by hand)
set -euo pipefail

MAIN=main
cd "$(git rev-parse --show-toplevel)"

cur() { git rev-parse --abbrev-ref HEAD; }
on_exp() { [[ "$(cur)" == exp/* ]]; }
require_clean() {
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "working tree not clean; commit or stash first:" >&2
    git status --short >&2
    exit 1
  fi
}

if [[ $# -eq 0 ]]; then
  set -- run ${EXP_NAME:+-n "$EXP_NAME"} -m "$EXP_MSG" -s "$SCRIPT" -- "${DRIVER_ARGS[@]}"
fi

case "${1:-}" in
  start)
    name="${2:-top-spec-$(date +%Y%m%d-%H%M)}"
    [[ "$(cur)" == "$MAIN" ]] || { echo "switch to $MAIN first (now on $(cur))" >&2; exit 1; }
    require_clean
    git switch -c "exp/$name"
    echo "on exp/$name — run driver.py (with --commit if you want per-fill commits)"
    ;;
  finish)
    msg="${2:-}"
    [[ -n "$msg" ]] || { echo "usage: exp.sh finish \"commit message\"" >&2; exit 1; }
    on_exp || { echo "not on an exp/ branch (now on $(cur))" >&2; exit 1; }
    require_clean
    br="$(cur)"; name="${br#exp/}"
    n="$(git rev-list --count "$MAIN..$br")"
    if [[ "$n" == 0 ]]; then
      echo "no commits on $br beyond $MAIN; nothing to squash" >&2; exit 1
    fi
    git tag -f "exp-raw/$name" "$br"
    git switch "$MAIN"
    git merge --squash "$br"
    git commit -q -m "$msg" -m "Squashed $n commit(s) from $br; raw history: tag exp-raw/$name"
    git branch -D "$br"
    echo "main: $(git log --oneline -1); raw history kept at tag exp-raw/$name"
    ;;
  abort)
    on_exp || { echo "not on an exp/ branch (now on $(cur))" >&2; exit 1; }
    require_clean   # uncommitted edits: commit them on the exp branch or stash, then abort
    br="$(cur)"
    read -r -p "discard $br and its $(git rev-list --count "$MAIN..$br") commit(s)? [y/N] " a
    [[ "$a" == y ]] || exit 1
    git switch "$MAIN"
    git branch -D "$br"
    ;;
  run)
    shift
    name=""; msg=""; script="$SCRIPT"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -n) name="$2"; shift 2 ;;
        -m) msg="$2"; shift 2 ;;
        -s) script="$2"; shift 2 ;;
        --) shift; break ;;
        *) echo "unknown option $1 (script args go after --)" >&2; exit 1 ;;
      esac
    done
    [[ $# -gt 0 ]] || { echo "usage: exp.sh run [-n name] [-m msg] [-s script] -- <script args>" >&2; exit 1; }
    [[ -f "$script" ]] || { echo "script not found: $script" >&2; exit 1; }
    name="${name:-top-spec-$(date +%Y%m%d-%H%M)}"
    "$0" start "$name"
    set +e
    python3 "$script" --commit "$@"
    rc=$?
    set -e
    n="$(git rev-list --count "$MAIN..HEAD")"
    if [[ $rc -ne 0 ]]; then
      echo "$script exited $rc; still on exp/$name with $n commit(s)." >&2
      echo "inspect, then: harness/exp.sh finish \"...\"   or   harness/exp.sh abort" >&2
      exit $rc
    fi
    if [[ "$n" == 0 ]]; then
      echo "$script accepted nothing; dropping exp/$name"
      git switch -q "$MAIN"; git branch -q -D "exp/$name"; exit 0
    fi
    echo "$script accepted $n fill(s); staying on exp/$name for inspection."
    echo "  git log --stat $MAIN..HEAD          # what was accepted, step by step"
    echo "  harness/exp.sh finish \"$msg\""
    echo "  harness/exp.sh abort                # drop the branch"
    ;;
  status)
    if on_exp; then
      echo "on $(cur), $(git rev-list --count "$MAIN..HEAD") commit(s) ahead of $MAIN"
      git log --oneline "$MAIN..HEAD"
    else
      echo "on $(cur) (no exp branch active)"
      git tag -l 'exp-raw/*'
    fi
    ;;
  -h|--help|help)
    sed -n '2,5p;20,30p' "$0" ;;
  *)
    echo "unknown subcommand: $1" >&2; sed -n '20,30p' "$0" >&2; exit 1 ;;
esac
