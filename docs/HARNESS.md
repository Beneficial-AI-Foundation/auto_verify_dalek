# Harness — status brief (2026-08-28)

Detail: [HARNESS-DETAIL.md](HARNESS-DETAIL.md) · decisions: [DECISIONS.md](DECISIONS.md)

## What it does

An agent fills one `sorry` at a time. The harness guarantees the accepted proof
is real: **no access to answers · statement unchanged · no new axioms ·
rebuildable from scratch by someone else.**

## One target

```
sealed slot copy ──▶ claude -p in bwrap sandbox ──▶ gate ──▶ accept / rollback ──▶ ledger
   (per job)          (≤5 rounds, --resume)       a–e          + merge-back
```

*merge-back* = on accept, copy the target file from the slot to the operator
tree under one lock (plain copy — never a git merge, see DEC-19).
*rollback* = on reject, restore the slot to its last accepted state
(`git show HEAD:` in the slot), so a later target in the same file starts
from the last accept, not from the baseline.

Gate: **a** only target file changed · **b** no `axiom` / `@[implemented_by]` /
`@[extern]` · **c** `lake build` ok ≤ 20 min, run under `nice -n 19` (driver gate and
replay; batch priority, wall-clock budget unchanged) ·

TODO: is 20 min too little for the big modules?


**c′** every statement in the
module unchanged (G1 fingerprint) · **d** sorry count down by one, nowhere
else · **e** axiom closure inside frozen whitelist (G2).

Whole run: `replay.py` (fresh worktree, empty build cache) → `report.py` →
`COMPLETE` or `INCOMPLETE: k of n`.

## What the agent sees

- its slot only: no `.git`, no `harness/`, no `ledger/`; empty `$HOME`; mathlib read-only
- `Aux.lean` is a definitions-only stub (DEC-21): no unproved helper statements to lean on
- the bundle on `main` holds no agent output (DEC-22); a run publishes onto its own `exp/` branch
- tools `Read Grep Glob Edit Write Bash(lake build, grep, cat, sed)` — no subagents, web, skills, MCP.
  `Edit(./**)` is also allowed so that `cat > F <<EOF` / `cat >> F` / `sed -i F` are
  auto-approved (Claude Code checks shell writes against *file* rules); every prompt
  tells the Worker exactly these forms. Scope gate (a) still rejects edits outside the target file
- 12-probe self-test before every run, receipt in each ledger record

## Decisions

| | Question | Decision | State |
|---|---|---|---|
| ✅ | What counts as done? | DEC-10 all of T proved + statements unchanged + no new axioms + fresh replay | implemented |
TODO: check fresh replay

| ✅ | Which Lean tricks allowed? | DEC-11 `native_decide` ok; `implemented_by`/`extern` banned; axiom whitelist | implemented |

TODO: check axiom whitelist, a subfolder has the axiom. Minimal math definitions from `Math/` and FunExternal.lean.  can derive top-level specs
minimal in the sense that: we can write down all the top level specs without having compilation errors like 'undefined EdCurve ...'

| ✅ | Which targets first? | DEC-14 full-project `S = T`; Scalar slice for shakeout | accepted |
top-level funcs VS. public APIs
We need to distinguish and chose what to use as S=T:
top-level functions: all the fucntions with no dependents
public API: wht rust labels as pub fn

maybe we need the intersection in the furture:
top-level public API functions

| ✅ | When to give up? | DEC-16 rounds, turns, wall clock, cost, stall/bloat reset, build budget | implemented |
| ✅ | Can a run be repeated? | DEC-17 git, toolchain, machine, harness hashes, billed models in every record | implemented |
| ✅ | Agents interfere in parallel? | one sealed slot + sandbox per job, `--jobs N` | implemented |
| ✅ | How to merge conflicting edits? | DEC-19 never merge code: file groups never span slots (owner-map tripwire), merge-back is a plain copy refused on hash mismatch (`rejected_merge_conflict`, job rolled back); no hand-merging mid-run (breaks DEC-12 seal); post-run git conflicts resolved by a human, `replay.py` is the arbiter | implemented |

TODO: sometimes the original function spec is wrong — needs an honest
escalation path (cf. CryptoProver FALSE_CONTRACT: agent supplies a
counterexample witness, harness re-verifies it against the frozen statement)

| ✅ | Can a human tamper mid-run? | DEC-12 tree hashed at run start; input-set change = violation, other change = drift; re-checked per target | implemented |
| 🟡 | Can the agent peek at answers? | DEC-08 filesystem closed; network deny-listed not blocked; credential in sandbox; no broker | partial (= CryptoProver) |
| ✅ | Do comments leak the proof? | DEC-20. Preprocessing: every comment (`/-! -/`, `/-- -/`, `/- -/`, `--`: NL specs, proof sketches, `Source:` pointers) was blanked, line-preserving, in all 216 hand-written Lean files of the checkout (`harness/strip_comments.py strip --in-place`; Aeneas-generated Funs/Types and Rust untouched). Sorry counts unchanged, frozen hashes regenerated, G2 passes. Last commented tree: commit `66753cb`; `strip_comments.py merge` restores comments onto a proved file. `driver.py --strip-comments` still exists for trees that carry comments. cf. CryptoProver `strip_specs.py --strip-docs` (drops `///` only) | done (2026-09-02) |

TODO: remove the annotations

| 🟡 | What may we claim? | DEC-09 "filesystem blocked and receipted; egress restricted; training data unknown" | supportable today |

TODO: use OpenTelemetry to check a posteriori if the agent accessed the internet in some way

| ✅ | How many runs, which models? | DEC-13 solved for now: n = 1 runs, one pinned model (saves tokens, like CryptoProver); **no comparative claim from n = 1**; records already carry hashes/limits/`models_used`, so `--repeats K` + k/K aggregation can be added when comparisons are needed | accepted (repeats deferred) |
| ⬜ | Agent writes the spec itself? | DEC-05/06/07 seed `S`, `Math/` visibility, writer/reviewer roles | not started (Phase 2) |
| 🟡 | Where do transcripts live, who reads? | DEC-01/02/15 transcripts in `ledger/transcripts/`, never discarded, `ledger/` git-ignored; raw restricted, publish hashes + outcomes + redacted summaries; open: which BAIF bucket gets the sealed tars | partial |
| ✅ | Is `T` really all the public APIs? | DEC-04 fixed checked-in list, pinned by tree hash; API face from `harness/api_top.py` (pub visibility × extraction × specs), CryptoProver cross-check + manual audit (`debug_top_api.md`) — "all public APIs" wording allowed; re-derivation hardening deferred (`top_func.md`) | accepted for now |
| ⬜ | Misc | DEC-18 claim boundary in report · run-invalidation rules | open |

## Next

1. Shakeout: real multi-round run on the Scalar slice (`--jobs 2`).
2. `--repeats` + aggregation (DEC-13, deferred to save tokens) — until then n = 1, no number is comparable.
3. Close network: `--unshare-net`, API via proxy, credential out of sandbox (DEC-08).
4. Decide what a broken seal / deadline / host restart does to a run (invalidation rules).
5. Then Phase 2.

## Dynamic per-node proof workflow

`prove_top_spec.py --bottom-up --dynamic` runs a fresh Worker session for each
internal specification, followed by the top-level proof. The initial dependency
graph comes from the existing callee plan. Execution is serial; independent
ready nodes can proceed even when another branch is blocked.

```bash
python harness/prove_top_spec.py --bottom-up --dynamic \
  --target curve25519_dalek.edwards.EdwardsPoint.double_spec \
  --model claude-sonnet-5 --rounds 3 --max-turns 60 --timeout 900 \
  --run-dir ledger/runs/double_dynamic
```

Use `--dry-run` to inspect the initial graph without invoking a model.

A Worker repairs ordinary Lean errors within its task. For a structural problem
it ends its final message with `END_REASON:LIMIT` and a JSON `blocker` object
(`kind`, `reason`, `evidence`) on the last line; the harness parses the last
JSON object in the message, so surrounding prose or code fences do not hide it.
`needs_split` invokes a fresh Refiner whose slot is mounted read-only (bwrap
`--ro-bind`, self-tested at start; the tool allowlist and a post-hoc
`changed_files` check remain as second lines of defense); `invalid_contract` blocks the
node without silently changing its statement; `needs_stronger_spec` names an
accepted internal specification that is too weak for the current proof. The Refiner proposes closed helper
statements, their dependencies, their purpose, and an exact insertion point.
The harness inserts only theorem placeholders, checks elaboration and statement
identity, adds the helper nodes, and schedules them before retrying the parent
in a new session. That session's prompt carries the run context for its target:
the helper lemmas with their stated purpose and status, and a bounded summary of
each earlier failed attempt (outcome, reported reason and evidence, first Lean
errors). Both are stored on the node in `graph.json`. Existing supplied statements are frozen. Synthesized internal
specifications still need to be strong enough for the top-level theorem; Lean
elaboration of a decomposition alone does not establish that sufficiency.

A helper that its Worker reports as `invalid_contract` (the Refiner proposed a
false statement) does not stall its parent: the harness removes that round's
unproved helper placeholders (proved siblings stay), verifies the build and
that no other statement changed, commits the removal, restores the parent's
dependencies, records the false statement on the parent, and asks a fresh
Refiner again with that statement marked as false. If the refinement budget
is exhausted the parent simply returns to `pending`.

An ordinary failure (gate rejection, agent limit, timeout) does not block a
node at once: it is retried in a fresh session up to `--max-node-retries`
times (default 1), each retry carrying the attempt history. A structural
blocker report skips the retries and goes straight to the Refiner, the spec
revision, or the block. A split or a spec revision resets the node's tries.

Each Worker uses the existing scope/build/statement gates plus a transitive
axiom check: its accepted theorem may depend on `sorryAx` only through the
frozen Math-layer assumptions (`harness/frozen/math_assumptions.json`, by name
and declared in a `Curve25519Dalek.Math.*` module; StmtCanon reports the
closure members that carry a sorry as `sorry_sources`). New or previously
verified declarations cannot acquire any other `sorryAx` dependency. A rejection
for this reason names the offending declarations in the Worker's feedback. Unproved helper
placeholders elsewhere in the graph are allowed. Failed decompositions are
rolled back; ordinary timeouts do not automatically trigger decomposition.

Accepted nodes are committed to the isolated workspace. `graph.json` records
node states, dependency edges, session IDs, gate evidence, source hashes and
refinement proposals; failed Worker edits are retained under `partials/`.
The bundle is published only after every node and the final joint gate pass.
This preserves local progress without exporting newly introduced placeholders.

To resume the same checkpoint, repeat the command with `--resume-dynamic`.
Recovery checks source hashes, a clean workspace, and the original plan, then
opens fresh sessions for unfinished tasks. It deliberately refuses to overwrite
a checkpoint with uncommitted edits after an abrupt crash; inspect and recover
that workspace first. A new run must use a different run directory.

Revision of an accepted spec (`needs_stronger_spec`): the harness checks that
the named function is an accepted internal spec upstream of the requesting
node, resets the slot to the commit before that spec was accepted, replays the
later commits except the acceptances of the spec and of every node that
transitively depends on it (a replay that conflicts or does not build falls
back to replaying split commits only; any failure restores the slot exactly),
and rebuilds the sorry counts. The spec and its dependents return to `pending`;
the spec's next Worker is told the previous statement, the requester, and the
missing equation or bound, and writes a stronger statement in a fresh session.
Dependents are then re-proved against it. `graph.json` keeps the ordered slot
commits and each revision request. Existing supplied statements stay frozen.

Bounds: `--max-refinements` (default 2 per node), `--max-helpers-per-split` (4),
`--max-proof-nodes` (64 total), `--max-node-attempts` (100 across resumes),
`--max-node-retries` (1 extra fresh attempt per node after an ordinary failure),
and `--max-spec-revisions` (2 per internal spec; 0 disables revision).
Worker rounds and Refiner invocations obey the configured turn/time limits.
`--max-cost-usd` remains a per-Worker limit, not a total workflow budget.
The dynamic mode does not support `--commit` or `--resume-proof-state`; it has
its own checkpoint recovery and publishes without creating a repository commit.
