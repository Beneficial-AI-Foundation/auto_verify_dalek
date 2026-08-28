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

TODO: *merge-back* *rollback* what does it do?

Gate: **a** only target file changed · **b** no `axiom` / `@[implemented_by]` /
`@[extern]` · **c** `lake build` ok ≤ 20 min · 

TODO: `nice -n 19` and too little


**c′** every statement in the
module unchanged (G1 fingerprint) · **d** sorry count down by one, nowhere
else · **e** axiom closure inside frozen whitelist (G2).

Whole run: `replay.py` (fresh worktree, empty build cache) → `report.py` →
`COMPLETE` or `INCOMPLETE: k of n`.

## What the agent sees

- its slot only: no `.git`, no `harness/`, no `ledger/`; empty `$HOME`; mathlib read-only
- tools `Read Grep Glob Edit Write Bash(lake build, grep)` — no subagents, web, skills, MCP
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

TODO: how to solve merge conflict? Sometimes original functions spec is wrong
does all the public functions are chosen

| ✅ | Can a human tamper mid-run? | DEC-12 tree hashed at run start; input-set change = violation, other change = drift; re-checked per target | implemented |
| 🟡 | Can the agent peek at answers? | DEC-08 filesystem closed; network deny-listed not blocked; credential in sandbox; no broker | partial (= CryptoProver) |

TODO: remove the annotations

| 🟡 | What may we claim? | DEC-09 "filesystem blocked and receipted; egress restricted; training data unknown" | supportable today |

TODO: use OpenTelemetry to check a posteriori if the agent accessed the internet in some way

| ⬜ | How many runs, which models? | DEC-13 no `--repeats`, no success-rate aggregation | open |
| ⬜ | Agent writes the spec itself? | DEC-05/06/07 seed `S`, `Math/` visibility, writer/reviewer roles | not started (Phase 2) |
| ⬜ | Where do transcripts live, who reads? | DEC-01/02/15 | open |
| ⬜ | Misc | DEC-04 `T` selection in driver · DEC-18 claim boundary in report · run-invalidation rules | open |

## Next

1. Shakeout: real multi-round run on the Scalar slice (`--jobs 2`).
2. `--repeats` + aggregation (DEC-13) — without it no number is comparable.
3. Close network: `--unshare-net`, API via proxy, credential out of sandbox (DEC-08).
4. Decide what a broken seal / deadline / host restart does to a run (invalidation rules).
5. Then Phase 2.
