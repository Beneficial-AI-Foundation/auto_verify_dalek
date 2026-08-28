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

Gate: **a** only target file changed · **b** no `axiom` / `@[implemented_by]` /
`@[extern]` · **c** `lake build` ok ≤ 20 min · **c′** every statement in the
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
| ✅ | Which Lean tricks allowed? | DEC-11 `native_decide` ok; `implemented_by`/`extern` banned; axiom whitelist | implemented |
| ✅ | Which targets first? | DEC-14 full-project `S = T`; Scalar slice for shakeout | accepted |
| ✅ | When to give up? | DEC-16 rounds, turns, wall clock, cost, stall/bloat reset, build budget | implemented |
| ✅ | Can a run be repeated? | DEC-17 git, toolchain, machine, harness hashes, billed models in every record | implemented |
| ✅ | Agents interfere in parallel? | one sealed slot + sandbox per job, `--jobs N` | implemented |
| 🟡 | Can the agent peek at answers? | DEC-08 filesystem closed; network deny-listed not blocked; credential in sandbox; no broker | partial (= CryptoProver) |
| 🟡 | What may we claim? | DEC-09 "filesystem blocked and receipted; egress restricted; training data unknown" | supportable today |
| 🟡 | Can a human tamper mid-run? | DEC-12 checkout untouched, but no tree hash at run start | partial |
| ⬜ | How many runs, which models? | DEC-13 no `--repeats`, no success-rate aggregation | open |
| ⬜ | Agent writes the spec itself? | DEC-05/06/07 seed `S`, `Math/` visibility, writer/reviewer roles | not started (Phase 2) |
| ⬜ | Where do transcripts live, who reads? | DEC-01/02/15 | open |
| ⬜ | Misc | DEC-04 `T` selection in driver · DEC-18 claim boundary in report · run-invalidation rules | open |

## Next

1. Shakeout: real multi-round run on the Scalar slice (`--jobs 2`).
2. `--repeats` + aggregation (DEC-13) — without it no number is comparable.
3. Close network: `--unshare-net`, API via proxy, credential out of sandbox (DEC-08).
4. Seal moment: hash whole tree at run start (DEC-12).
5. Then Phase 2.
