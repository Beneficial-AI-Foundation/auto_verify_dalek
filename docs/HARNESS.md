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

| | Decision | State |
|---|---|---|
| ✅ | DEC-10 success = all of T proved + statements unchanged + no new axioms + fresh replay | implemented |
| ✅ | DEC-11 `native_decide` allowed, `implemented_by`/`extern` banned, axiom whitelist | implemented |
| ✅ | DEC-14 full-project `S = T` first; Scalar slice for shakeout | accepted |
| ✅ | DEC-16 stop rules: rounds, turns, wall clock, cost, stall/bloat reset, build budget | implemented |
| ✅ | DEC-17 provenance: git, toolchain, machine, harness hashes, billed models | implemented |
| ✅ | parallel agents: one sealed slot + sandbox per job, `--jobs N` | implemented |
| 🟡 | DEC-08 sandbox — **filesystem closed**; network deny-listed not blocked, credential in sandbox, no broker | partial (= CryptoProver level) |
| 🟡 | DEC-09 claim label: "filesystem access blocked and receipted; egress restricted; training data unknown" | supportable today |
| 🟡 | DEC-12 no humans mid-run — checkout untouched, but no sealed-bundle moment | partial |
| ⬜ | DEC-13 model matrix / repeats — no `--repeats`, no success-rate aggregation | open |
| ⬜ | DEC-05/06/07 seed `S`, `Math/` visibility, writer/reviewer roles (Phase 2) | not started |
| ⬜ | DEC-01/02/15 storage & access to raw transcripts | open |
| ⬜ | DEC-04 `T` selection in driver, DEC-18 claim boundary in report, run-invalidation rules | open |

## Next

1. Shakeout: real multi-round run on the Scalar slice (`--jobs 2`).
2. `--repeats` + aggregation (DEC-13) — without it no number is comparable.
3. Close network: `--unshare-net`, API via proxy, credential out of sandbox (DEC-08).
4. Seal moment: hash whole tree at run start (DEC-12).
5. Then Phase 2.
