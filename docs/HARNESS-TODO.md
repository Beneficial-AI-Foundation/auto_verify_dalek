# Harness TODO (from run `double_dynamic_01`, 2026-10-09)

Source: `ledger/runs/double_dynamic_01/graph.json`, `ledger/transcripts/dag_double_dynamic_01_*.jsonl`
(21 sessions, $14.99, 16/17 nodes accepted; top node blocked by two harness bugs, both fixed).
Run was measured against a contaminated bundle (DEC-22); n15 used the pre-published `Sub.lean`.
Ordered by expected saving.

## Urgent

1. **Generic helper lemmas are re-proved per file.** (Addressed, verify next run.)
   In `double_dynamic_01` the big loss ($7.0 of $14.99) had two causes. (a) `reduce`/`sub`
   were hand-proved in the bundle with an Aux sorry closure, so n3/n15 were rejected and
   re-proved copies (`double_reduce_spec`, `double_sub_spec`). Gone: on the pristine bundle
   `--dry-run` now yields 20 nodes with `reduce` (n9) and `sub` (n10) as real nodes, and
   `ProjectivePoint.double` (n18) imports `Sub.lean` through a dependency edge.
   (b) Former Aux lemmas (`cast_U64_val`, `cast_U128_val`, `mask51_spec`,
   `shiftRight51_spec`, `Field51_as_Nat_eq`, `prod_le`) belong to no Rust function, so they are
   never nodes. `Mul.lean` and `Pow2K.lean` each proved all five under different names;
   Pow2K (n11) ran after Mul (n3) and did not import it. Next run expects 3–4 copies
   (mul, reduce, pow2k_loop, sub). Cheap lemmas, so cost is turns and bundle noise, not $.
   Done 2026-10-09 (DEC-23): `Aux.lean` is the shared helper file every node may extend
   (`--shared-file`); prompt says grep it and accepted spec files first. Verify on the next run.

2. **Permission denials dominate tool errors.** 44 of 57 tool errors across 21 sessions are
   sandbox denials, not Lean failures. Breakdown: `cd DIR && cmd` compound (13), `grep ... | ...`
   compound (6), output redirection (5), `python` (5), `$VAR` / `$(...)` / brace expansion /
   quoted text "can't be checked" (10), `lake env lean --stdin` (1), other (4).
   Done: whitelist `cat *`, `sed *`, explicit edit instructions (3285616).
   Still open: compound commands, shell variables, direct `lean` invocation.
   Options: (a) tell Worker "cwd is already the slot, never `cd`; one command per call;
   no `$VAR`"; (b) whitelist `Bash(lake env lean*)`; (c) since bwrap is the real boundary,
   run Worker with `--dangerously-skip-permissions` and keep the allowlist as log-only check.
   Measure: denials per session should drop below 1.

3. **Run-level cost cap missing.** `--max-cost-usd` is enforced per target inside
   `driver.run_rounds`; `dynamic_proof.py` only records `cost_usd` per attempt. A DAG run has
   no global budget. Add `--max-run-cost-usd`; stop scheduling new nodes when exceeded,
   write `graph.json` so `--resume-dynamic` can continue.

## Important

4. **Per-attempt history only on failed nodes.** Accepted n1–n16 store `tries` and `result`
   but no `history` (cost, turns, outcome per attempt). Only n17 has it. Post-run analysis
   must re-parse transcripts. Record `history` for every attempt regardless of outcome.

5. **Trivial nodes open a full session.** `LOW_51_BIT_MASK`, `m` (×2 each), `as_extended`,
   `as_projective`: six sessions, $0.1–0.4 each, ~$1.3 total. Add a tactic pre-pass
   (`decide` / `rfl` / `simp` / `progress*` with timeout) before spawning an agent; or batch
   same-file leaves into one session (Mul.lean 3 nodes, Pow2K.lean 4 nodes).
   Trade-off: coarser accept granularity.

6. **Serial execution.** 21 sessions ran one after another. `mul` chain, `add` chain,
   `pow2k` chain are independent. Run ready nodes in parallel slots (each slot own
   `lake build`); merge accepted files via the existing publish step.

7. **Worker cannot self-check axiom closure cheaply.** Workers ran `#print axioms` by hand
   or were denied `lake env lean --stdin`. `lean_check.py --axioms <decl>` returning the
   sorry sources (same logic as the gate) removes a full reject/retry cycle.

## Fixed, verify on next run

- Sorry policy: gate now reports `sorry_sources`; whitelisted `math_assumptions.json` entries
  no longer reject (attempt 17 was rejected for an allowed `Add` instance sorry).
- Stale `.olean` after Worker edit made G1 report `rejected_statement_changed` (attempt 18).
- Worker file edits via `cat > F <<'EOF'` and `sed -i` allowed; instructions in prompt.
- Aux.lean stub (DEC-21); bundle on `main` holds no agent output (DEC-22); runs on `exp/` branches.
- `build_plan` took the first Funs dependency of the top statement as the target function;
  `to_edwards_spec` names `invert` before `to_edwards`, so its graph was invert's (9 nodes,
  not 36). Now `top_function` matches the theorem name (2026-10-09); only to_edwards affected.

## Not from this run (older list)

See `docs/HARNESS.md` § Next (2026-08-28, partly stale): `--repeats` aggregation (DEC-13),
network closure (DEC-08), seal/deadline invalidation rules.
