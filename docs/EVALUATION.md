<!-- generated-by: gsd-doc-writer -->
# Evaluation and Acceptance Protocol

This document defines what an automated Lean formalisation run is allowed to claim.  It is deliberately stricter than “the edited checkout builds”: a result must preserve the frozen experiment inputs and trusted base, close the intended obligations, and be replayable independently.  It is intended for experiments that start from selected high-level contracts and try to recover specifications and/or proofs for the `curve25519-dalek` Lean translation.

The protocol measures functional correctness relative to the declared contracts and trusted base.  It does **not** establish constant-time behavior, side-channel resistance, cryptographic security, or adequacy of a contract unless those properties are separately stated and checked.

## Scope and baseline

The authoritative starting inventory is [`.verilib/sorry_inventory.json`](../.verilib/sorry_inventory.json).  At the time of writing it records 410 declaration-level `sorry` uses: 347 task targets (318 in `Specs` and 29 auxiliary), 10 mathematical source locations, 36 intentional external-spec declarations, and 17 declarations in the pinned Aeneas dependency.  The task denominator for a full-recovery run is therefore the 347 `Specs` plus auxiliary declarations—not a text search count and not the frozen or dependency zones.

The baseline trusted material is a named input, not an invisible convenience:

| Baseline component | Current evidence | Policy |
| --- | --- | --- |
| Lean kernel foundations | `propext`, `Classical.choice`, and `Quot.sound` | Report as ordinary Lean foundations. |
| External Aeneas boundary | 21 declarations in [`harness/frozen/external_axioms.json`](../harness/frozen/external_axioms.json) | Fixed set and statement identities; no additions in a scored run. |
| Mathematical assumptions | 11 kernel declarations arising from 10 source locations in [`harness/frozen/math_assumptions.json`](../harness/frozen/math_assumptions.json) | Fixed set and statement hashes; report them prominently. |
| Pinned Aeneas dependency | 17 inventoried declarations with `sorry` | Treat as an explicit dependency trust component, not work completed by the run. |
| Compiler-trusted computation | `Lean.ofReduceBool` and `Lean.trustCompiler` reachable through `native_decide` | Allowed only when enumerated in the run’s trust report; do not call such results kernel-only. |

An experiment manifest must name the source revision, Lean/toolchain and dependency locks, selected target set, input/spec budget, baseline manifests, model and prompt versions, gate versions, resource limits, and hashes of all frozen inputs.  A different manifest defines a different condition; results must not be pooled without saying so.

## Success ladder

The ladder makes partial progress visible while preventing partial evidence from being described as a completed formalisation.

| Level | Name | Required evidence |
| --- | --- | --- |
| L0 | Valid run | Complete manifest, immutable input hashes, raw event/transcript ledger, explicit termination reason, and a verifier-produced result record. |
| L1 | Compiling candidate | The prescribed clean whole-project build exits successfully with no Lean errors. This is necessary but never a headline success on its own. |
| L2 | Obligation closure | The chosen task denominator reaches zero: each designated task declaration is closed, with no `sorry` left in the task zone and none moved to another task declaration or file. |
| L3 | Integrity-preserving formalisation | L2 plus all acceptance gates below: frozen contracts/toolchain unchanged, trust closure within baseline, forbidden-construct scan clean, and a fresh replay passes. |
| L4 | Semantically assessed specification | L3 plus the specification-quality evidence required for generated contracts: reference comparison where available, non-vacuity and mutation checks, and reviewed strength reporting. |
| L5 | Independently reproduced result | A separately initiated run in a fresh sealed environment reproduces L3 (and L4 where specification synthesis is claimed) under the same published manifest, or the variance is reported. |

### Headline rule

“Automatically formalised” requires at least L3.  “Automatically synthesised adequate specifications” requires L4.  A result described as reproducible requires L5.  Any headline must state its task denominator, exact trusted-base baseline, input budget, model/version, number of attempted runs, and whether the target was proof-only or included specification synthesis.

## Mandatory acceptance gates

The verifier, not the agent, owns these gates.  Agents must not be able to edit the verifier, frozen inputs, toolchain, or acceptance record.

1. **Clean whole-project build.** Build from a clean checkout/cache policy using the pinned toolchain.  The build must exit zero and contain no Lean errors; module-local success is not enough.
2. **Exact task-inventory closure.** Compare declaration-level build warnings with the baseline inventory.  Every designated task `sorry` must be gone.  The count may not be reduced by deleting, renaming, weakening, hiding, or moving an obligation; unchanged non-task baseline zones are reported separately.
3. **Frozen-input and contract preservation.** Hash the source snapshot, selected top-level contracts, permitted mathematical vocabulary, toolchain/dependency files, and gate implementation before and after the run.  A drift is a failed run, not an agent improvement.
4. **Trust-closure equality or narrowing.** Collect axioms/assumptions reachable from the accepted declarations and compare them with the manifest’s baseline.  No new axiom, `sorryAx` root, externally verified declaration, or external boundary is allowed.  Removing a baseline dependency is allowed but must be reported.
5. **Forbidden-construct and scope scan.** Reject new `axiom`, `@[implemented_by]`, `@[extern]`, `@[externally_verified]`, unsanctioned `sorry`/`admit`, declaration-body replacement, generated binary/object injection, or modifications outside the permitted target/output paths.  The exact allowlist and scanner version belong in the manifest.  Scan source and generated build inputs, then rebuild from clean artifacts so cached `.olean` files cannot carry a proof.
6. **`native_decide` accounting.** A run may use `native_decide` only under a written policy.  Record every newly reachable compiler-trusted root and include `Lean.ofReduceBool`/`Lean.trustCompiler` in the trust report.  New `@[implemented_by]` or `@[extern]` attributes are rejected because they can change the compiled program on which a computation relies.
7. **Fresh replay.** Reconstruct the candidate from the collected result artifacts in a new environment with no mutable agent workspace or build cache.  Re-run all prior gates.  A run that only passes in its live workspace is unaccepted.

The repository’s [`harness/gates/g2_trust_base.py`](../harness/gates/g2_trust_base.py) already implements important portions of gates 2–4: frozen-file hashes, external-axiom equality, mathematical-assumption identity, and build-warning checks. It also reports compiler-trusted roots used by `native_decide`, but its current policy does not fail every new root. The driver supplies additional edit-scope and source-level forbidden-construct checks. Together they are a prototype baseline, not a substitute for the full experiment verifier and fresh replay gate.

## Why a successful build is insufficient for generated specifications

A generated contract can be too weak, vacuous, inconsistent with the intended API, or merely a transcription of implementation behavior.  Lean can check that code satisfies such a contract without establishing that the contract says the desired thing.  Therefore a specification-synthesis condition reports contract quality separately from proof closure.

### Required specification evidence

For every synthesised top-level contract, retain the contract text, elaborated statement hash, provenance, and reviewer decisions.  Apply the following checks where they are meaningful for the target.

| Check | Question answered | Evidence |
| --- | --- | --- |
| Hidden-reference relation | Does the proposed contract match an independently withheld reference? | Classify the generated statement as **equivalent**, **stronger**, **weaker**, or **incomparable** after normalization/elaboration. Report undecided cases; do not coerce them into equivalence. |
| Executable mirror | Can executable behavior be connected to the proposition? | A computable model/property plus a proved connecting lemma, test vectors, or an explicit explanation why this form is impossible. |
| Non-vacuity | Can the precondition be satisfied and can the postcondition constrain outcomes? | Witnesses, satisfiability checks, boundary cases, and checks for impossible preconditions, `False` consequences, and unused outputs. |
| Mutation testing | Does the contract reject plausible wrong implementations? | A fixed mutation suite and kill rate, including boundary, encoding, arithmetic, and error-path mutations relevant to the target. |
| Counterexample search | Is there cheap evidence that the statement is false or too strong? | Bounded/executable search, property tests, or model finding, with domain and limits recorded. A lack of counterexamples is not a proof. |
| Blinded semantic review | Would reviewers judge the contract adequate without seeing the run identity or reference proof? | Independent reviewer rubric, disagreement record, and final adjudication. |

The comparison against a hidden human reference must be performed by a process that the synthesis agent cannot query.  “Stronger” only improves the score after checking that the strength is intended and satisfiable; an accidental impossible precondition is not a stronger useful contract.  For targets without a hidden reference, label the result *unanchored* and rely on the other evidence and human review rather than claiming equivalence.

Report per contract and aggregate: relation class, normalized statement hash, number of assumptions/preconditions, executable-mirror status, non-vacuity status, mutation denominator and killed mutants, counterexample-search budget/results, and reviewer outcome.  A single aggregate percentage must never hide weaker or incomparable public API contracts.

## Metric schema

Each attempted run emits one machine-readable record.  The schema below is intentionally a vector, because a lower `sorry` count can coexist with weaker contracts, a larger trust base, or much greater cost.

| Group | Minimum fields |
| --- | --- |
| Identity and condition | `run_id`, manifest/input hashes, source/toolchain/dependency hashes, target-set ID and denominator, experiment arm, model/provider/version, prompt and gate versions, random seed where applicable. |
| Progress | targets attempted/accepted/rejected/skipped; task `sorry` count before/after; remaining declarations by zone; build attempts; closed declarations; dependency order/parallelism. |
| Integrity | outcome of every gate; frozen-file/spec/toolchain diffs; axiom and `sorryAx` closure before/after; external and Math assumption deltas; `native_decide` roots; forbidden-scan findings; replay result. |
| Specification quality | per-contract relation class, non-vacuity/mirror/mutation/counterexample outcomes, reviewer ratings and disagreement, and missing-evidence reasons. |
| Resources | wall-clock elapsed time, active agent time, CPU/GPU allocation if controlled, input/output/cache tokens, provider-reported cost and currency, retry/reset counts, context-compaction or fresh-session count, and verifier time. |
| Attempt quality | accepted edits, rejected edits/attempts by gate and reason, recovery/rollback count, retrieval/tool use if collected, and transcript/artifact hashes. |
| Reproducibility | replay environment/hash, replay timestamp, outcome, independent reproducer ID or environment class, and deviations from the original run. |

The existing [`harness/buckets.py`](../harness/buckets.py) can classify transcript tokens into productive, diagnostic, retrieval, and rejected/dead-end categories and record re-ingestion input.  Preserve raw transcripts as the primary evidence; bucket rules are analytical and may change.  Do not compare costs unless the provider billing basis and inclusion of retries, verification, and failed attempts are the same.

## Reporting, uncertainty, and stopping

Report all attempted runs, including failures and integrity rejections.  The denominator for every rate must be explicit: for example, “23/347 task declarations closed” is different from “23/410 all inventoried declarations,” and “3/5 runs accepted” is different from “3/5 retries.”  Do not select the best run without disclosing the selection rule.

Run enough independent trials to estimate variance for any comparative claim.  “Independent” means fresh agent state, fresh sealed workspace, fixed manifest, and no carry-over of unreported solutions; it does not erase possible model-training contamination.  State model sampling settings and any adaptive changes between trials.

Before running, publish a stopping rule: maximum cost, wall time, tokens, failed attempts, resets, and target coverage; plus the conditions for early success or safety termination.  A budget exhaust, timeout, or verifier crash is an outcome, not silently omitted data.  Any change to prompts, target selection, input budget, model, gates, or human intervention creates a new experimental arm and should restart the relevant denominator.

## Interpretation boundaries

An L3 result is evidence that Lean accepted the stated theorems under the declared assumptions and integrity policy.  It is not evidence that the contracts are complete, that the Rust implementation is constant-time, or that a cryptographic construction is secure.  L4 raises confidence in generated contract adequacy but still depends on the reference/review methodology.  Claims beyond functional correctness need their own formal properties, threat model, verification tools, and acceptance gates.

For background on agent-generated internal specifications, frozen trusted libraries, and gated verification, see [*Automating Cryptographic Proofs in Verus*](https://arxiv.org/abs/2608.00965v1).  This protocol deliberately adds explicit denominators, fresh replay, contract-adequacy evidence, and full failure reporting as requirements for a defensible experiment.
