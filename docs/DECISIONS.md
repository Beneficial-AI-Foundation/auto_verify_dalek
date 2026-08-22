# Decisions for the PR

Use the decision IDs in PR comments. `OPEN` means there is no preferred answer
yet. `PROPOSED` means the text gives a suggested starting point, not a final
decision.

When a decision is accepted, add the date, owner, and link to the discussion.

## Experiment design

### DEC-01 — What belongs in this repository?

**Status:** PROPOSED

**Question:** Is this only a runner script, or the reviewed home of the whole
experiment setup?

**Suggested start:** Keep docs, schemas, builder/runner/checker code, manifests,
and small result summaries here. Keep large run files elsewhere.

### DEC-02 — Where do large run files live?

**Status:** OPEN

**Question:** Which BAIF-managed storage should hold transcripts, patches,
logs, and sealed bundles?

**Suggested start:** Use storage with restricted access and file hashes.
Keep failed runs as well as successful ones.

### DEC-03 — Is Aeneas extraction part of the task?

**Status:** PROPOSED

**Question:** Do agents receive translated Lean, or must they start from Rust?

**Suggested start:** Give pinned Aeneas-generated Lean in the first experiments.
Test Rust-to-Lean later as a separate experiment.

### DEC-04 — How do we choose the top-level set `T`?

**Status:** PROPOSED

**Question:** Which graph rule and which API/trait targets should define `T`?

**Suggested start:** Check in a deterministic script using pinned probe data.
Use `A → B` for “A calls B,” and report `api` and `trait-instance` targets
separately.

### DEC-05 — How do we choose the supplied seed `S`?

**Status:** PROPOSED

**Question:** What must the JSON contain, and what can agents see for targets
in `W = T \ S`?

**Suggested start:** The JSON lists `S`, compile-support mode, Math input, and
whether missing targets include their translated Lean bodies. The builder
computes `W`. Rust function names are always visible. Hidden reference
statements remain verifier-only.

Start with `S = T`, then test smaller seeds. Report the smallest seed that
passes a fixed number of repeated runs, not an unproven global minimum.

### DEC-06 — How much of `Math/` is visible?

**Status:** OPEN

**Question:** Which definitions, lemmas, assumptions, comments, and proofs may
the agents read?

**Suggested start:** Give only definitions and structures required to compile
the input. Make the agents derive useful lemmas. Run larger Math-input modes
separately if the minimal mode is too hard.

### DEC-07 — Which agent roles do we use?

**Status:** PROPOSED

**Question:** One long-running agent, or separate writer, reviewer, and prover
roles inspired by FVS?

**Suggested start:** Use fresh writer and reviewer sessions, at most three
review rounds by default, then freeze an accepted statement before proving it.
Also run a simpler baseline for comparison.

## Isolation and checking

### DEC-08 — What sandbox is enough?

**Status:** OPEN

**Question:** Is a locked-down container enough, or do scored runs need a
microVM or remote worker?

**Minimum requirement:** No host checkout, sibling repositories, old Git
history, credentials, shared writable caches, or general network access. Model
calls go through a restricted broker. Verification runs elsewhere.

### DEC-09 — What can we say about cheating?

**Status:** PROPOSED

**Question:** How should results be labelled when known solutions are public?

**Suggested start:** Claim only that runtime access was blocked and checked.
State that training-data contamination is unknown. Do not claim a fully clean
room unless there is stronger evidence.

### DEC-10 — What counts as success?

**Status:** PROPOSED

**Question:** Is a clean build or zero `sorry` enough?

**Suggested start:** No. Success needs the whole declared task complete, every
target in `T` specified and proved, unchanged supplied statements, no new
trusted assumptions or shortcuts, and a fresh replay. Generated specifications
also need quality checks.

### DEC-11 — Which Lean features are allowed?

**Status:** ACCEPTED (2026-08-22, Zhang-Liao; policy in `log/plan.md` §4)

**Question:** Should features such as `native_decide`, custom tactics, macros,
plugins, and native code be banned or allowed under a list?

**Decision:** `native_decide` is allowed in proofs. It is real computation, and
`collectAxioms` faithfully marks every theorem depending on it; the final
report states "N theorems depend on the compiler." Sites are ledgered in
`harness/frozen/native_decide_sites.json` (baseline: 6 sites plus the two
compiler axioms `Lean.ofReduceBool` and `Lean.trustCompiler`). The only
mechanically closed hole: agent output must contain zero new
`@[implemented_by]` or `@[extern]` attributes, since these can swap a
function's compiled version and let `native_decide` prove a false proposition.
This is a G2 gate check (`harness/gates/g2_trust_base.py`). All other trusted
assumptions are governed by the frozen axiom whitelist, enumerated by
`collectAxioms` over the dependency closure rather than by grep.

### DEC-12 — Can humans help during a scored run?

**Status:** PROPOSED

**Question:** May a person repair statements or guide agents after the run
starts?

**Suggested start:** No human changes after the bundle is sealed. Human work is
allowed while designing the experiment and reviewing results afterwards.

## Running and reporting experiments

### DEC-13 — Which models and how many repeats?

**Status:** OPEN

**Question:** Which providers/models do we test, with what limits, and how many
runs make a comparison credible?

**Suggested start:** Validate the harness with one pinned model, then record a
small model matrix. Compare models only on identical inputs and budgets.

### DEC-14 — What is the first project scope?

**Status:** ACCEPTED (2026-08-22, Zhang-Liao; experiment design in `log/plan.md` §7)

**Question:** One module, one portable backend, or the full crate?

**Decision:** As the suggested start. Small slices are for debugging the
harness only: the `Scalar/Scalar` vertical slice (33 proofs, 20 top-level
specs; `log/plan.md` §7.1) shakes out the driver batch mode and the Phase-2
measurement instruments. The full-project `S = T` baseline — all 347
sorry-bearing declarations proved with `collectAxioms` inside the frozen
whitelist (Phase 1, §7.2) — must exist before any end-to-end claim with a
smaller seed, because without a tree known to close, a synthesis failure
cannot be attributed (spec not synthesizable vs. proof not provable).

### DEC-15 — Who can read raw run data?

**Status:** OPEN

**Question:** Are full model transcripts public, restricted to reviewers, or
deleted after a fixed period?

**Suggested start:** Keep raw evidence in restricted storage long enough for
audit. Publish hashes, costs, outcomes, and redacted summaries.

### DEC-16 — When does a run stop?

**Status:** PROPOSED

**Question:** What are the fixed limits for cost, time, tokens, retries, review
rounds, and stalled progress?

**Suggested start:** Put all limits in the run JSON. Report timeout, budget
exhaustion, checker failure, and sandbox failure instead of discarding them.

### DEC-17 — What environment details are recorded?

**Status:** OPEN

**Question:** How much OS, image, CPU, toolchain, and model-version information
is needed to repeat a run?

**Suggested start:** Pin software and image versions. Record architecture,
resource limits, cache policy, date, and exact model identifier where possible.

## Claim boundary

### DEC-18 — Which properties are in scope?

**Status:** PROPOSED

**Question:** Does a result cover only Lean functional correctness, or also
constant-time and cryptographic security?

**Suggested start:** The first experiments cover only functional correctness
under the listed assumptions. Constant-time, side-channel, memory-safety, and
cryptographic-security claims need separate work.

## Other questions

- [ ] Which service pays for and runs the agents?
- [ ] What success rate makes a seed “validated”?
- [ ] Which seed-search method fits the available compute budget?
- [ ] How do we test that the sandbox really blocks files, Git, DNS, and web
      access?
- [ ] How are parallel agents isolated from one another?
- [ ] Which hidden-spec quality checks are mandatory?
- [ ] Is a private or post-training-cutoff test target available?
- [ ] What event invalidates a run and requires a rerun?
- [ ] What evidence would satisfy an external reviewer despite unknown model
      training data?

See [PROJECT-SCOPE.md](PROJECT-SCOPE.md),
[EXPERIMENT-PROTOCOL.md](EXPERIMENT-PROTOCOL.md), and
[EVALUATION.md](EVALUATION.md) for the short supporting rules.
