# Architecture and experiment decision register

Every item is either **OPEN** (a decision is required) or **PROPOSED** (a starting position for
review).  

## Status and review conventions

| Status | Meaning |
| --- | --- |
| **OPEN** | The question is deliberately unresolved; do not treat its options as policy. |
| **PROPOSED** | A provisional recommendation is supplied for PR discussion; it has not been adopted. |
| **ACCEPTED** | A PR or recorded governance decision adopted the choice.  No item currently has this status. |
| **REJECTED** | An option was considered and declined, with a reason recorded. |
| **SUPERSEDED** | A later decision replaces this item; retain the history and link to its replacement. |

Each accepted item should gain an owner, decision date, implementation issue,
and a link to the discussion that made it binding.  An experiment manifest then
names the IDs and exact policy versions it implements; it never inherits an
unstated convention.

## Decision register

### DEC-01 — Repository boundary and control plane

**Status:** PROPOSED

**Decision needed.** Is this repository a benchmark/control plane, an
experiment-results archive, an agent implementation, or all three?

**Options.**

1. Keep only a runner script and record results informally elsewhere.
2. Make this repository the reviewed control plane: experiment manifests,
   sealed-input builder, runner, gates, verifier, schemas, documentation, and
   a lightweight result index.
3. Put both the control plane and all raw run outputs/transcripts in Git.

**Provisional recommendation.** Choose option 2.  It makes the experimental
condition and acceptance authority reviewable without turning Git history into
an uncontrolled store of model output or potential solution leakage. The question is then: where to run experiments and how to record results? CryptoProver might have partial answers to this.

### DEC-02 — Where large runs and raw artifacts live

**Status:** PROPOSED

**Decision needed.** Where do patches, transcripts, build logs, sealed
bundles, and replay outputs live once they exceed a small PR
artifact?

**Options.**

1. Commit everything to this repository.
2. Store all material in an access-controlled, content-addressed artifact
   store; commit only manifests, result summaries, hashes, and retention
   status.
3. Store only accepted outputs externally and discard failed attempts.

**Provisional recommendation.** Choose option 2 and publish an index for both
accepted and rejected attempts.  Git should contain enough data to reproduce
the verdict, while the store retains the larger or sensitive evidence.

**Consequences/evidence required.** Select a retention period, access policy,
encryption/backup responsibility, immutable object/versioning mechanism, and
redaction process.  A run without the agreed minimum evidence is *unscored*,
not silently represented by a success row.

**question.** Which BAIF-managed artifact service can offer content hashes,
access control, and retention suitable for raw model transcripts?


### DEC-04 — Runtime sandbox and egress boundary

**Status:** PROPOSED

**Decision needed.** What isolation technology and evidence threshold prevent
runtime access to existing solutions or undeclared tools?

**Options.** A conventional container with policy checks; a container plus
host-level network namespace/firewall and read-only mounts; a microVM/remote
ephemeral worker; or a layered design combining a sealed OCI image with a
microVM and a provider-only broker.

**Provisional recommendation.** Require a sealed, ephemeral environment with
no host checkout, sibling repositories, `.git` history, package caches,
credentials, or general network egress.  Permit model requests only through an
authenticated egress broker that records request/response metadata and
enforces destination allowlists.  Build the final candidate again in a fresh
verifier environment.

**Consequences/evidence required.** Publish the image recipe, mount list,
network policy, process/file-access and egress receipts, clean Git-object-store
audit, negative connectivity test, and fresh replay log.  Prompt instructions
or command-trace inspection alone do not constitute a sandbox.

**question.** Is container-plus-host enforcement sufficient for the first
scoreable arm, or must the baseline be microVM/remote-worker isolation from the
start?

### DEC-05 — Runtime retrieval versus training-data contamination

**Status:** PROPOSED

**Decision needed.** What may a result claim when `dalek-lite`,
`curve25519-dalek-lean-verify`, CryptoProver, and related material are public?

**Options.** Claim a clean-room result; claim only runtime isolation; exclude
all public targets; or run public and held-out targets with separate labels.

**Provisional recommendation.** Treat runtime retrieval and model pretraining
as distinct threats.  A good sandbox can evidence the former but cannot prove
that a hosted model never memorised public code/proofs.  Use the term
*runtime-isolated reconstruction under a declared trusted base* for public
targets, and label training contamination as unknown unless supported by
credible model/vendor evidence and an appropriate holdout.

**Consequences/evidence required.** Record model identifier/release date,
target-publication timeline, public solution repositories considered, and any
similarity/plagiarism or negative-control analysis.

**question.** Which label set should appear in result tables: `runtime-isolated`,
`reference-assisted`, `training-contamination-unknown`, and `held-out`?

### DEC-06 — Aeneas extraction boundary

**Status:** PROPOSED

**Decision needed.** Do agents receive Aeneas-generated Lean, run extraction
themselves from Rust, or support both as named conditions?

**Options.** (a) supply only pinned generated Lean; (b) supply Rust and a
deterministic Aeneas command; (c) let agents install/configure extraction; (d)
run separate arms for (a) and (b).

**Provisional recommendation.** Make pre-extracted, pinned Lean the initial
scored condition, produced by a deterministic offline builder.  It measures
specification/proof recovery rather than tool installation or extraction
debugging.  Add Rust-plus-extraction only as a separately named arm once the
builder and toolchain are reproducible; do not permit ad-hoc downloads in the
agent runner.

**Consequences/evidence required.** Pin source bytes, Aeneas version/config,
commands, generated-output hash, and transformation logs.  Report whether a
run begins from Rust, generated Lean, or both.

**question.** Is extraction itself part of the research claim, or a fixed
preprocessing step that every scored proof/spec agent receives?

### DEC-07 — Deterministic top-level target selection

**Status:** PROPOSED

**Decision needed.** What exactly counts as a top-level specification, and how
is the answer produced reproducibly rather than selected by taste?

**Options.** Hand-curated APIs; call-graph extrema; public Rust API
closures; graph candidates followed by a reviewed classification; or one
module-specific target list per arm.

**Provisional recommendation.** Use `probe-rust`/`probe-aeneas` facts from
pinned tool versions and a checked-in deterministic selection algorithm.
Classify public API declarations, trait-instance operations, generated helpers,
external primitives, and manual exceptions separately.  The existing
`.verilib/top_level_specs.{json,md}` candidate list is useful evidence but not
yet sufficient as the authoritative pipeline. Fix the convention `A → B`
when `A` calls or depends on `B`. The current 94-of-263 inventory contains
specified functions with no incoming call path from another specified
function, traversing helpers without specs; these are graph sources under that
convention (38 `api`, 56 `trait-instance`). This decision defines the universe
`T`, not which subset is supplied to a run.

**Consequences/evidence required.** Archive graph facts, tool/config hashes,
algorithm version, selection output, exception rationale, and validation that
probe target configuration did not silently omit modules.  Name whether
"top-level" means public entry point, graph extremum, or benchmark boundary.

**question.** Should the first target list be public API only, or include
trait specifications and graph-derived candidates as distinct strata?

### DEC-08 — Mathematical infrastructure, axioms, and input-budget arms

**Status:** OPEN

**Decision needed.** Which existing Math definitions, lemmas, assumptions,
comments, contracts, and proof clues may be exposed to the agent?

**Options.** A single full-reference baseline; no project Math layer; a fixed
minimal vocabulary; or a declared matrix of progressively stronger input
budgets.

**Provisional recommendation.** Use a matrix and never pool its results:

| Arm | Agent receives | Intended interpretation |
| --- | --- | --- |
| M0 | Mathlib and only the domain/type definitions needed to state and type targets | Feasibility floor; may be impractical. |
| M1 | M0 plus a fixed project definition/specification vocabulary, but no project theorem/axiom statements, proof bodies, or strategy comments except an allowlist | Tests mathematical-interface discovery with a low reference budget. |
| M2 | M1 plus a fixed, declared set of Math lemma/assumption statements, with proof bodies and strategy comments hidden | Recovery relative to a stated trusted Math interface. |
| M3 | M2 plus the full allowed project Math layer and explicitly listed guidance | Reference-assisted productivity baseline, not clean specification discovery. |

The builder must separately account for mandatory elaboration support and
optional semantic assistance. Imports, types, structures, definitions, and
notation needed to compile a chosen seed are a **support closure**; including
them must not silently include project lemmas, theorem statements, proof
bodies, comments, or hidden top-level reference contracts.

**Consequences/evidence required.** Hash every visible file/declaration and separately
count declarations, assumptions, comments, statement text, and proof bodies
available in each arm.  The current frozen Math/external manifests are a useful
starting inventory, not permission to hide a large trusted base. Report the
support closure and semantic Math budget as different manifest fields.

**question.** What is the smallest M1 vocabulary that still lets Lean state
meaningful Curve25519/Ristretto properties without making the experiment
artificially impossible?

### DEC-09 — FVS-inspired agent roles and bounded review loops

**Status:** PROPOSED

**Decision needed.** Should the system use a role-separated workflow inspired
by the existing Formal Verification Skill (FVS) material, and who decides when
a specification is frozen? In a seeded run, only the supplied set `S` is
frozen initially; contracts for `W = T \ S` must be generated.

**Options.** One general agent; spec writer plus prover; spec writer →
independent spec reviewer → rewrite loop → prover; or a broader multi-agent
system with a separate orchestrator and verifier.

**Provisional recommendation.** Treat FVS prompts/roles as a versioned
treatment, not an acceptance authority.  Use fresh contexts for a spec writer
and independent reviewer; permit at most three writer/reviewer cycles per
target; then record `freeze`, `reject`, or `defer` automatically under a
published rule.  A prover gets the frozen contract and a separate fresh
context.  The harness/verifier, outside all agents' write authority, accepts
or rejects the outcome. An accepted generated contract in `W` is
canonicalised and frozen before it reaches a prover; supplied contracts in
`S` are immutable for the entire run.

**Consequences/evidence required.** Version/hash role prompts, tool permissions,
handoff summaries, review rubric, loop count, and termination decision.  The
reviewer must not see a hidden human reference or have a feedback channel that
lets the synthesis agent query it.

**question.** Which FVS role prompts are admissible in the initial arm?

### DEC-10 — Acceptance and headline definition of success

**Status:** PROPOSED

**Decision needed.** What gates must pass before a run is called successful?

**Options.** A build passing; zero `sorry`; zero task-scope
obligations plus fixed trust base; or a ladder separating compilation,
obligation closure, integrity (no axioms or weird meta-programming patterns), specification adequacy, and reproduction.

**Provisional recommendation.** Adopt the ladder in `docs/EVALUATION.md` as
the vocabulary for discussion.  A headline “automatically formalised” result
requires clean whole-project replay, zero declared task obligations, immutable
inputs/contract identities, no trust-base expansion, scope and forbidden-code
checks, and fresh verification (L3).  Claims of adequate generated
specifications additionally require the semantic checks described there (L4).
A seeded run succeeds only if every target in `T`, including the withheld
`W`, has an accepted fully proved contract **and** the declared whole-project
task denominator closes. Because it generates `W`, a “formalised from seed
`S`” headline requires L4.

**Consequences/evidence required.** Every table states denominator, target set,
input arm, trust report, prompt/model version, attempts, failures, cost, and
whether it was proof-only or specification synthesis.

**question.** Should L3 be the minimum scoreable result, with L1/L2 kept as
progress-only outcomes, or do colleagues need a smaller initial acceptance
unit for engineering iteration?

### DEC-11 — Lean anti-cheat policy and allowlist

**Status:** PROPOSED

**Decision needed.** Which Lean facilities are forbidden, which are pinned
baseline dependencies, and which are permissible with explicit accounting?

**Options.** Textual scans only; a blanket ban on advanced Lean features; or
a manifest-owned allowlist plus source, declaration, trust-closure, and fresh
replay gates.

**Provisional recommendation.** Forbid new `sorry`, `admit`, `axiom`,
`@[implemented_by]`, `@[extern]`, `@[externally_verified]`, unsafe declarations,
unapproved opaque proof escapes, new plugins/macros/elaborators, generated
object injection, and edits to toolchain/gates/frozen inputs.  Permit only
pre-pinned packages and reviewed baseline exceptions.  `native_decide` is
neither automatically banned nor silently kernel-only: each reachable
`Lean.ofReduceBool`/`Lean.trustCompiler` root must be declared and compared to
the baseline.

**Consequences/evidence required.** An allowlist entry has exact file or
declaration, hash, owner, rationale, arm scope, and trust effect.  Fresh replay
must use source closure only, not runner-produced `.olean` caches.  The policy
must cover indirect metaprogramming and imports, not just word searches.

**question.** For the first scored experiment, should *all* new
`native_decide` be rejected, or allowed only when the compiled code and trust
roots are independently pinned and reported?

### DEC-12 — Model/provider/repetition matrix

**Status:** OPEN

**Decision needed.** Which providers/models/sampling settings form the
evaluation matrix, and how many independent trials support comparison?

**Options.** One named model for a pilot; a fixed multi-provider matrix;
rolling latest models; or a held constant model plus a separately reported
drift study.

**Provisional recommendation.** Begin with one pinned model/version and
sampling configuration for harness validation, then add a pre-registered
matrix of providers/models with fresh workspaces and contexts per trial.  Do
not compare costs or success rates across models unless token accounting,
retry policy, budgets, prompts, and input bundle are comparable.

**Consequences/evidence required.** Record provider/model/version/date,
sampling settings, tool API version, rate-limit behavior, trial seed where
available, retries/resets, number of attempts, and model drift events.  A
provider model alias such as “latest” is not reproducible without a dated
identifier.

**question.** What is the minimum trial count and provider diversity needed
before presenting a comparative claim rather than a single-case demonstration?

### DEC-13 — Source revision, backend, and target scope

**Status:** OPEN

**Decision needed.** What source revision and execution/backend surface is in
scope for the first campaign?

**Options.** The current Aeneas Lean snapshot; a pinned upstream
`curve25519-dalek` revision re-extracted from Rust; one portable backend/slice;
or the full crate including all generated and platform-specific paths.

**Provisional recommendation.** We could aim for full-crate verification after
establishing the `S = T` all-top-level-spec baseline, then test smaller seed
sets without changing the full-crate success denominator.

**Consequences/evidence required.** Record Rust commit, Aeneas output hash,
Rust feature flags, target architecture/OS, compiler and toolchain versions,
and inclusion/exclusion rationale for scalar, Edwards, Montgomery, Ristretto,
traits, FFI, and architecture-specific code.

**question.** Is the full crate too much for the initial experiment? 

### DEC-14 — Artifact privacy, retention, and reviewer access

**Status:** OPEN

**Decision needed.** How long are prompts, provider responses, logs, and
patches retained; who can access them; and what can be public in a PR?

**Options.** Full public release; restricted raw artifacts plus public hashes
and summaries; or destroy raw artifacts after aggregate extraction.

**Provisional recommendation.** Retain restricted raw evidence long enough for
independent audit, publish redacted summaries/hashes by default, and document
why any evidence is withheld.  Preserve rejected-run metadata as well as
successful outputs, subject to privacy and licensing constraints.

**Consequences/evidence required.** Define data classification, access roles,
retention/deletion schedule, redaction review, audit logging, incident process,
and what a reviewer needs to reproduce or challenge a result.

**PR question.** Are unredacted model transcripts acceptable project artifacts,
and if not, which receipt fields are sufficient for meaningful review?

### DEC-15 — Human intervention and blinded semantic evaluation

**Status:** PROPOSED

**Decision needed.** Which human actions are allowed during a scored run, and
how should people judge generated top-level contracts without leaking a hidden
reference?

**Options.** Interactive human-in-the-loop agents; no intervention after
bundle sealing; separate engineering and scored modes; or automated checks
only.

**Provisional recommendation.** The ultimate scored goal is no human
intervention after bundle sealing. That applies both when all top-level specs
are supplied and when agents generate `W`; agent review and mechanical or
blinded post-run assessment are part of the registered workflow, not ad-hoc
human feedback.

**question.** Is “no `sorry` in top-level proofs” useful only as a progress
gate, with semantic adequacy and whole-project closure still required for
success?

### DEC-16 — Failure reporting and stopping rules

**Status:** PROPOSED

**Decision needed.** When does a campaign stop, what is published on failure,
and how are verifier/sandbox incidents handled?

**Options.** Stop informally after apparent success; discard failures; use a
fixed budget/time/stall rule with complete attempt accounting; or allow adaptive
changes without restarting the denominator.

**Provisional recommendation.** Pre-register cost, wall-time, token, retry,
review-loop, and target-coverage limits.  Publish every attempt's termination
reason, including timeout, budget exhaustion, gate rejection, verifier crash,
and isolation incident.  Any meaningful change to inputs, prompts, model,
gates, or intervention starts a new arm.

**Consequences/evidence required.** Define severity/containment steps for a
leak or credential incident, artifact quarantine, notification/owner, and
whether affected results are invalidated or rerun.  Preserve enough evidence to
diagnose failures without exposing secrets.

**question.** What stopping rule prevents endless prompt tuning while still
allowing legitimate harness repairs to be distinguished from benchmark
adaptation?

### DEC-17 — Constant-time, security, and correctness claim boundary

**Status:** PROPOSED

**Decision needed.** Which properties are in scope for claims made by this
project?

**Options.** Functional contract satisfaction only; functional correctness plus
selected algebraic properties; or include constant-time, memory-safety,
side-channel, and cryptographic security goals.

**Provisional recommendation.** Initial results are functional Lean
formalisation relative to declared contracts and trusted assumptions.  Do not
describe them as proving constant-time behavior, side-channel resistance,
Rust memory safety, or Curve25519 cryptographic security.  Those are separate
property families requiring their own models, specifications, tools, and
reviewers.

**Consequences/evidence required.** Every abstract, README result table, and
PR summary states this boundary and names any property that is deliberately
out-of-scope.

**question.** Should an explicit non-goal statement be mandatory in every
experiment manifest and published result page to avoid the agents getting drifted trying tasks like constant-time behavior etc?

### DEC-19 — Hardware, determinism, and model drift

**Status:** OPEN

**Decision needed.** Which environmental details are part of a reproducible
run, and what happens when a provider changes a model or hardware differs?

**Options.** Report only source and model name; fully pin OS/image/toolchain
and resource limits; or freeze all hardware and provider versions where
possible.

**Provisional recommendation.** Pin software/image/toolchain and report CPU
architecture, OS/kernel class, resource limits.
Treat provider/model drift as a new condition; where a model cannot be pinned,
record the date and label reproducibility as limited rather than pretending it
is exact.

**Consequences/evidence required.** Add image digest, architecture, resource
limits, build/replay timing, cache policy, deterministic-seed support, and
model availability changes to receipts.

**PR question.** What minimum hardware/OS record is useful without making the
first manifests platform-specific?

### DEC-21 — Parametric top-level seed sets and support closure

**Status:** PROPOSED

**Decision needed.** How does a run declare which top-level specifications are
supplied, what information identifies the missing targets, and which related
Math material is included merely to make the starting bundle elaborate?

**Options.** Always supply all of `T`; accept a JSON seed `S ⊆ T`
with only its minimal elaboration closure; accept the same parametric seed but
also expose definition-only vocabulary sufficient to state all of `T`; or
hand-build each bundle without a reproducible closure rule.

**Provisional recommendation.** Make the seed a versioned, schema-validated
experiment input. The builder fixes `T`, reads `allowed_spec_ids` for `S`,
derives `W = T \ S`, and emits a sealed agent bundle plus a separate
verifier-only reference manifest. Contracts in `S` and their required
definition/structure closure are supplied; reference statements and proofs for
`W` are not. Every withheld target exposes its stable Rust function identity.
Whether its extracted Lean declaration/body from
`Curve25519Dalek/Funs.lean` is also visible is an explicit treatment field.

Begin with `S = T` to validate the harness. Then evaluate deterministic
ablations under both named closure policies if resources allow:
`seed-elaboration-only` for the strongest reconstruction claim and
`universe-vocabulary` as a more guided diagnostic condition. Direct
model/workflow comparisons use identical seeds and closure hashes; results
across seeds form a spec-budget curve.

**Consequences/evidence required.** Record the ordered `T`, `S`, derived
`W`, target-identity/body visibility, support-closure algorithm and resolved
declarations, Math budget, generator/configuration hashes, and final bundle
hash. Scan agent inputs for reference statements or proofs for `W`. For every
run, report top-level completion separately from whole-project closure. A seed
set is “validated” only under a pre-registered repetition/pass threshold; the
search may claim the smallest validated seed found, not a global minimum it did
not exhaustively establish.

**question.** For the first `S2` campaign, should withheld targets expose their
transpiled Lean bodies, and should support be `seed-elaboration-only` or
`universe-vocabulary`?

## AOB / questions we may have missed

Use this checklist to add discussion items before any decision is marked
accepted.

- [ ] Should reference repositories be blocked only at runtime, or should
      outputs also be compared against them for suspicious copying?
- [ ] Is a private/post-training-cutoff holdout available, and who controls it?
- [ ] How do we test the sandbox itself (DNS, proxy, Git object, cache,
      clipboard/IPC, and model-tool escape tests) before scoring a campaign?
- [ ] Do benchmark bundles need reproducible offline dependency mirrors, and
      how are those mirrors kept free of solution material?
- [ ] How are parallel agents isolated from one another so that a successful
      worker cannot become an undeclared oracle for another worker?
- [ ] What merge/order policy prevents independently proved modules from
      creating termination or dependency-cycle failures?
- [ ] Should mutations, hidden-reference comparisons, and semantic review be
      mandatory per target or sampled by module?
- [ ] What independent-run count and pass threshold make a seed sufficient,
      and how do we report stochastic non-monotonicity between subsets?
- [ ] Which deterministic seed-search strategy and total compute budget are
      credible when exhaustive search over `2^|T|` subsets is impossible?
- [ ] What public result format makes failed, timed-out, and rejected runs as
      visible as accepted runs?
- [ ] Who is allowed to change the target selector, input budget, FVS prompts,
      gate allowlist, or scoring rubric, and what starts a new experiment arm?
- [ ] Which operational incidents (credential exposure, egress violation,
      discovered reference mount, verifier defect) automatically invalidate a
      run and trigger notification?
- [ ] Is there a deprecation/archival policy for obsolete model versions,
      sealed images, artifact stores, and old result links?
- [ ] What would persuade a skeptical external reviewer that the result is
      useful even when clean pretraining decontamination cannot be proven?

## Related documents

- [Project scope](PROJECT-SCOPE.md) separates the research tracks, claim
  boundary, and repository-versus-artifact deliverable.
- [Architecture proposal](ARCHITECTURE.md) describes the proposed trust
  boundaries and repository/artifact split.
- [Experiment protocol](EXPERIMENT-PROTOCOL.md) defines target derivation,
  input-budget arms, and the bounded agent workflow.
- [Isolation and integrity](ISOLATION-AND-INTEGRITY.md) expands the threat
  model, sterility evidence, and Lean gate policy.
- [Evaluation and acceptance protocol](EVALUATION.md) defines the success
  ladder, metrics, and specification-adequacy evidence.
