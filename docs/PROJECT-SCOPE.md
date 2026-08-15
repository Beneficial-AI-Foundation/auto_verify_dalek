<!-- generated-by: gsd-doc-writer -->

# Project scope and research claims

## Purpose

This project will build and evaluate a reproducible experimental harness for
agent-assisted formalisation of `curve25519-dalek` in Lean.  Its motivating
question is deliberately narrower than “can an AI prove cryptography?”:

> Given a pinned implementation, a declared input budget, and a controlled
> trusted base, how much correct Lean verification work can an agent produce
> without access to a known solution during the run?

The design is informed by the [CryptoProver paper](https://arxiv.org/abs/2608.00965v1),
but this is an independent experiment and must make its own inputs, isolation
evidence, verification policy, and limitations inspectable.

The current checkout is useful seed material: it is a Lean/Aeneas
no-proofs benchmark with task `sorry`s, separate Math/external/dependency trust
zones, a specification inventory, and a prototype graph-derived set of
top-level-spec candidates.  Those facts are a starting point, not a commitment
to use every existing artifact in every experiment.

## Three distinct research tracks

Results from these tracks answer different questions and must not be merged
into a single success headline.

### A. Proof recovery

The formal theorem and specification statements are supplied and the agent
fills proof bodies.  This measures proof search, Lean engineering, and the
effect of an explicit trusted theorem environment.  It does **not** show that
the agent discovered an adequate specification.

The initial benchmark snapshot contains 347 task declarations with `sorry`
according to its current inventory.  A proof-recovery run must report exactly
which statements, Math facts, external assumptions, tactics, and dependencies
were made available.

### B. Internal-spec synthesis from top-level contracts

The agent receives a pinned translated implementation and a selected set of
high-level contracts.  It may propose intermediate specifications and prove
implementation obligations, subject to separate specification-quality and
trust checks.  This is the central track for testing whether a dependency
graph plus a small contract boundary can support decomposition.

The present prototype identifies 94 candidates from 263 specifications using
a call-graph rule.  That number is not a semantic ground truth: the selection
algorithm, public-API classification, trait/external handling, tool versions,
and any manual exceptions must be frozen in the experiment manifest.

### C. Rust-to-Lean end-to-end formalisation

In the most demanding arm, the starting source is pinned Rust and the Lean
translation is produced by a pinned Aeneas pipeline.  The experiment must say
whether the agent sees the extracted Lean, operates the extractor, or receives
both.  This arm includes translation and interface choices that are absent
from tracks A and B, so it should be reported independently.

## Research questions and hypotheses

The documentation and PR discussion should settle these questions before a
scoreable campaign begins.

| ID | Research question | Testable working hypothesis |
| --- | --- | --- |
| RQ1 | How much proof recovery is possible when statements are fixed? | Isolated agents can close a measurable subset, but progress, cost, and trust preservation vary substantially by module. |
| RQ2 | Can high-level contracts support safe internal-spec synthesis? | A deterministic graph-derived boundary plus a constrained Math budget yields useful intermediate specs; compilation alone is insufficient evidence of adequacy. |
| RQ3 | How much does supplied mathematical infrastructure contribute? | Larger supplied Math/theorem budgets improve completion but also weaken the claim about autonomous formalisation; results need a budget curve, not one number. |
| RQ4 | Does role separation improve reliability? | Fresh-context spec author, independent reviewer, and prover roles reduce obvious bad specs and context degradation compared with a single long-lived agent. |
| RQ5 | What isolation evidence is enough for a credible runtime claim? | A sealed input bundle, no solution-bearing mounts/history/network, and independently replayable receipts can support a runtime-isolation claim, while not proving freedom from model pretraining contamination. |
| RQ6 | Are results reproducible across runs? | Repeated runs with fixed manifests can estimate variance; a one-off completion is an existence result, not a capability estimate. |

These are hypotheses, not success criteria.  A negative or inconclusive result
is a useful result if its input bundle, run record, and failure mode are
available for review.

## Scientific contribution and claim boundaries

The intended contribution is an auditable methodology and dataset of runs,
not a claim that an agent has independently established all security properties
of Curve25519.

Permitted claims should be phrased at the level actually supported by the
accepted run:

- A candidate patch checks against a pinned Lean toolchain and declared trusted
  base.
- A run reconstructed proofs or generated internal contracts under its
  declared input and isolation conditions.
- A collection of repeated runs achieved a stated acceptance rate, cost,
  elapsed time, and coverage for a defined target set.

The project must not silently upgrade those claims to any of the following:

- functional correctness beyond the supplied top-level contracts;
- adequacy, completeness, or non-vacuity of a generated contract without a
  separate evaluation;
- constant-time behaviour, side-channel resistance, memory safety, protocol
  security, or production security of the Rust crate;
- absence of all copying from public solutions, especially through model
  pretraining; or
- a general capability claim from a single model, seed, target ordering, or
  experiment run.

A provisional starting scope is one vertical slice of the portable serial
`u64` backend, not an implicit promise to cover the full crate.  The exact
first slice remains open under `DEC-13`; scalar-only may be tractable but may
underrepresent the API and specification challenges.  Expanding to other
backends, features, or platform-specific code is a new manifest and a new
result set.  Likewise, Aeneas extraction is an explicit experimental input:
it may be treated as a pinned preprocessing step, but it must never disappear
into an unreported trusted assumption.

## Experimental unit

A **scored run** is one immutable experiment manifest executed from a fresh
sealed workspace.  It identifies at least:

- source, extracted-code, dependency, and toolchain revisions/hashes;
- the target declarations and target ordering;
- the input budget and trusted-base inventory;
- agent roles, prompts, model identifiers, decoding settings, stop/budget
  limits, and permitted tools;
- isolation policy and collected enforcement evidence; and
- verifier version and acceptance-gate outcomes.

For multi-agent arms, the scored run contains all bounded substeps.  A useful
default is: spec author → independent spec reviewer → revision, with at most
three review cycles; then freeze or reject the specification before a fresh
prover works on it.  The verifier and its gates are not agent-editable.

An individual candidate patch is only an intermediate artifact.  It becomes a
result only after an independent, clean replay accepts it under the manifest.

## Deliverables and artifact boundaries

This Git repository should be the **control plane**: human-reviewable
documentation, experiment protocols, manifests, schemas, gate and verifier
code, runner code, input-construction scripts, and aggregate summaries.  It
should contain enough material to recreate a run environment, subject to
licensed dependencies and approved compute access.

Large or sensitive per-run materials should be content-addressed external
artifacts: candidate patches, raw model transcripts, tool logs, container and
input hashes, network/egress receipts, usage records, clean-replay logs, and
failure diagnostics.  Git should retain only a lightweight index pointing to
their identifiers, checksums, retention policy, and access status.  This keeps
PR review practical while preserving a path to audit.

The project is therefore not merely a script that calls an agent, and it is
not a repository intended to accumulate every run's raw output.  It is a
reproducible orchestration and evaluation layer around externally stored run
evidence.

## Compute, funding, and governance

Scored experiments should run against a governed API/project budget,
institutional runner, or another explicitly approved shared funding mechanism.
They must not presume that a contributor will spend a personal subscription or
personal credits to make the experiment work.  Provider, model, API access,
budget ceilings, storage, and retention are open governance decisions; each
run must record the decision actually used and disclose incomplete usage
receipts.

Credentials belong outside the sealed benchmark input and outside Git.  The
runner should receive the minimum scoped credential through an approved
mechanism, and the resulting accounting record should be available to the
reviewer without exposing the secret.

## Reproducibility and open scope choices

Reproducibility means more than retaining a final patch.  It requires a pinned
bundle, deterministic selection procedure where feasible, complete enough
receipts to replay acceptance, and a clear statement of nondeterministic
elements such as model serving and scheduling.

The following choices remain deliberately open for PR discussion:

- whether the first scored target is only the portable serial `u64` slice or
  a broader full-crate target;
- whether Aeneas extraction happens offline before scoring, inside a controlled
  build stage, or is part of the agent task;
- which Math definitions, axioms, theorems, comments, and prior specs each
  input-budget arm may see;
- which model provider and funding route meet the governance requirements;
- how many repeated seeds/runs are needed before publishing a comparison; and
- whether a later, explicitly separate security track addresses constant-time
  and cryptographic/protocol properties.

## Glossary

**Input budget**
: The complete, hashed set of information and tools available to an agent:
  source, extracted code, contracts, Math facts, prompts, dependencies, and
  allowed commands.  It is an experimental variable, not background context.

**Trusted base**
: Declarations, axioms, toolchain components, extraction assumptions, and
  external verifiers that an accepted proof is allowed to rely on.  The run
  records its exact closure and any delta from the baseline.

**Candidate patch**
: An agent-produced change set before independent acceptance.  A compiling
  patch is not automatically scored or trusted.

**Scored run**
: A fresh execution of one immutable manifest, including all agents and a
  separate acceptance replay, with recorded cost and integrity evidence.

**Runtime isolation**
: Controls that prevent the running agent from reading or fetching undeclared
  information, such as known proof repositories or shared Git history.  It is
  evidenced by the sealed environment and receipts.

**Training contamination**
: Knowledge a model may already contain because relevant code, proofs, or
  discussions appeared in its training data.  Runtime isolation cannot remove
  it; it limits what can truthfully be claimed and needs separate disclosure
  and, where possible, model/provider evidence or held-out controls.
