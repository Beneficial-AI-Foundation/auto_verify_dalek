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

## Four distinct research tracks

Results from these tracks answer different questions and must not be merged
into a single success headline.

### A. Proof recovery (trivial)

The formal theorem and specification statements are supplied and the agent
fills proof bodies.  It's well known that proofs are nowadays cheap. It could happen tho that a proof is quite involved and to do it properly it requires several helping lemmas, and the agent has to understand how to properly decompose the big task into smaller manageable ones.

### B. Internal-spec synthesis from all top-level contracts

The agent receives a pinned Aeneas translation and every contract in a fixed,
graph-derived top-level target universe `T`. It must recover sufficient
internal specifications and prove the resulting obligations. This is the
closest all-contract baseline for measuring the value of the proposed agent
workflow without also asking it to discover the outer specification boundary.

Here and throughout these documents, fix the edge convention `A → B` when
`A` calls or depends on `B`. A top-level target is a specified function that
no other specified function calls, directly or transitively through helper
definitions without specifications. Under this convention the targets have no
incoming dependency path and are graph **sources**; they would be sinks if the
edge direction were reversed. For example, if `A` uses `B`, and nothing uses
`A`, then `A`, not `B`, is top-level for this experiment.

The current exploratory inventory identifies 94 candidates from 263
specifications: 38 labelled `api` and 56 labelled `trait-instance`. That is
35.7%, rather than almost half. The count and classification still need to be
reproduced by a checked-in deterministic selection script before they become
an experimental boundary.

### C. Parametric top-level-spec recovery

This is the main proposed experiment. Fix the deterministic top-level universe
`T`, then choose a per-run supplied seed set `S ⊆ T`. The withheld targets are
determined, not hand-picked separately: `W = T \ S`. Contracts in `S` are
visible and immutable. For each target in `W`, the agent receives at least its
stable Rust function identity. Whether it also receives the corresponding
pinned extracted Lean declaration/body from `Curve25519Dalek/Funs.lean`, its
source location, expected theorem name, or destination is a manifest-level
choice.

A deterministic builder must also materialise the declarations required for
the seed to elaborate. This **support closure** is distinct from the semantic
Math budget: imports, types, structures, definitions, and notation needed to
compile the supplied inputs do not automatically justify exposing helpful
lemmas, theorem statements, proof bodies, comments, or the withheld reference
contracts. The closure policy must therefore be declared and hashed.

A successful run must synthesize semantically adequate contracts for every
target in `W`, retain the exact supplied contracts in `S`, and produce full
proofs for every target in `T`, as well as close the declared whole-project
task obligations. Merely filling the `sorry`s attached to `S` is not success.
The research objective is to find the smallest seed set that repeatedly meets
those gates under a fixed harness and budget. Since exhaustive search over 94
targets is infeasible and model outcomes are stochastic, any practical result
must be called the **smallest validated seed set found**, not a proven global
minimum. The all-spec case `S = T` remains the fallback baseline.

### D. Rust-to-Lean end-to-end formalisation

Whether the agent must produce the Lean translation is a separate experimental
axis from which contracts it receives. In this optional, more demanding track,
the starting source is pinned Rust and a pinned Aeneas pipeline produces—or the
agent is asked to help produce—the Lean target. Results must state both the
translation treatment and the seed set `S`; a small seed set must not be
silently conflated with Rust-to-Lean translation work.

## Research questions and hypotheses

The documentation and PR discussion should settle these questions before a
scoreable campaign begins.

| ID | Research question | Testable working hypothesis |
| --- | --- | --- |
| RQ2 | Can high-level contracts support safe internal-spec synthesis? | A deterministic graph-derived boundary plus a constrained Math budget yields useful intermediate specs; compilation alone is insufficient evidence of adequacy. |
| RQ3 | How much does supplied mathematical infrastructure contribute? | Larger supplied Math/theorem budgets improve completion but also weaken the claim about autonomous formalisation; results need a budget curve, not one number. |
| RQ4 | Does role separation improve reliability? | Fresh-context spec author, independent reviewer, and prover roles reduce obvious bad specs and context degradation compared with a single long-lived agent. |
| RQ5 | What isolation evidence is enough for a credible runtime claim? | A sealed input bundle, no solution-bearing mounts/history/network, and independently replayable receipts can support a runtime-isolation claim, while not proving freedom from model pretraining contamination. |
| RQ6 | Are results reproducible across runs? | Repeated runs with fixed manifests can estimate variance; a one-off completion is an existence result, not a capability estimate. |
| RQ7 | What is the smallest useful top-level seed set? | A deterministic seed manifest and support-closure policy permit a controlled input-ablation curve; repeated success, rather than a single lucky run, is required before calling a seed sufficient. |

Possible answers:
RQ3: I'd only supply math infrastructure needed to compile the top-level specs; this means just provide with definitions structures that allows us to define the top-level spec. the lemmas and props about math objects that we need to complete the top-level proofs should be derived by the agents if we want to fully test the auto-formalisation feasibility.

RQ4: the answer is basically already known and it's yes, if we avoid context rot then we gain in quality
RQ5: pretraining contamination is out of reach for us, we cannot have any idea about this and we should be transparent about it. But what ew could do is to try to gatekeep agents from internet access or network. but this will worsen their lean coding capabilities since they will have no access to mathlib or useful Lean api's. Is there a better approach? how was this solved in the cryptoprover?

RQ6: I guess that repeated experiments with low variance should strenghten our findings, we might need to impose some thresholds to be happy with tho.

## Experimental unit

A **scored run** is one immutable experiment manifest executed from a fresh
sealed workspace.  It identifies at least:

- source, extracted-code, dependency, and toolchain revisions/hashes;
- the top-level-universe identifier, supplied seed `S`, derived withheld set
  `W`, target-function visibility policy, and target ordering;
- the deterministic elaboration/support-closure policy and its materialised
  declaration inventory;
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

Scored experiments should run using API keys, not personal subscription accounts so that we can also record the total spent and the actual time spent.
Provider, model, API access, budget ceilings, storage, and retention are things to be tracked. Each
run must record at least the provider, the model, the budget spent and the time.

## Reproducibility and open scope choices

Reproducibility means more than retaining a final patch.  It requires a pinned
bundle, deterministic selection procedure where feasible, complete enough
receipts to replay acceptance, and a clear statement of nondeterministic
elements such as model serving and scheduling.

The following choices remain deliberately open for PR discussion:

- whether Aeneas extraction happens offline before scoring, inside a controlled
  build stage, or is part of the agent task (probably not: we have deterministic scripts we can run in our environments so tht the agents can start working afterwards without introducing randomness in the extraction phase too. This of course means that we are assuming that the extraction will go smoothly, but we already have this assumption for curve dalek);
- which Math definitions, axioms, theorems, comments, and prior specs each
  input-budget arm may see;
- whether a seeded run receives only the closure required to elaborate `S`,
  or a definition-only vocabulary sufficient to state all targets in `T`;
- whether withheld targets expose only their required Rust identity or also
  an extracted Lean body, source location, expected theorem name, and
  destination;
- which model provider and funding route meet the governance requirements (I'd go for Fable and GPT Sol, and maybe have smaller models for specific subagents with low level tasks);
- how many repeated seeds/runs are needed before publishing a comparison; and
- whether a later, explicitly separate security track addresses constant-time
  and cryptographic/protocol properties.

## Glossary

**Input budget**
: The complete, hashed set of information and tools available to an agent:
  source, extracted code, contracts, Math facts, prompts, dependencies, and
  allowed commands.  It is an experimental variable, not background context.

**Top-level target universe `T`**
: The deterministically selected, versioned set of top-level functions whose
  contracts and proofs must exist at the end of a seeded run.

**Seed set `S`**
: The subset of `T` whose exact contracts are supplied to the agent at the
  start of a run. The withheld set `W = T \ S` must be reconstructed.

**Support closure**
: The minimal, deterministically generated declarations and imports needed for
  the chosen visible implementation and seed specifications to elaborate. It
  is recorded separately from optional semantic lemmas and Math guidance.

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
