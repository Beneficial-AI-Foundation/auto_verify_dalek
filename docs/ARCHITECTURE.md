# Architecture proposal

This repository is intended to become the control plane for reproducible experiments that attempt to formalise selected parts of `curve25519-dalek` in Lean from an explicitly declared input budget.  It must distinguish three things that are easily conflated: preparing a benchmark, letting an agent modify a working copy, and independently deciding whether a run is acceptable.

The immediate target is the existing Lean/Aeneas snapshot, not a claim that the proposed system has already been implemented.  The architecture below is therefore a discussion proposal.

## Current repository components

The repository already provides useful benchmark and prototype material:

| Area | Current role | Architectural status |
| --- | --- | --- |
| `Curve25519Dalek/` | Aeneas-generated Lean translation, Lean specifications, mathematical support, auxiliary lemmas, and tactics. | Benchmark input; exact inclusion in a future experimental bundle is a protocol decision. |
| `lakefile.toml`, `lean-toolchain`, `lake-manifest.json` | Pinned Lean/Lake project and dependencies. | Candidate part of the fixed toolchain input. |
| `.verilib/sorry_inventory.json` | Declaration-level inventory, including the stated task, Math, external-spec, and dependency zones. | Current status artifact; it should be regenerated and hashed for each scored bundle. |
| `.verilib/top_level_specs.{json,md}` | A current graph-derived list of 94 top-level specification candidates (among 263 specifications). | Useful prototype output, not yet a fully reproducible target-selection pipeline. |
| `harness/driver.py` | A per-target agent loop with scope, forbidden-construct, build, sorry-accounting, and G2 checks. | Prototype harness, not an OS-level sandbox or a complete experiment runner. |
| `harness/gates/g2_trust_base.py` and `harness/frozen/` | Frozen-file hashes, external-axiom and Math-assumption manifests, and a Lean-side trust-closure audit. | Strong starting point for acceptance gates; needs a clearly versioned policy per experiment. |
| `harness/gates/StmtCanon.lean` | Statement canonicalisation intended to detect changes hidden by alpha-renaming or controlled unfolding. | Candidate statement-integrity gate. |
| `harness/resynth.py` | A prototype for deleting/resynthesising selected specifications and recording a constrained specification budget. | Candidate treatment implementation; its exact policy must be fixed before scoring. |
| `harness/buckets.py` and the run-time ledger format in `harness/driver.py` | Transcript classification and per-attempt records. | Candidate provenance/cost accounting, not yet a complete external-usage receipt. The driver creates its ledger paths when it runs; no run ledger is committed in this snapshot. |

The root README describes a no-proofs snapshot.  Its historical aggregate `sorry` count is not the current experiment authority: `.verilib/sorry_inventory.json` explicitly records that it supersedes the stale triple-counted summary.  A scored run should record the exact inventory hash rather than relying on prose counts.

## Proposed control plane

The proposed design uses one-way hand-offs.  The component that accepts a result must not be editable by the agent producing it, and the component that builds a test image must be separate from the environment that sees the test image.

```text
                            offline / trusted preparation
┌──────────────────────────────────────────────────────────────────────────┐
│ pinned Rust source + Aeneas/probe tools + selection policy + Lean pins   │
│                 Deterministic input builder                              │
│              ┌───────────────────────────────────────┐                   │
│              │ target T, seed S, withheld W          │                   │
│              │ support closure + input/policy hashes │                   │
│              └───────────────────┬───────────────────┘                   │
└──────────────────────────────────┼───────────────────────────────────────┘
                                   │ immutable, content-addressed bundle
                                   v
┌──────────────────────────────────────────────────────────────────────────┐
│ isolated untrusted runner                                                 │
│  read-only bundle ──> role agents ──> writable candidate workspace        │
│          │                 │                     │                         │
│          │                 └── provider-only egress broker ──> receipts    │
│          │                                                               │
│          └── no host checkout, solution trees, git history, or secrets    │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ candidate patch + logs only
                                   v
┌──────────────────────────────────────────────────────────────────────────┐
│ independent verification and collection                                  │
│ fresh verifier ──> immutable gates ──> signed/hash-linked run artifacts  │
│                                      └──> lightweight repository index     │
└──────────────────────────────────────────────────────────────────────────┘
```

### 1. Deterministic input builder

The builder runs before scoring, ideally in a controlled preparation environment.  It should:

1. Check out pinned bytes of the Rust source, the Lean project, Aeneas/probe tooling, and all toolchain inputs.
2. Run the selected extraction and graph-analysis commands with recorded versions and configuration.  `probe-rust` and `probe-aeneas` are natural candidates for emitting Rust and cross-language call-graph facts; neither should silently determine the benchmark by an undocumented default.
3. Apply a versioned, deterministic target-selection algorithm to those facts.  The generated top-level universe `T` must identify public APIs, trait-instance operations, trusted/external declarations, and manual exceptions separately.
4. Read a versioned experiment input that selects the supplied seed `S ⊆ T`, and derive the withheld targets `W = T \ S`. The complement must not be maintained as a second hand-edited list.
5. Materialise the registered target visibility policy. Supplied contracts in `S` are visible and immutable; targets in `W` always receive their stable Rust function identities and only the additional implementation material explicitly permitted by the manifest, such as pinned extracted declarations/bodies in `Curve25519Dalek/Funs.lean`.
6. Compute the declared support closure. Keep syntactic elaboration support—imports, types, structures, definitions, and notation—separate from optional semantic Math lemmas, theorem statements, proof bodies, comments, and reference contracts.
7. Produce two non-overlapping outputs: an agent bundle with no reference statements or proofs for `W`, and a verifier-side reference manifest used only for post-run semantic assessment.
8. Produce a manifest with cryptographic hashes for every input file and declaration, the resolved `T`, `S`, and `W`, generator version, command configuration, selection/closure-policy versions, and declared trusted base.

Extraction is best treated as preparation rather than agent work: it makes the agent's contribution legible and avoids measuring incidental tool installation or network access.  An alternative arm in which the agent receives Rust rather than pre-extracted Lean can still be useful, but it must be named as a different condition and have its own bundle.

### 2. Content-addressed experiment bundle

An experiment bundle is the complete, immutable description of a single runnable condition.  Its identifier should derive from the manifest and content hashes, not a mutable branch name.  At a minimum it should carry:

- source and dependency bytes permitted to the agent;
- Lean toolchain and build configuration;
- graph facts, target list, and selection rationale;
- the top-level-universe identifier, supplied seed `S`, derived withheld set
  `W`, target-function visibility, and support-closure policy/output;
- agent prompts/role definitions, model configuration, budgets, and stopping rules;
- frozen files, allowlists, forbidden constructs, and the verifier version;
- the input-budget declaration, including whether existing Math statements, lemmas, comments, and proofs are visible;
- a reference-free policy for external data, solution repositories, caches, and network egress.

The bundle manifest is part of the scientific result.  It must make it possible to tell the difference between “proved existing statements” and “reconstructed specifications and proved them.” Existing manifests emitted by the exploratory `harness/resynth.py` workflow archive original statements for later comparison. Those are useful verifier records, but they must not be copied into an `S2` agent bundle without a new split-manifest builder.

### 3. Isolated untrusted agent runner

The runner gives agents a writable candidate workspace and a narrow, recorded interface to the model provider.  It must not expose the host checkout, sibling repositories, the host Git object store, ambient credentials, shell history, or build caches that can contain reference proofs.

The recommended model is provider-only egress through a broker.  The broker enforces the approved provider endpoints, records request and response metadata needed for cost and provenance accounting, and rejects other network destinations.  The runner itself should have no direct general-purpose egress.  Model credentials belong to the broker or orchestration service, never to the agent workspace.

The current `harness/driver.py` is deliberately more modest: it invokes a headless agent process, constrains its tool list, gates diffs, and runs the local build.  Those controls are valuable, but they do not demonstrate filesystem, process, cache, DNS, network, or model-training-data isolation.  They should therefore be described as prototype gates until an independently reproducible sandbox and receipt mechanism exists.

### 4. Harness-owned immutable gates

The agent may propose a patch; it must not change the criterion for accepting its own patch.  The gates and their configuration should be mounted read-only or supplied from a separate verifier image.  Candidate gates include:

- identity/canonicalisation and frozen hashes for supplied statements in `S`;
- designated writable slots for generated contracts in `W`, followed by
  canonicalisation and freezing after independent review accepts them;
- full clean Lean rebuild, with a contract and proof for every target in `T`
  and no declared task `sorry` left in scope;
- fixed or reduced axiom/trust closure and no new `axiom`, `@[implemented_by]`, `@[extern]`, unsafe compiler hook, or unapproved metaprogramming route;
- source-scope limits and checks that work is not migrated to another file or declaration;
- toolchain/dependency-image integrity;
- network/process/file-access audit results and agent/provider usage receipts.

`g2_trust_base.py` already illustrates the desired separation: it checks frozen inputs, axiom declarations, assumption statements, and build warning locations against manifests.  Its current `native_decide` treatment permits the frozen compiler-trusted roots and reports new roots rather than failing them. A production gate set must turn that report-only behavior into an explicit per-arm acceptance choice and add policy for macros, plugins, generated object files, and every other route that can affect kernel trust or obscure the proof source.

### 5. Independent fresh verifier

Verification should replay the candidate patch in a fresh environment assembled only from the bundle plus the patch.  It should not reuse the runner's build products, Git metadata, model context, or write permissions to the bundle.  A verifier returns a machine-readable verdict and reasons for rejection; it does not give the runner an opportunity to mutate the gate configuration.

For specification-synthesis experiments, successful elaboration is necessary but insufficient.  The verifier should also run the selected adequacy checks (for example, vocabulary restrictions, totality/determinism obligations, executable-mirror checks, mutation tests, or hidden-reference comparison where permitted by the protocol). For a seeded run, hidden references for `W` are mounted only in this verifier environment, after the candidate patch and transcript are sealed.

### 6. Artifact collector and run index

The collector receives append-only runner and verifier outputs, hashes them, and links them to the bundle identifier.  It should retain at least the candidate patch, tool/model configuration, command/egress receipts, transcripts under the agreed retention policy, verifier logs, final trust report, and costs/timing.

Large or sensitive artifacts should live outside the Git repository in an access-controlled artifact store.  The repository should retain small, reviewable materials: experiment manifests, schemas, gate code, aggregate tables, and a lightweight run index containing content hashes, locations, verdicts, and redaction status.  This keeps pull requests useful without turning Git history into an uncontrolled corpus of model transcripts or solution material.

## Trust boundaries and failure containment

| Boundary | What crosses it | Failure that must not cross back |
| --- | --- | --- |
| Preparation → bundle | Declared, hashed implementation, seed contracts, and support closure only | Unpinned sources, accidental reference statements/proofs for `W`, closure overreach, or hidden generation state. |
| Bundle → runner | Read-only benchmark and policy | Runner edits to inputs, gates, dependencies, or target definition. |
| Runner → provider broker | Approved prompts and model calls | General web access, credential disclosure, unrecorded provider use, or unbounded cost. |
| Runner → verifier | Patch and auditable outputs | Runner build cache, Git history, private mounts, or self-authored acceptance policy. |
| Verifier → collector | Verdict, logs, hashes, measurements | Mutable/rewriteable provenance records or unreviewed result substitution. |

Containment must assume that an agent will use any visible channel that helps it succeed.  Restricting a prompt is not a trust boundary.  A failed gate should preserve the patch and rejection evidence for analysis, then discard the candidate workspace before the next independent attempt.  This also reduces cross-attempt leakage and makes fresh-context experiments meaningful.

## Repository and artifact responsibilities

The following layout is a proposed destination, not a claim about the current tree:

```text
docs/                 # scope, protocol, architecture, decisions
experiment/
  manifests/          # reviewed experiment-condition definitions
  schemas/            # bundle, receipt, verdict, and run-index schemas
harness/
  builder/            # deterministic bundle construction
  runner/             # sandbox launch and provider broker integration
  gates/              # read-only acceptance checks
  verifier/           # fresh replay and adequacy checks
tools/                # pinned graph/extraction wrappers and audits
runs/
  index/              # small hash-linked summaries; not full transcripts
```

The existing `harness/` and `.verilib/` material, together with the driver's run-time ledger format, can be migrated or wrapped incrementally.  It is important not to infer that every future run belongs in Git: the authoritative full artifacts should be external, content-addressed records; Git should point at them and define how colleagues reproduce the verdict.

## Open architecture decisions

1. **Isolation technology:** OCI/container, microVM, remote ephemeral worker, or a combination; what evidence makes its network and filesystem controls reviewable?
2. **Execution placement and funding:** institutional cluster, dedicated API/project account, self-hosted CI runners, or another governed service.  The protocol needs a named budget owner and a cost ceiling; it should not presume a contributor's personal subscription.
3. **Bundle granularity:** one bundle per seed set, target, module, or campaign; and which caches, if any, may be shared without contaminating a trial?
4. **Aeneas boundary:** should agents receive already extracted Lean, Rust plus a deterministic extraction command, or both as separate benchmark arms?
5. **Top-level and seed policy:** which graph extrema qualify for `T`, which `S ⊆ T` is supplied per run, and how are public APIs, traits, generated helpers, and external primitives classified?
6. **Support, Math, and reference budget:** should closure be `seed-elaboration-only` or `universe-vocabulary`, and which definitions, theorems, comments, axioms, or existing specifications are legitimate trusted inputs for each named condition?
7. **Provider interface:** what model APIs, logging, retention, redaction, and reproducibility guarantees are required of the egress broker?
8. **Artifact governance:** where are raw transcripts stored, who can read them, how long are they retained, and which hashes/signatures are sufficient for a PR reviewer to audit a run?

The companion protocol, integrity, evaluation, and decision documents should turn these into explicit choices before results are presented as evidence of autonomous formalisation.
