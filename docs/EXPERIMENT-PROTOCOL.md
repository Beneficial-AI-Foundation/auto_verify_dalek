<!-- generated-by: gsd-doc-writer -->
# Experiment protocol

This document proposes a pre-registered protocol for measuring how far an agent can formalise `curve25519-dalek` in Lean from deliberately limited inputs. It is a design for discussion, not a claim that the repository already enforces every control described below. The objective is repeatable evidence about reconstruction under a declared input budget, rather than an undifferentiated demonstration that happens to compile.

The motivating comparison is [CryptoProver](https://arxiv.org/abs/2608.00965v1). Its reported proof-and-spec setup starts from executable code, high-level contracts, and a fixed trusted library, then has agents recover internal specifications and proofs. Our protocol must make its own inputs, exclusions, and acceptance gates independently inspectable.

## Protocol at a glance

Each scored run follows four stages:

1. **Preflight.** Build a sealed input bundle from pinned source and deterministic analysis outputs; select targets using a checked-in algorithm; record the complete manifest.
2. **Run.** Give fresh, bounded agents only the bundle and the allowed tools. They write candidate specifications and proofs into an untrusted work area.
3. **Verify.** A separate mechanical verifier replays the result from the frozen bundle and evaluates integrity, trust, and build gates. It is the only acceptance authority.
4. **Publish.** Preserve successful and failed manifests, receipts, verdicts, and a minimal reproducibility bundle. Do not silently discard unsuccessful trials.

Human choices belong in the experiment definition before a run begins. A scored run has no interactive human repair, steering, or discretionary change to its inputs, target list, prompts, or acceptance rules.

## Scope and experimental arms

Every result must name one arm. Results from different arms are not pooled into a single success rate.

| Arm | Agent receives | Primary question | Excluded claim |
| --- | --- | --- | --- |
| `P0-proof-recovery` | Frozen Lean code and already-fixed statements for a selected set of holes | Can agents recover proofs under the declared trust policy? | It does not measure specification synthesis. |
| `S1-top-level-to-internal-spec` | Executable/extracted code, selected top-level contracts, and the declared Math budget | Can agents propose, review, freeze, and prove sufficient internal contracts? | A compiling result alone does not establish that a generated contract is adequate. |
| `R2-rust-to-lean` (optional) | Pinned Rust source plus the explicitly permitted translation/extraction artifacts | Can the pipeline reach the Lean target with less supplied Lean code? | It must not be compared directly with `P0` or `S1` without accounting for the extra translation task. |

Start with a small, published target slice before a whole-crate campaign. An arm must state whether it covers only selected specifications, all task holes in a module, or the entire crate.

## Frozen source, extraction, and target selection

### Extract before the scored run

Run source analysis outside the scored agent environment. Extraction is infrastructure, not an agent capability, and moving it out of the run makes target discovery deterministic and avoids giving the agent incidental network, compiler-cache, or repository access.

The preflight bundle must pin and hash:

- the `curve25519-dalek` source revision and all Lean/Aeneas dependencies;
- the source and revision of `probe-rust`, `probe-aeneas`, Charon/Aeneas, Lean, Lake, and any wrappers;
- command-line options, configuration files, environment-relevant settings, and tool output schemas;
- the Rust call graph, cross-language facts, Aeneas function-mapping artifact, and any permitted translation artifacts;
- the extracted Lean code given to agents, if applicable; and
- the target-selection program and its output.

`probe-rust` can emit the pinned Rust call graph and optional Charon data. `probe-aeneas` can join Rust, Lean, the Aeneas function mapping, and optional translation facts. Preflight must explicitly test that probe-lean's `defaultTargets` configuration has not silently omitted the Aeneas library or other intended inputs.

### Define “top-level” mechanically

“Top-level” is ambiguous: a graph sink, a public API entry point, a trait method, and a function not called by another specified function are different concepts. The repository currently has 94 graph-derived candidates among 263 specifications in `.verilib/top_level_specs.json`; its current convention is graph sinks among specified functions, and the command that generated the selection is not checked in. That is useful exploratory data, but not yet a reproducible protocol.

Before scoring, add a checked-in selection pipeline that consumes the pinned probe facts and emits a versioned target-set JSON artifact plus a human-readable report. Its algorithm must specify:

1. which edge relation is used (Rust call graph, Lean call graph, cross-language relation, or a defined combination);
2. whether reachability is direct or transitive and how unresolved/dynamic/external calls are handled;
3. how visibility and crate public API status are determined;
4. whether trait declarations and implementations are targets, support obligations, or excluded; and
5. how generated code, unsupported constructs, and dependency boundaries are treated.

The report must classify every candidate as one of:

- **public API** — intended externally visible operation;
- **trait method** — declaration or implementation, with its dispatch relation recorded;
- **internal helper** — non-public implementation support;
- **trusted external** — an explicitly supplied dependency, primitive, or axiom boundary; or
- **excluded** — with a machine-readable reason.

Manual inclusions, exclusions, and category corrections are permitted only through a reviewed exceptions file. Each exception needs an identifier, rationale, author/reviewer, date, and the target-selection output hash it modifies. The publication must show both raw output and post-exception output.

## Declared input budgets

The supplied mathematical layer is a treatment variable, not incidental setup. Do not mix different levels of prior formalisation into one headline result.

| Budget | Permitted mathematical input | Intended interpretation |
| --- | --- | --- |
| `M0-minimal` | Mathlib plus only the domain/type definitions required to state and type-check the task | Feasibility floor with the least project-specific guidance; it may be impractical. |
| `M1-vocabulary` | `M0` plus a fixed project definition and specification vocabulary, but no project theorem/axiom statements, proof bodies, or strategy comments except an explicit allowlist | Tests whether the agent can discover the mathematical interfaces as well as the proof structure. |
| `M2-fixed-statements` | `M1` plus a reviewed set of lemma and assumption statements, with their proof bodies and strategy comments hidden | Measures proof/spec recovery relative to a declared trusted mathematical interface. |
| `M3-reference-assisted` | `M2` plus the full allowed BAIF Math layer and any explicitly listed guidance | Productivity baseline with substantial reference assistance; it is not a clean-room condition. |

For each budget, record every visible file, declaration, line count, byte count, approximate prompt-token count, and whether comments, proof bodies, theorem names, source locations, and natural-language explanations are visible. “Definitions only” must be operationally specified: a theorem statement or revealing identifier can itself be a material clue. Hidden target proof bodies and any undeclared full solution repository are never mounted in a scored environment; any Math proof bodies visible in `M3` are declared treatment inputs rather than hidden assistance.

## Agent workflow and context discipline

Use FVS as a source of role separation and prompt ideas, not as the authority that decides correctness. The current FVS prompts in the companion Lean verification project are interactive; both their text and their role design are experimental inputs and must be revision-pinned, hashed, and disclosed.

For `S1`, use this bounded workflow for each target or coherent target batch:

1. A **fresh spec writer** proposes an internal statement and records its rationale and dependencies.
2. A **fresh, independent spec reviewer** examines the proposal against only the permitted bundle and reports accept/revise/reject. It does not see hidden human reference statements.
3. At most three writer/reviewer revise-review cycles are allowed. On acceptance, canonicalise and freeze the statement. On exhaustion, apply the pre-registered outcome (`reject` or `defer`); a prover may receive a statement only if the last recorded reviewer verdict accepted that exact canonical statement.
4. **Fresh prover workers** receive frozen statements only. They may not relax, replace, or accept the statements they are asked to prove.
5. A **mechanical verifier** outside every agent's write scope performs the final decision.

Run at least one baseline without this role workflow and one FVS-inspired workflow with identical source, targets, budget, model family, and acceptance gates. This ablation distinguishes any benefit of role separation from changes in input privilege. Fresh contexts at role boundaries and after defined failure plateaus help limit context accumulation; their reset policy must be recorded, not improvised.

## Repetitions, budgets, and stopping rules

The pre-registration for an experiment family must declare:

- model provider, model identifier/version or snapshot, API/tool version, temperature, seed where supported, context window, and reasoning/tool settings;
- number of independent repetitions per arm, with independent sealed workspaces and fresh agent sessions;
- per-target and per-run caps for wall time, provider spend, input/output tokens, tool calls, retries, and reviewer cycles;
- a fixed target order or a pre-registered randomisation seed;
- the policy for transient infrastructure failure, rate limits, and verifier failures;
- stopping conditions, including whether a target failure stops a batch or simply records an incomplete target; and
- what is held constant when comparing arms.

Use at least three independent runs for any comparative conclusion when resources permit. A single demonstration run may be published as a case study, but must not be described as a success rate or robust capability estimate. Report all attempted runs within the declared budget, including aborts, integrity-gate failures, and runs with no proof progress.

Compute is governed rather than assumed. The run manifest must identify the authorised execution environment and budget owner (for example, a funded API project, institutional runner, or approved CI/self-hosted capacity), the maximum approved spend, and the mechanism that records provider usage. No personal subscription, credential, or unmetered local account is an implicit requirement of the protocol.

## Preflight checklist

Preflight produces an immutable experiment bundle and refuses to start if any required item is missing.

- Pin source/tool/model/prompt revisions and build the bundle from a clean checkout.
- Run and archive deterministic extraction and target selection.
- Validate target categories, exception file, and selected target hashes.
- Materialise the chosen Math budget and an explicit allow-list of agent-writable paths.
- Exclude `.git`, host caches, sibling solution repositories, reference proof bodies, credentials, and network-capable helper tools from the agent environment.
- Freeze verifier code, toolchain, gate configuration, and the baseline trust inventory.
- Build a dry-run bundle and independently verify that it has only the declared readable inputs.

The sealed bundle is the input to all repetitions of an arm; changing it creates a new experiment identifier.

## Run and verification procedure

During a run, collect transcripts, commands, edits, provider-usage records, and environment receipts without giving agents write access to the collector or verifier. Workers operate in isolated workspaces; parallel workers must not share mutable compiler caches, git object stores, or work directories.

Verification runs from a fresh copy of the sealed bundle plus the candidate patch. At minimum it must:

1. rebuild the selected Lean project and required whole-crate target from scratch;
2. check that task `sorry` obligations decreased or vanished according to the arm's declared target set;
3. compare frozen source, statements, prompts, toolchain, and allowed-input hashes to the manifest;
4. compare the trust closure to the baseline and reject undeclared axioms or trust-expanding mechanisms; and
5. apply the declared forbidden-construct and sandbox-integrity policies.

The verifier produces a pass/fail verdict per target and per run plus a reason code. It must be runnable by reviewers without provider credentials.

## Per-run manifest

Store a signed or content-addressed JSON manifest with every run. It should include:

- experiment, arm, run, target-batch, and repetition identifiers;
- source revisions and hashes; extraction, target-selection, exception, and bundle hashes;
- target categories and canonical statement hashes;
- Math budget and complete allowed-input inventory with visibility flags and size/token measures;
- agent roles, prompt/template hashes, model/configuration, seeds, session-reset events, and worker topology;
- compute authorisation, budget caps, measured spend/tokens/time, and provider-usage receipt references;
- sandbox/image/toolchain/verifier/gate hashes and read/write mount inventory;
- transcript, command, patch, build-log, and artifact hashes or access-controlled references;
- verifier verdicts, trust deltas, remaining obligations, failure reason codes, and retry history; and
- publication status, retention policy, and any approved deviation from the protocol.

Secrets never belong in a manifest or transcript. Artifact references may be access-controlled, but their hashes and the reason for any non-public material must still be published.

## Publication and deviations

Publish the protocol, target-selection program, prompts, budget declaration, verifier/gate source, aggregate results, and a manifest index before making broad capability claims. For each accepted run, publish enough non-secret artifacts for an independent reviewer to reconstruct the bundle and replay verification. For failures, publish at least the manifest, reason codes, cost/time totals, and redacted evidence needed to distinguish an ordinary proof failure from an integrity or infrastructure failure.

Any human intervention, new lemma, altered target list, changed model, changed prompt, relaxed gate, or changed Math budget after preflight is a protocol deviation. It must create a new run or arm identifier and be reported beside—not merged into—the original results.

## Open protocol decisions

- Which exact graph convention should define the first public target set, and is the present graph-sink set useful as an exploratory comparison arm?
- What is the minimum viable `M0` domain/type definition set for a non-vacuous Curve25519 task?
- Which whole-crate build target is practical and sufficiently strong for the first slice?
- Which funded compute environment can provide isolated, metered, auditable runs without relying on personal subscriptions?
- Should `R2-rust-to-lean` begin only after `P0` and `S1` are stable, or run as a separately budgeted pilot?
