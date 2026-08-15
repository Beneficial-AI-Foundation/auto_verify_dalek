<!-- generated-by: gsd-doc-writer -->
# Auto-verifying curve25519-dalek: architecture discussion

These documents scope a proposed research control plane for automatically
formalising `curve25519-dalek` in Lean from deliberately limited high-level
specifications. They are written to support architecture review in this
repository's pull requests; no choice becomes policy merely because it appears
on this branch.

The motivating reference is the [CryptoProver paper](https://arxiv.org/abs/2608.00965v1).
This project asks a related but more explicitly measured question: what inputs,
trusted mathematics, agent workflow, isolation evidence, and acceptance gates
are needed for a credible curve25519-dalek experiment?

## Read this first: the honesty boundary

Runtime retrieval can be constrained and evidenced: a scored agent can be
given a sealed input bundle with no access to solution repositories, Git
history, sibling checkouts, ordinary network egress, or mutable verification
logic. That does **not** prove that a hosted model lacks pretraining knowledge
of public solutions such as `dalek-lite` or
`curve25519-dalek-lean-verify`. Runtime isolation and training-data
contamination are different threats. The former can be tested; the latter must
be disclosed, mitigated with suitable holdouts where possible, and never
overclaimed as clean-room novelty.

This is a first-order issue for the motivating comparison: the paper cites a
public BAIF `dalek-lite` pull request that predates the artifact's recorded
headline run. [Isolation and integrity](ISOLATION-AND-INTEGRITY.md#why-the-public-solution-chronology-matters)
records the primary links, the controls the paper reports, and what remains
unprovable. The chronology motivates stronger evidence; it is not an allegation
that the paper's authors or model retrieved the solution.

## Documents and the questions they answer

| Document | Primary question |
| --- | --- |
| [Project scope](PROJECT-SCOPE.md) | What claim are we trying to test, what is out of scope, and what belongs in the repository versus a run artifact? |
| [Architecture](ARCHITECTURE.md) | What control-plane, runner, verifier, and artifact boundaries should a scoreable system have? |
| [Experiment protocol](EXPERIMENT-PROTOCOL.md) | What does an experimental arm receive, how are targets derived, and how should the agent roles and bounded review loops work? |
| [Isolation and integrity](ISOLATION-AND-INTEGRITY.md) | How do we defend against retrieval, Git/object-store leakage, harness tampering, Lean escape hatches, and pretraining contamination? |
| [Evaluation](EVALUATION.md) | What counts as progress or success, and which mechanical gates, trust checks, and replay evidence are required? |
| [Decision register](DECISIONS.md) | Which choices remain open, what is provisionally recommended, and what needs a recorded PR decision? |

## Recommended PR review order

1. Read [Project scope](PROJECT-SCOPE.md) to agree on the claim and deliverable.
2. Read the [decision register](DECISIONS.md) and comment first on the decisions that constrain every run: repository boundary, input budget, isolation claim, and success definition.
3. Review [Architecture](ARCHITECTURE.md) and [Isolation and integrity](ISOLATION-AND-INTEGRITY.md) together; a runner is not scoreable if the verifier or its inputs remain agent-writable.
4. Review [Experiment protocol](EXPERIMENT-PROTOCOL.md) for deterministic target selection, experimental arms, and the proposed bounded agent workflow.
5. Review [Evaluation](EVALUATION.md) last, checking that its gates actually support the claim agreed above.

## Current snapshot, not a scored system

The repository contains useful baseline material, but it is not yet the
proposed experiment platform:

- [`.verilib/sorry_inventory.json`](../.verilib/sorry_inventory.json) identifies **347 task declarations with `sorry`** (318 in `Specs` and 29 auxiliary declarations), separate from frozen mathematical assumptions and dependency/external-spec zones.
- [`.verilib/top_level_specs.json`](../.verilib/top_level_specs.json) records **94 prototype graph-derived top-level candidates among 263 specifications**. Its selection method is exploratory; the generating pipeline is not yet checked in as a reproducible protocol.
- [`harness/driver.py`](../harness/driver.py) and its gates are a useful prototype for per-goal work, build checks, and trust accounting. They are **not** a scoreable OS-level sandbox or an independently replayed verifier.

These facts define a starting point for a first experiment slice; they do not
establish that any target has been automatically formalised.

## How to make PR discussion durable

Use stable IDs from [DECISIONS.md](DECISIONS.md) in review comments—for
example, `DEC-06: prefer the sealed-bundle proposal, with this change`. Add a
new ID rather than folding a distinct question into an existing decision.

Only change an item to **ACCEPTED**, **REJECTED**, or **SUPERSEDED** when the
entry links to the decision-making PR, issue, or recorded meeting outcome and
names the resulting policy/version. Until then, retain **OPEN** or
**PROPOSED**. A future run manifest should cite those resolved IDs rather than
relying on prose or reviewer memory.

## Proposed next step

Resolve the decision register before implementing a new runner or publishing a
scored result. The first implementation milestone should then turn the agreed
inputs, isolation boundary, target-selection algorithm, and acceptance gates
into versioned, replayable artifacts.
