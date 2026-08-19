# Auto-verifying curve25519-dalek

This folder is for discussing how to automatically formalise
`curve25519-dalek` in Lean. The experiment starts from limited inputs and asks
agents to recover the missing specifications and proofs.

The main idea is:

- `T` is the full set of top-level functions we want to specify;
- `S` is the subset of specifications given to the agents; and
- `W = T \ S` is the set the agents must recover.

A successful run must recover and prove every specification in `W`, prove the
specifications in `S`, and finish the rest of the declared Lean work. Starting
with `S = T` is the easier baseline. Later runs can use smaller seeds to find
the smallest set that still works reliably.

## Important limitation

The agent must not be able to read existing BAIF solutions during a run. We can
test this with a sealed workspace, blocked network access, and a fresh final
check.

We cannot prove that a hosted model never saw public solutions during training.
Results must say this clearly. See [Isolation and integrity](ISOLATION-AND-INTEGRITY.md).

## Documents

| Document | Purpose |
| --- | --- |
| [Project scope](PROJECT-SCOPE.md) | What we are trying to learn and what counts as success. |
| [Architecture](ARCHITECTURE.md) | The proposed builder, agent runner, verifier, and result storage. |
| [Experiment protocol](EXPERIMENT-PROTOCOL.md) | The inputs and steps for one run. |
| [Evaluation](EVALUATION.md) | How runs are checked and compared. |
| [Isolation and integrity](ISOLATION-AND-INTEGRITY.md) | How we prevent access to known solutions and Lean shortcuts. |
| [Decisions](DECISIONS.md) | Questions to settle in the PR. |

## Current facts

- [`.verilib/sorry_inventory.json`](../.verilib/sorry_inventory.json) records
  347 task declarations with `sorry`.
- [`.verilib/top_level_specs.json`](../.verilib/top_level_specs.json) records
  94 top-level candidates among 263 specifications: 38 `api` and 56
  `trait-instance`.
- [`harness/driver.py`](../harness/driver.py) and the existing gates are useful
  prototypes, but they are not yet a complete sandbox or independent verifier.
