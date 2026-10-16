# AutoFV documentation

The product goal is a CLI for user-provided Lean repositories with prepared
top-level specs: discover targets, provision the sandbox, run a bounded agent
experiment, independently verify results and export evidence. Dalek is the
current development benchmark, not the intended limit on supported projects.

Start with the [root README](../README.md) and [usage guide](../autofv/USAGE.md)
for current capabilities and missing implementation. Older design pages below
contain historical research assumptions; they do not establish that generic
repository bootstrap, multi-root execution or internet-enabled agents work today.

## Benchmark evidence boundary

The Dalek benchmark keeps known solutions inaccessible to the agent. Its sealed
workspace, restricted network and separate verifier enforce that policy. Future
projects may explicitly allow internet access under a different recorded policy;
that mode is not implemented yet. Neither mode can prove that a hosted model
never saw public solutions during training. See
[Isolation and integrity](ISOLATION-AND-INTEGRITY.md).

## Documents

| Document | Purpose |
| --- | --- |
| [AutoFV usage](../autofv/USAGE.md) | Repo-first user workflow, actual command behavior, missing bootstrap/discovery, single-root limit and future network policies. |
| [Current development recipe](../autofv/DEVELOPMENT-RUN.md) | Existing operator-assisted prepared Dalek launch; not the intended general user interface. |
| [Dalek benchmark snapshot](DALEK-BENCHMARK.md) | Snapshot provenance, layout, Lake build and licensing, moved out of the main product README. |
| [AutoFV controller](../autofv/README.md) | Current implementation, local checks and evidence boundaries, including the distinction between live failed attempts and synthetic fixture success. |
| [Method](METHOD.md) | How `T` is chosen, why top-level specs are frozen before proving bottom-up, and how internal specs are repaired when a proof fails. |
| [Project scope](PROJECT-SCOPE.md) | What we are trying to learn and what counts as success. |
| [Architecture](ARCHITECTURE.md) | The proposed builder, agent runner, verifier, and result storage. |
| [Experiment protocol](EXPERIMENT-PROTOCOL.md) | The inputs and steps for one run. |
| [Evaluation](EVALUATION.md) | How runs are checked and compared. |
| [Isolation and integrity](ISOLATION-AND-INTEGRITY.md) | How we prevent access to known solutions and Lean shortcuts. |
| [Decisions](DECISIONS.md) | Questions to settle in the PR. |

## Dalek research data

- [`.verilib/sorry_inventory.json`](../.verilib/sorry_inventory.json) records
  347 task declarations with `sorry`.
- [`.verilib/top_level_funs.json`](../.verilib/top_level_funs.json) records
  134 lean-top functions among 338 extracted function candidates, selected by
  [`harness/lean_top.py`](../harness/lean_top.py). This is not the public API
  catalogue; see [DEC-04](DECISIONS.md).
- [`harness/driver.py`](../harness/driver.py) and the existing gates are useful
  prototypes, but they are not yet a complete sandbox or independent verifier.
