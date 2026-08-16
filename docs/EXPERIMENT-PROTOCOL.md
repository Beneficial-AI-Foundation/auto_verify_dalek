# Experiment protocol

This is a draft protocol for discussion. A scored run must follow a fixed JSON
file and must not receive human help after it starts.

## Experiment types

| Name | Starting point | Question |
| --- | --- | --- |
| `P0-proof-recovery` | Statements are given. | Can the agents prove them? |
| `S1-all-top-level` | All specifications in `T` are given. | Can the agents recover internal specifications and proofs? |
| `S2-seed-recovery` | Only `S ⊆ T` is given. | Can the agents recover `W = T \ S` and complete the project? |
| `R2-rust-to-lean` | Start from Rust and an Aeneas pipeline. | Can the experiment also cover translation? |

Use a small slice while building the harness. A successful `S2` research run
must later cover the whole declared project, not only the seed.

## Selecting `T`

The top-level list must come from a checked-in deterministic script using
pinned `probe-rust`, `probe-aeneas`, or equivalent data.

Use `A → B` to mean “A calls B.” The current exploratory rule selects a
specified function when no other specified function can reach it, including
paths through helpers without specifications.

The current result is 94 targets from 263 specifications: 38 `api` and 56
`trait-instance`. Any manual exception must be recorded in a small reviewed
file.

## Seed JSON

Each `S2` run starts from a JSON file like this:

```json
{
  "schema_version": 1,
  "top_level_set": "sha256:<hash>",
  "allowed_spec_ids": ["<spec-id>"],
  "lean_body_for_missing_targets": true,
  "compile_support": "seed-only",
  "math_input": "minimal",
  "builder_revision": "<commit>"
}
```

The builder checks that every ID belongs to `T`, computes `W`, gathers the
required definitions, and records the final bundle hash. The Rust function name
for every target in `W` is always visible. The JSON decides whether its Lean
body is visible too.

The original statements and proofs for `W` must not appear in the agent bundle.
They may be kept in separate reference data for the final check.

## Compile support and Math input

Two kinds of input must be listed separately:

- **Compile support:** imports, types, structures, notation, and definitions
  required for the starting files to compile.
- **Math input:** lemmas, assumptions, comments, and other facts that may help
  the agents solve the task.

The first experiment should include only the compile support required by `S`.
A second, easier mode may also include definitions needed to state every target
in `T`. Neither mode should silently include helpful lemmas or the missing
reference specifications.

## Run steps

### 1. Prepare

- Pin source, tool, prompt, model, and checker versions.
- Generate `T`, read `S`, and compute `W`.
- Build the agent bundle and hidden reference data separately.
- Record time, token, cost, and retry limits.
- Check that the bundle contains no Git history, credentials, caches, or known
  solution files.

### 2. Run agents

For specification work, the proposed loop is:

1. a fresh writer proposes a statement;
2. a fresh reviewer accepts it or asks for changes;
3. stop after the fixed number of review rounds;
4. freeze an accepted statement; and
5. give the frozen statement to fresh prover agents.

Specifications in `S` are frozen from the start. Generated specifications in
`W` become frozen only after review. The final verifier is not an agent and is
not editable by them.

### 3. Verify

From a fresh workspace:

- build the whole declared Lean target;
- check that all required `sorry`s are gone;
- check that every member of `T` has a specification and proof;
- compare all frozen files and statements with the manifest;
- reject new axioms, unsafe shortcuts, or out-of-scope edits; and
- run the quality checks for generated specifications.

### 4. Record

Keep every attempted run, including failures. Record at least:

- `T`, `S`, and `W`;
- all input and tool hashes;
- model, prompts, limits, and agent roles;
- build and checker results;
- remaining tasks and reasons for failure;
- time, tokens, and cost; and
- links and hashes for the patch, transcript, and logs.

## Comparing runs

Compare models or workflows directly only when they use the same `T`, `S`,
inputs, limits, and checks.

Runs with different seeds answer a different question. Report them as a seed
size experiment, not as equal tasks.

There are `2^94` possible subsets of the current target list, so we cannot test
all of them. A practical search can:

1. prove the `S = T` baseline works;
2. remove one module or group at a time;
3. test smaller fixed fractions; and
4. repeatedly retest the smallest successful seeds.

Do not call the result a global minimum. Call it the **smallest validated seed
found**, and state the search method and number of successful repeats.

The unresolved choices are in [DECISIONS.md](DECISIONS.md).
