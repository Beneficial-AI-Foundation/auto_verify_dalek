# Project Overview

### 1. Dataset (the benchmark snapshot)

**`Curve25519Dalek/`** — removed all proofs.
What still remains? Shall we remove math?

only the math defintion for the top-level funcs

### 2. Top-level API identification

- **api-top** .verilib/api_top_specs.md functions can be called from API

removed functions that cannot be processed by Aeneas

use probe-tools (probe-aeneas, ) do double check

### 3. Harness

initial implementaion, still messy

lang-graph
https://github.com/mattpocock/sandcastle
container

### 4. Experiments

- **`experiments/spec_budget_curve/slice_scalar/`** — the first resynth
  slice (scalar module): manifest plus archived reference originals.
- The overall protocol ladder (`docs/EXPERIMENT-PROTOCOL.md`):
  `P0-proof-recovery` (statements given, fill proofs) →
  `S1-all-top-level` (all top-level specs given, recover internals) →
  `S2-seed-recovery` (only a seed `S ⊆ T` given, recover `W = T \ S`) →
  `R2-rust-to-lean` (start from Rust, include Aeneas extraction).

### 5. network blocking
.claude/settings-offline.json
use this configuration when running experiments
`claude -p`