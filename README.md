<p align="center">
<img
 alt="dalek-cryptography logo"
 width="160px"
 src="https://cdn.jsdelivr.net/gh/dalek-cryptography/curve25519-dalek/docs/assets/dalek-logo-clear.png"/>
</p>

> AutoFV pipeline work is documented in
> [`autofv/README.md`](autofv/README.md). A matching
> [`autofv/README.html`](autofv/README.html) is available for HTML preview.

# dalek-lean benchmark — no-proofs snapshot

This repository is a **benchmark snapshot** of the
[curve25519-dalek-lean-verify](https://github.com/Beneficial-AI-Foundation/curve25519-dalek-lean-verify)
project in which **every proof has been replaced by `sorry`**.

It is a complete, self-contained Lake project: the formal statements (theorem
signatures, definitions, the Aeneas-generated Rust translation, and all
supporting math) are preserved exactly, while each proof body is stubbed out.
The task for a model or human is to **fill the proofs back in** so the project
builds with no `sorry` and no errors.

---

## What this is

The underlying project formally verifies
[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) — a
widely-used Rust implementation of elliptic curve cryptography — in Lean 4. Rust
is translated to Lean with [Aeneas](https://github.com/AeneasVerif/aeneas), and
specifications are proven against that translation.

This snapshot was taken from the upstream project and then mechanically
processed so that all theorem and lemma proofs are `sorry`. Everything else —
the formal statements themselves — is left intact, so the benchmark measures
exactly one thing: **can the proofs be recovered?**

| Field | Value |
|---|---|
| Source repo | https://github.com/Beneficial-AI-Foundation/curve25519-dalek-lean-verify |
| Source commit | `313600244d62b31bad4f08abb2a9705fe75d5585` (`master`) |
| Lean toolchain | `leanprover/lean4:v4.28.0-rc1` |
| Total `sorry`s | 1062 |
| Unique goal states | 349 |
| Files containing `sorry` | 138 |

(See `source_metadata.json` for provenance and `sorries_summary.json` for the
full per-file breakdown.)

---

## How a proof is stubbed

Each proof body is replaced with `sorry`; the statement is untouched:

```lean
-- original
theorem add_comm (a b : Nat) : a + b = b + a := by
  induction a with ...

-- in this snapshot
theorem add_comm (a b : Nat) : a + b = b + a := by
  sorry
```

The goal is to replace every `sorry` with a real proof while keeping the
statements exactly as written.

---

## Repository layout

```
.
├── Curve25519Dalek/
│   ├── Funs.lean            # Auto-generated Lean translation of Rust (Aeneas output)
│   ├── Types.lean           # Auto-generated type definitions
│   ├── Specs/               # Formal specifications (one subtree per Rust module)
│   ├── Math/                # Supporting math: Edwards, Montgomery, Ristretto, BitList
│   ├── Aux.lean             # Shared auxiliary lemmas
│   └── Tactics.lean         # Custom Lean tactics
├── Utils/                   # Build/status tooling (listfuns, syncstatus, ...)
├── lakefile.toml            # Lake project (deps: aeneas, PrimeCert, mathlib)
├── lean-toolchain           # Pinned Lean version
├── lake-manifest.json       # Pinned dependency revisions
├── sorries.jsonl            # One record per sorry (elaborated goal state + location)
├── sorries_summary.json     # Total count, unique goal hashes, per-file breakdown
└── source_metadata.json     # Upstream commit / branch / remote provenance
```

---

## `sorries.jsonl` schema

Each line records one `sorry`, including the **elaborated goal state** as Lean
sees it (not just the source text). Each sorry has a stable content-based id:
the first 16 hex chars of `sha256(goal_string)`, so the same goal keeps the same
id across refactors.

```jsonc
{
  "id":           "a3f1b2c4d5e6f789",   // first 16 hex chars of sha256(goal)
  "file":         "Curve25519Dalek/Aux.lean",
  "lean_version": "v4.28.0-rc1",
  "location": {
    "start_line": 42, "start_column": 4,
    "end_line":   42, "end_column":   9
  },
  "goal": "⊢ a + b = b + a"
}
```

---

## Quick start

```bash
# Lean 4 / Lake (version pinned in lean-toolchain)
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

# Build all dependencies (mathlib, aeneas, PrimeCert) — slow on first run
lake build
```

A fresh checkout builds successfully because `sorry` is accepted (with warnings).
The benchmark is "solved" when `lake build` reports **no `sorry` warnings and no
errors**.

---

## Dependencies

| Dependency | Role |
|---|---|
| Lean 4 (`lean-toolchain`) | Proof checker and build system |
| [Aeneas](https://github.com/AeneasVerif/aeneas) | Rust → Lean extraction (Lean package) |
| [Mathlib](https://github.com/leanprover-community/mathlib4) | Mathematical library |
| [PrimeCert](https://github.com/oliver-butterley/PrimeCert) | Cryptographic certificates |

---

## Underlying verification project

This benchmark is built on top of the
[curve25519-dalek Lean verification project](https://github.com/Beneficial-AI-Foundation/curve25519-dalek-lean-verify),
maintained by Oliver Butterley and
[The Beneficial AI Foundation](https://www.beneficialaifoundation.org/). That
project uses Aeneas to translate Rust to Lean 4 and follows the Aeneas WP
(weakest-precondition) style for specifications.

---

## License

The Lean verification code is licensed under the Apache License 2.0.

The `curve25519-dalek` Rust source is dual-licensed under Apache 2.0 or MIT.
