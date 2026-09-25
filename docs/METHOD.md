# Method

## Goal

How much of the Lean specification of `curve25519-dalek` can an agent write
instead of a human, without weakening any guarantee?

- `T`: the top-level functions, each with a human-written spec.
- `S ⊆ T`: the specs we give the agent.
- `W = T \ S`: the specs the agent must recover.

The agent recovers `W`, writes internal specs, and fills proofs. A build alone
cannot establish that a recovered specification says the right thing; a
separate quality check against the reference is required.

## Top-level functions

For the selected `T`, a function is **lean-top** when no other extracted
function depends on it. The checked-in
[lean-top list](../.verilib/top_level_funs.json) contains 134 of 338 extracted
function candidates. It does not describe every public API; see
[DEC-04](DECISIONS.md) for the edge rules and the separate API catalogue.

## Freeze the top, prove from the leaves

```
frozen    top-level specs (S)      Specs/**/*_spec for T
mutable   internal specs           Scalar52, FieldElement51, CurveModels, ...
mutable   proofs
frozen    code                     Funs.lean, Types.lean, Math/
```

The middle is squeezed. An internal spec that is too weak cannot support the
top; one that is false cannot be proved against the code. So the gates only
hold the two ends: statement fingerprints for `S`, file hashes for the code,
and an axiom whitelist plus `sorry` accounting everywhere.

Prove bottom-up. Leaves are functions that call nothing else (limb arithmetic,
constants). Their specs are true or false, never "weak", and their proofs are
computation. Each higher proof consumes lower specs through `@[progress]`, so
lower specs must be settled first.

```
Scalar52.montgomery_mul_spec ─┐
Scalar52.as_montgomery_spec ──┼─▶ Scalar52.invert_spec ──▶ Scalar.invert_spec (T)
Scalar52.from_montgomery_spec ┘
```