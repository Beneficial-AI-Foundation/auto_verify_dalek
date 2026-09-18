# Top-spec proving runs on `dalek-top-spec-only`

Results of `harness/prove_top_spec.py`: one top-level spec theorem of the
agent bundle per run, same agent loop and gates as `harness/driver.py`
(G2 skipped — the bundle has no trust-base manifests). Raw records:
`ledger/top_spec_rounds.jsonl`; transcripts `ledger/transcripts/topspec_*`.

## Bundle state (2026-09-16)

- 57 kept top spec theorems, all `sorry`; 144 sorry declarations in 67 files
  (includes stubs and Math assumptions).
- Math/ minimized to 128 of 447 declarations ([MINIMAL-MATH.md](MINIMAL-MATH.md)).
- Candidates ranked by dependency closure of the statement (in-package
  declarations, from the bundle probe). Smallest first:

| closure | Funs | Math | theorem |
|---|---|---|---|
| 2 | 1 | 0 | `backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq_spec` |
| 2 | 1 | 0 | `montgomery.MontgomeryPoint.as_bytes_spec` |
| 2 | 1 | 0 | `montgomery.MontgomeryPoint.to_bytes_spec` |
| 2 | 1 | 0 | `ristretto.CompressedRistretto.to_bytes_spec` |
| 3 | 1 | 1 | `montgomery.MontgomeryPoint.Insts.Curve25519_dalekTraitsIdentity.identity_spec` |
| 3 | 1 | 0 | `scalar.Scalar.to_bytes_spec` |
| 4 | 1 | 1 | `scalar.Scalar.Insts.CoreConvertFromU{8,16,32,64,128}.from_spec` (5) |
| 7 | 4 | 2 | `backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithSubAssignSharedAFieldElement51.sub_assign_spec` |
| 8 | 4 | 3 | `backend.serial.u64.field.FieldElement51.as_bytes_spec` |

Full list: `python3 harness/prove_top_spec.py --list`.

## Internal specs needed per top spec (2026-09-18)

The closure column above counts every in-package declaration in the
statement, including types and projections. A second ranking counts what an
agent would actually have to *write*: the internal `Funs.lean` functions the
target function transitively calls, each of which needs its own `@[progress]`
spec because the bundle strips all internal specs (stub files are empty).
Computed by `harness/internal_spec_stats.py` from the full-repo probe
(`.verilib/probes/lean_Curve25519Dalek_0.1.0.json`), following
`dependencies` from the target function through `Funs.lean` definitions.

Excluded from the count:

- **Trait-impl instance records** (`@[rust_trait_impl]`, e.g.
  `U8.Insts.SubtleConditionallySelectable`). These are dictionaries bundling
  method functions, `@[reducible]`, no `Result`, no pre/postcondition; callers
  project the concrete method out of them. None of the 208 instance records
  in the full repo has a spec.
- **`FunsExternal.lean` functions** (hand-written models of `subtle`,
  `zeroize`, ...). Their `@[progress]` specs ship with the bundle as
  sorry-assumptions, so the agent uses them and never writes them.

`never_specd` = callees that have no `@[progress]` theorem anywhere in the
full repo, i.e. no human reference spec exists; the agent would have to
design the statement from scratch. Zero for every target with ≤ 9 callees.

| internal specs | top spec target | internal callees |
|---|---|---|
| 0 | `AffineNielsPoint...assert_receiver_is_total_eq`, `MontgomeryPoint.{identity, conditional_select, as_bytes, to_bytes}`, `CompressedRistretto.to_bytes`, `Scalar.to_bytes`, `Scalar.Insts.CoreConvertFromU{8,16,32,64,128}.from` (12) | none; unfold only |
| 1 | `AffineNielsPoint...conditional_select`, `AffinePoint...conditional_select`, `montgomery.ProjectivePoint...conditional_select` | `FieldElement51...conditional_select` |
| 1 | `AffineNielsPoint...conditional_assign` | `FieldElement51...conditional_assign` |
| 1 | `CompressedEdwardsY...ct_eq` | `CompressedEdwardsY.as_bytes` |
| 1 | `CompressedRistretto...ct_eq` | `CompressedRistretto.as_bytes` |
| 1 | `Scalar...CoreCmpPartialEqScalar.eq` | `Scalar...SubtleConstantTimeEq.ct_eq` |
| 2 | `RistrettoPoint...conditional_select` | `FieldElement51...conditional_select`, `EdwardsPoint...conditional_select` |
| 3 | `IdentityCurveModelsProjectivePoint.identity` | `FieldElement51.{ONE, ZERO, from_limbs}` |
| 3 | `FieldElement51...sub_assign` | `FieldElement51.sub`, `FieldElement51.reduce`, `reduce.LOW_51_BIT_MASK` |
| 3 | `FieldElement51.as_bytes` | `FieldElement51.reduce`, `reduce.LOW_51_BIT_MASK`, `FieldElement51.to_bytes` |
| 5 | `AffineNielsPoint...eq`, `AffinePoint...eq` | |
| 7–9 | `MontgomeryPoint...eq`, `EdwardsPoint...eq`, `RistrettoPoint...eq`, `ProjectivePoint.as_extended`, `EdwardsPoint + AffineNielsPoint` `add`/`sub` | |
| 15–19 | `Scalar52.square` (3 never_specd), `EdwardsPoint.{compress, as_affine_niels, double}` | |
| 21–42 | `Scalar.{neg, mul (4 variants), from_bytes_mod_order, from_bytes_mod_order_wide, from_canonical_bytes, invert}` (5–6 never_specd), `MontgomeryPoint.{mul, mul_clamped, to_edwards}`, `RistrettoPoint.{compress, from_uniform_bytes}`, `CompressedRistretto.decompress`, `elligator_encode`, `EdwardsPoint.is_small_order` | |
| 59–66 | `EdwardsPoint.{mul_clamped, mul_base_clamped, is_torsion_free}`, `MontgomeryPoint.mul_base_clamped`, `RistrettoPoint.mul_base` (24–28 never_specd) | |

Observations:

- `FieldElement51...conditional_select` is the single most reusable internal
  spec: one lemma unlocks four top specs.
- `ONE`, `ZERO`, `LOW_51_BIT_MASK` are constants; their specs are near
  trivial. `FieldElement51.reduce` is the first callee with real limb
  arithmetic, shared by `sub_assign` and `as_bytes`.
- Suggested ladder for the "few internal specs" experiment: 1 spec
  (`AffineNielsPoint...conditional_select`), then 3 (`sub_assign` or
  `as_bytes`), then 8–9 (`as_extended`, `add`/`sub`).

Full table with callee lists: `python3 harness/internal_spec_stats.py [N]`
(N = expand callees for targets with ≤ N internal specs).

## Runs

### 2026-09-16 — `assert_receiver_is_total_eq_spec` — accepted

Smoke test of the pipeline on the smallest target (function body is `ok ()`).

| | |
|---|---|
| model | claude-sonnet-5 (haiku-4-5 also billed, claude's internal use) |
| rounds / turns | 1 / 20 |
| wall | 77 s agent, 3.4 s gate build, 3.0 s G1 |
| cost | $0.24 |
| tokens | 4.7k output, 23k cache write, 505k cache read |
| gates | scope, forbidden-attr, build, G1 statement identity, sorry count: all pass; G2 skipped |
| run dir | `ledger/runs/topspec_2026-09-16T015613+0000` |

Proof accepted and copied into the bundle:

```lean
theorem assert_receiver_is_total_eq_spec
    (self : backend.serial.curve_models.AffineNielsPoint) :
    assert_receiver_is_total_eq self ⦃ result => result = () ⦄ := by
  unfold assert_receiver_is_total_eq
  simp [Aeneas.Std.WP.spec, Aeneas.Std.WP.theta, Aeneas.Std.WP.wp_return]
```

An earlier attempt the same day (run dir `topspec_2026-09-16T015419+0000`,
$0.18, proof `simp [assert_receiver_is_total_eq]`) was rejected by the scope
gate for a harness bug, not an agent fault: the bundle ships no
`.gitignore`, so the slot's sealed baseline tracked `.lake/build` and the
rebuilt `.olean` counted as an out-of-scope edit; the rollback then crashed
decoding the binary. Fixed by writing `.gitignore` (`.lake/`) into the slot
before sealing. No ledger record for that attempt.

## Next

First non-trivial experiment: `scalar.Scalar.to_bytes_spec` (closure 3,
structure eta) or `FieldElement51 ... sub_assign_spec` (closure 7, first
with limb arithmetic and Math lemmas).
