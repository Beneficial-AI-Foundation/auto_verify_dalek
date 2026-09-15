# Minimal Math subset of dalek-top-spec-only

Computed by `harness/build_without_internal_spec.py --minimize-math --math-closure`:
- roots: every declaration outside `Math/` in the bundle (Specs statements, proofs are `sorry`; Aux, TypesAux, Funs, ...)
- edges: exact constant closure from `harness/math_closure.lean` (`.verilib/math_closure.tsv`, run in the built bundle) merged with the probe-lean graph (`.verilib/probes/lean_bundle_Curve25519Dalek_0.1.0.json`); shared `match_N` matchers do not pull in their host definition
- kept regardless: the 11 sorry-assumptions of `harness/frozen/math_assumptions.json`, with their statement closure

Math declarations: 447 total, **134 kept**, 313 removed. `lake build` of the result passes.

| file | kept / total | lines (bundle / repo) |
|---|---|---|
| Math/Basic.lean | 35 / 65 | 222 / 548 |
| Math/BitList.lean | 0 / 60 | 0 / 514  *(dropped)* |
| Math/Edwards/Basepoint.lean | 1 / 4 | 15 / 38 |
| Math/Edwards/Curve.lean | 22 / 48 | 124 / 331 |
| Math/Edwards/EightTorsion.lean | 0 / 6 | 0 / 67  *(dropped)* |
| Math/Edwards/Representation.lean | 13 / 62 | 157 / 523 |
| Math/Montgomery/Curve.lean | 11 / 53 | 88 / 502 |
| Math/Montgomery/Representation.lean | 16 / 89 | 253 / 2487 |
| Math/PrimeCerts.lean | 0 / 2 | 0 / 44  *(dropped)* |
| Math/Ristretto/Representation.lean | 36 / 58 | 245 / 1233 |

Dropped modules: BitList, Edwards.EightTorsion, PrimeCerts

## Kept declarations

### Curve25519Dalek/Math/Basic.lean

- `abbrev` `Edwards.CurveField`
- `def` `Field51_as_Nat`
- `def` `L`
- `def` `Scalar52_as_Nat`
- `def` `U8x32_as_Field`
- `def` `U8x32_as_Nat`
- `def` `U8x64_as_Nat`
- `def` `a`
- `def` `curve25519_dalek.backend.serial.u64.field.FieldElement51.IsValid`
- `instance` `curve25519_dalek.backend.serial.u64.field.FieldElement51.instDecidableIsValid`
- `def` `curve25519_dalek.backend.serial.u64.field.FieldElement51.toField`
- `def` `curve25519_dalek.math.abs_edwards`
- `theorem` `curve25519_dalek.math.abs_edwards_sq`
- `def` `curve25519_dalek.math.inv_sqrt_checked`
- `theorem` `curve25519_dalek.math.inv_sqrt_checked_snd` *(sorry-assumption)*
- `theorem` `curve25519_dalek.math.inv_sqrt_checked_spec` *(sorry-assumption)*
- `theorem` `curve25519_dalek.math.inv_sqrt_checked_sq_mul` *(sorry-assumption)*
- `theorem` `curve25519_dalek.math.inv_sqrt_checked_zero`
- `def` `curve25519_dalek.math.is_negative`
- `theorem` `curve25519_dalek.math.p_sub_one_cast`
- `def` `curve25519_dalek.math.sqrt`
- `def` `curve25519_dalek.math.sqrt_ad_minus_one`
- `def` `curve25519_dalek.math.sqrt_ad_minus_one_val`
- `def` `curve25519_dalek.math.sqrt_checked`
- `theorem` `curve25519_dalek.math.sqrt_checked_iff_isSquare` *(sorry-assumption)*
- `theorem` `curve25519_dalek.math.sqrt_checked_spec` *(sorry-assumption)*
- `def` `curve25519_dalek.math.sqrt_m1`
- `theorem` `curve25519_dalek.math.sqrt_m1_not_square`
- `theorem` `curve25519_dalek.math.sqrt_m1_sq`
- `theorem` `curve25519_dalek.math.sqrt_m1_sq_nat`
- `def` `d`
- `def` `h`
- `theorem` `instFactPrimeL`
- `theorem` `instFactPrimeP`
- `def` `p`

### Curve25519Dalek/Math/Edwards/Basepoint.lean

- `def` `Edwards.basepoint`

### Curve25519Dalek/Math/Edwards/Curve.lean

- `def` `Edwards.Ed25519`
- `theorem` `Edwards.Ed25519.denomsNeZero`
- `structure` `Edwards.EdwardsCurve`
- `projection` `Edwards.EdwardsCurve.a`
- `projection` `Edwards.EdwardsCurve.d`
- `structure` `Edwards.Point`
- `theorem` `Edwards.Point.on_curve`
- `projection` `Edwards.Point.x`
- `projection` `Edwards.Point.y`
- `theorem` `Edwards.add_assoc_Ed25519` *(sorry-assumption)*
- `theorem` `Edwards.add_closure`
- `theorem` `Edwards.add_closure_Ed25519`
- `def` `Edwards.add_coords`
- `theorem` `Edwards.complete_addition_denominators_ne_zero` *(sorry-assumption)*
- `theorem` `Edwards.d_not_square`
- `instance` `Edwards.instAddPointCurveFieldEd25519`
- `instance` `Edwards.instInhabitedPointCurveFieldEd25519`
- `theorem` `Edwards.instNeZeroCurveFieldOfNat`
- `instance` `Edwards.instSMulNatPointCurveFieldEd25519`
- `instance` `Edwards.instZeroPointCurveFieldEd25519`
- `theorem` `Edwards.neg_one_is_square`
- `def` `Edwards.nsmul_Ed25519`

### Curve25519Dalek/Math/Edwards/Representation.lean

- `structure` `curve25519_dalek.edwards.EdwardsPoint.IsValid`
- `theorem` `curve25519_dalek.edwards.EdwardsPoint.IsValid.Z_ne_zero`
- `theorem` `curve25519_dalek.edwards.EdwardsPoint.IsValid.on_curve`
- `instance` `curve25519_dalek.edwards.EdwardsPoint.instDecidableIsValid`
- `theorem` `curve25519_dalek.edwards.EdwardsPoint.isValid_iff`
- `def` `curve25519_dalek.edwards.EdwardsPoint.toPoint`
- `def` `curve25519_dalek.edwards.EdwardsPoint.toPoint'`
- `structure` `curve25519_dalek.edwards.affine.AffinePoint.IsValid`
- `theorem` `curve25519_dalek.edwards.affine.AffinePoint.IsValid.on_curve`
- `instance` `curve25519_dalek.edwards.affine.AffinePoint.instDecidableIsValid`
- `theorem` `curve25519_dalek.edwards.affine.AffinePoint.isValid_iff`
- `def` `curve25519_dalek.edwards.affine.AffinePoint.toPoint`
- `def` `curve25519_dalek.math.decompress_edwards_pure` *(sorry-assumption)*

### Curve25519Dalek/Math/Montgomery/Curve.lean

- `def` `Montgomery.Curve25519.A`
- `abbrev` `Montgomery.CurveField`
- `def` `Montgomery.MontgomeryCurveCurve25519`
- `abbrev` `Montgomery.Point`
- `def` `Montgomery.T_point`
- `def` `Montgomery.get_u`
- `instance` `Montgomery.instDecidableEqCurveField`
- `theorem` `Montgomery.instFactPrimeP`
- `theorem` `Montgomery.instNeZeroCurveFieldOfNat`
- `theorem` `Montgomery.non_singular`
- `theorem` `Montgomery.nonsingular_iff`

### Curve25519Dalek/Math/Montgomery/Representation.lean

- `theorem` `Montgomery.B_d_relation`
- `def` `Montgomery.Curve25519.roots_B`
- `def` `Montgomery.MontgomeryPoint.mkPoint`
- `def` `Montgomery.MontgomeryPoint.u_affine_toPoint`
- `theorem` `Montgomery.a_plus_d`
- `theorem` `Montgomery.a_sub_d`
- `theorem` `Montgomery.adA`
- `theorem` `Montgomery.adB`
- `theorem` `Montgomery.d_eq`
- `def` `Montgomery.fromEdwards`
- `theorem` `Montgomery.montgomery_edwards_inverse`
- `theorem` `Montgomery.nonsingular_on_curves_M`
- `theorem` `Montgomery.on_MontgomeryCurves`
- `theorem` `Montgomery.on_curves_M`
- `theorem` `Montgomery.pow2_roots_B`
- `def` `Montgomery.v_squared`

### Curve25519Dalek/Math/Ristretto/Representation.lean

- `def` `curve25519_dalek.math.a_val`
- `def` `curve25519_dalek.math.compress_den1`
- `def` `curve25519_dalek.math.compress_den2`
- `def` `curve25519_dalek.math.compress_den_inv`
- `def` `curve25519_dalek.math.compress_invsqrt`
- `def` `curve25519_dalek.math.compress_pure`
- `def` `curve25519_dalek.math.compress_rotate`
- `def` `curve25519_dalek.math.compress_s`
- `def` `curve25519_dalek.math.compress_u1`
- `def` `curve25519_dalek.math.compress_u2`
- `def` `curve25519_dalek.math.compress_x_prime`
- `def` `curve25519_dalek.math.compress_y_final`
- `def` `curve25519_dalek.math.compress_y_prime`
- `def` `curve25519_dalek.math.compress_z_inv`
- `theorem` `curve25519_dalek.math.decompress_helper`
- `def` `curve25519_dalek.math.elligator_D`
- `def` `curve25519_dalek.math.elligator_Ns`
- `def` `curve25519_dalek.math.elligator_Nt`
- `def` `curve25519_dalek.math.elligator_c`
- `def` `curve25519_dalek.math.elligator_is_square`
- `def` `curve25519_dalek.math.elligator_r`
- `def` `curve25519_dalek.math.elligator_ratio`
- `def` `curve25519_dalek.math.elligator_ristretto_flavor_pure` *(sorry-assumption)*
- `def` `curve25519_dalek.math.elligator_ristretto_flavor_x`
- `def` `curve25519_dalek.math.elligator_ristretto_flavor_y`
- `def` `curve25519_dalek.math.elligator_s`
- `instance` `curve25519_dalek.math.instDecidableElligatorIsSquare`
- `def` `curve25519_dalek.math.invsqrt_a_minus_d`
- `def` `curve25519_dalek.ristretto.CompressedRistretto.IsValid`
- `def` `curve25519_dalek.ristretto.IsEven`
- `theorem` `curve25519_dalek.ristretto.IsEven_iff_in_doubling_image_right` *(sorry-assumption)*
- `def` `curve25519_dalek.ristretto.RistrettoPoint.IsValid`
- `def` `curve25519_dalek.ristretto.RistrettoPoint.toPoint`
- `def` `curve25519_dalek.ristretto.decompress_pure`
- `def` `curve25519_dalek.ristretto.decompress_step1`
- `def` `curve25519_dalek.ristretto.decompress_step2`
