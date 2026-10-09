/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aeneas
import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Index

set_option exponentiation.threshold 416

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

attribute [-simp] Int.reducePow Nat.reducePow

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Limb-wise behaviour of `mul_internal`: the `k`-th output limb is the schoolbook
convolution `∑_{i+j=k} a[i] * b[j]`. Requires the limbs to be small enough that the
(at most five) partial products of each column fit in a `u128`. -/
theorem mul_internal_limbs (a b : Scalar52)
    (ha : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 62)
    (hb : ∀ i, i < 5 → (b.val[i]!).val < 2 ^ 62) :
    mul_internal a b ⦃ r =>
      (r.val[0]!).val = (a.val[0]!).val * (b.val[0]!).val ∧
      (r.val[1]!).val = (a.val[0]!).val * (b.val[1]!).val + (a.val[1]!).val * (b.val[0]!).val ∧
      (r.val[2]!).val = (a.val[0]!).val * (b.val[2]!).val + (a.val[1]!).val * (b.val[1]!).val +
        (a.val[2]!).val * (b.val[0]!).val ∧
      (r.val[3]!).val = (a.val[0]!).val * (b.val[3]!).val + (a.val[1]!).val * (b.val[2]!).val +
        (a.val[2]!).val * (b.val[1]!).val + (a.val[3]!).val * (b.val[0]!).val ∧
      (r.val[4]!).val = (a.val[0]!).val * (b.val[4]!).val + (a.val[1]!).val * (b.val[3]!).val +
        (a.val[2]!).val * (b.val[2]!).val + (a.val[3]!).val * (b.val[1]!).val +
        (a.val[4]!).val * (b.val[0]!).val ∧
      (r.val[5]!).val = (a.val[1]!).val * (b.val[4]!).val + (a.val[2]!).val * (b.val[3]!).val +
        (a.val[3]!).val * (b.val[2]!).val + (a.val[4]!).val * (b.val[1]!).val ∧
      (r.val[6]!).val = (a.val[2]!).val * (b.val[4]!).val + (a.val[3]!).val * (b.val[3]!).val +
        (a.val[4]!).val * (b.val[2]!).val ∧
      (r.val[7]!).val = (a.val[3]!).val * (b.val[4]!).val + (a.val[4]!).val * (b.val[3]!).val ∧
      (r.val[8]!).val = (a.val[4]!).val * (b.val[4]!).val ⦄ := by
  have pb : ∀ i j, i < 5 → j < 5 → (a.val[i]!).val * (b.val[j]!).val < 2 ^ 124 := by
    intro i j hi hj
    have := Nat.mul_lt_mul'' (ha i hi) (hb j hj)
    simpa [← pow_add] using this
  have := pb 0 0 (by omega) (by omega); have := pb 0 1 (by omega) (by omega)
  have := pb 0 2 (by omega) (by omega); have := pb 0 3 (by omega) (by omega)
  have := pb 0 4 (by omega) (by omega); have := pb 1 0 (by omega) (by omega)
  have := pb 1 1 (by omega) (by omega); have := pb 1 2 (by omega) (by omega)
  have := pb 1 3 (by omega) (by omega); have := pb 1 4 (by omega) (by omega)
  have := pb 2 0 (by omega) (by omega); have := pb 2 1 (by omega) (by omega)
  have := pb 2 2 (by omega) (by omega); have := pb 2 3 (by omega) (by omega)
  have := pb 2 4 (by omega) (by omega); have := pb 3 0 (by omega) (by omega)
  have := pb 3 1 (by omega) (by omega); have := pb 3 2 (by omega) (by omega)
  have := pb 3 3 (by omega) (by omega); have := pb 3 4 (by omega) (by omega)
  have := pb 4 0 (by omega) (by omega); have := pb 4 1 (by omega) (by omega)
  have := pb 4 2 (by omega) (by omega); have := pb 4 3 (by omega) (by omega)
  have := pb 4 4 (by omega) (by omega)
  clear pb ha hb
  unfold mul_internal
  progress*
  subst_vars
  simp only [Array.set_val_eq, Array.repeat]
  simp [List.replicate, *]

/-- Spec for `Scalar52::mul_internal`: the nine-limb (radix `2^52`) unreduced product
represents `a * b`. Each output limb is below `2^127`; when both inputs have 52-bit limbs
(the usual case, e.g. before `montgomery_reduce`) each output limb is below `2^107`. -/
@[progress]
theorem mul_internal_spec (a b : Scalar52)
    (ha : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 62)
    (hb : ∀ i, i < 5 → (b.val[i]!).val < 2 ^ 62) :
    mul_internal a b ⦃ r =>
      U128x9_as_Nat r = Scalar52_as_Nat a * Scalar52_as_Nat b ∧
      (∀ i, i < 9 → (r.val[i]!).val < 2 ^ 127) ∧
      ((∀ i, i < 5 → (a.val[i]!).val < 2 ^ 52) → (∀ i, i < 5 → (b.val[i]!).val < 2 ^ 52) →
        ∀ i, i < 9 → (r.val[i]!).val < 2 ^ 107) ⦄ := by
  apply spec_mono (mul_internal_limbs a b ha hb)
  rintro r ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8⟩
  have bnd : ∀ k, (∀ i, i < 5 → (a.val[i]!).val < 2 ^ k) →
      (∀ i, i < 5 → (b.val[i]!).val < 2 ^ k) →
      ∀ i, i < 9 → (r.val[i]!).val < 5 * 2 ^ (2 * k) := by
    intro k ha' hb'
    have pb : ∀ i j, i < 5 → j < 5 → (a.val[i]!).val * (b.val[j]!).val < 2 ^ (2 * k) := by
      intro i j hi hj
      have := Nat.mul_lt_mul'' (ha' i hi) (hb' j hj)
      rwa [← pow_add, ← two_mul] at this
    have := pb 0 0 (by omega) (by omega); have := pb 0 1 (by omega) (by omega)
    have := pb 0 2 (by omega) (by omega); have := pb 0 3 (by omega) (by omega)
    have := pb 0 4 (by omega) (by omega); have := pb 1 0 (by omega) (by omega)
    have := pb 1 1 (by omega) (by omega); have := pb 1 2 (by omega) (by omega)
    have := pb 1 3 (by omega) (by omega); have := pb 1 4 (by omega) (by omega)
    have := pb 2 0 (by omega) (by omega); have := pb 2 1 (by omega) (by omega)
    have := pb 2 2 (by omega) (by omega); have := pb 2 3 (by omega) (by omega)
    have := pb 2 4 (by omega) (by omega); have := pb 3 0 (by omega) (by omega)
    have := pb 3 1 (by omega) (by omega); have := pb 3 2 (by omega) (by omega)
    have := pb 3 3 (by omega) (by omega); have := pb 3 4 (by omega) (by omega)
    have := pb 4 0 (by omega) (by omega); have := pb 4 1 (by omega) (by omega)
    have := pb 4 2 (by omega) (by omega); have := pb 4 3 (by omega) (by omega)
    have := pb 4 4 (by omega) (by omega)
    clear pb ha' hb' ha hb
    intro i hi
    interval_cases i <;> omega
  refine ⟨?_, ?_, ?_⟩
  · rw [U128x9_as_Nat_expand]
    unfold Scalar52_as_Nat
    simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq]
    rw [h0, h1, h2, h3, h4, h5, h6, h7, h8]
    ring
  · intro i hi
    have := bnd 62 ha hb i hi
    omega
  · intro ha' hb' i hi
    have := bnd 52 ha' hb' i hi
    omega

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
