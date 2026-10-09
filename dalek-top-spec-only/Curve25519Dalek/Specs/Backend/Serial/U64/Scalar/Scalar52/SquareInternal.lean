import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Index

set_option exponentiation.threshold 416

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

attribute [-simp] Int.reducePow Nat.reducePow

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Limb-wise behaviour of `square_internal`: the `k`-th output limb is the schoolbook
convolution `∑_{i+j=k} a[i] * a[j]` (with the symmetric cross terms doubled). -/
theorem square_internal_limbs (a : Scalar52)
    (ha : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 62) :
    square_internal a ⦃ r =>
      (r.val[0]!).val = (a.val[0]!).val * (a.val[0]!).val ∧
      (r.val[1]!).val = 2 * (a.val[0]!).val * (a.val[1]!).val ∧
      (r.val[2]!).val = 2 * (a.val[0]!).val * (a.val[2]!).val +
        (a.val[1]!).val * (a.val[1]!).val ∧
      (r.val[3]!).val = 2 * (a.val[0]!).val * (a.val[3]!).val +
        2 * (a.val[1]!).val * (a.val[2]!).val ∧
      (r.val[4]!).val = 2 * (a.val[0]!).val * (a.val[4]!).val +
        2 * (a.val[1]!).val * (a.val[3]!).val + (a.val[2]!).val * (a.val[2]!).val ∧
      (r.val[5]!).val = 2 * (a.val[1]!).val * (a.val[4]!).val +
        2 * (a.val[2]!).val * (a.val[3]!).val ∧
      (r.val[6]!).val = 2 * (a.val[2]!).val * (a.val[4]!).val +
        (a.val[3]!).val * (a.val[3]!).val ∧
      (r.val[7]!).val = 2 * (a.val[3]!).val * (a.val[4]!).val ∧
      (r.val[8]!).val = (a.val[4]!).val * (a.val[4]!).val ⦄ := by
  have pb : ∀ i j, i < 5 → j < 5 → (a.val[i]!).val * (a.val[j]!).val < 2 ^ 124 := by
    intro i j hi hj
    have := Nat.mul_lt_mul'' (ha i hi) (ha j hj)
    simpa [← pow_add] using this
  have := ha 0 (by omega); have := ha 1 (by omega); have := ha 2 (by omega)
  have := ha 3 (by omega); have := ha 4 (by omega)
  have := pb 0 0 (by omega) (by omega); have := pb 0 1 (by omega) (by omega)
  have := pb 0 2 (by omega) (by omega); have := pb 0 3 (by omega) (by omega)
  have := pb 0 4 (by omega) (by omega)
  have := pb 1 1 (by omega) (by omega); have := pb 1 2 (by omega) (by omega)
  have := pb 1 3 (by omega) (by omega); have := pb 1 4 (by omega) (by omega)
  have := pb 2 2 (by omega) (by omega); have := pb 2 3 (by omega) (by omega)
  have := pb 2 4 (by omega) (by omega)
  have := pb 3 3 (by omega) (by omega); have := pb 3 4 (by omega) (by omega)
  have := pb 4 4 (by omega) (by omega)
  clear pb ha
  unfold square_internal
  progress*
  simp only [Array.make] at i9_post i15_post i25_post i31_post
  simp at i9_post i15_post i25_post i31_post
  subst_vars
  simp only [Array.make]
  simp [*]
  exact ⟨.inl (by ring), .inl (by ring), by ring, by ring, by ring, .inl (by ring), .inl (by ring)⟩

/-- Spec for `Scalar52::square_internal`: the nine-limb (radix `2^52`) unreduced square
represents `a * a`. Each output limb is below `2^127`; when the input has 52-bit limbs
(the usual case, e.g. before `montgomery_reduce`) each output limb is below `2^107`. -/
@[progress]
theorem square_internal_spec (a : Scalar52)
    (ha : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 62) :
    square_internal a ⦃ r =>
      U128x9_as_Nat r = Scalar52_as_Nat a * Scalar52_as_Nat a ∧
      (∀ i, i < 9 → (r.val[i]!).val < 2 ^ 127) ∧
      ((∀ i, i < 5 → (a.val[i]!).val < 2 ^ 52) →
        ∀ i, i < 9 → (r.val[i]!).val < 2 ^ 107) ⦄ := by
  apply spec_mono (square_internal_limbs a ha)
  rintro r ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8⟩
  have bnd : ∀ k, (∀ i, i < 5 → (a.val[i]!).val < 2 ^ k) →
      ∀ i, i < 9 → (r.val[i]!).val < 5 * 2 ^ (2 * k) := by
    intro k ha'
    have pb : ∀ i j, i < 5 → j < 5 → (a.val[i]!).val * (a.val[j]!).val < 2 ^ (2 * k) := by
      intro i j hi hj
      have := Nat.mul_lt_mul'' (ha' i hi) (ha' j hj)
      rwa [← pow_add, ← two_mul] at this
    have := pb 0 0 (by omega) (by omega); have := pb 0 1 (by omega) (by omega)
    have := pb 0 2 (by omega) (by omega); have := pb 0 3 (by omega) (by omega)
    have := pb 0 4 (by omega) (by omega)
    have := pb 1 1 (by omega) (by omega); have := pb 1 2 (by omega) (by omega)
    have := pb 1 3 (by omega) (by omega); have := pb 1 4 (by omega) (by omega)
    have := pb 2 2 (by omega) (by omega); have := pb 2 3 (by omega) (by omega)
    have := pb 2 4 (by omega) (by omega)
    have := pb 3 3 (by omega) (by omega); have := pb 3 4 (by omega) (by omega)
    have := pb 4 4 (by omega) (by omega)
    clear pb ha' ha
    simp only [mul_assoc] at h1 h2 h3 h4 h5 h6 h7
    intro i hi
    interval_cases i <;> omega
  refine ⟨?_, ?_, ?_⟩
  · rw [U128x9_as_Nat_expand]
    unfold Scalar52_as_Nat
    simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq]
    rw [h0, h1, h2, h3, h4, h5, h6, h7, h8]
    ring
  · intro i hi
    have := bnd 62 ha i hi
    omega
  · intro ha' i hi
    have := bnd 52 ha' i hi
    omega

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
