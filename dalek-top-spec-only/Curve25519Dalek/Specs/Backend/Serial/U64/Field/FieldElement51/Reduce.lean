/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Mathlib.Tactic.IntervalCases

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

attribute [-simp] Int.reducePow Nat.reducePow

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.reduce

@[progress]
theorem LOW_51_BIT_MASK_spec :
    LOW_51_BIT_MASK ⦃ r => r.val = 2 ^ 51 - 1 ⦄ := by
  unfold LOW_51_BIT_MASK
  progress as ⟨i, hi⟩
  progress as ⟨r, hr⟩
  scalar_tac

end curve25519_dalek.backend.serial.u64.field.FieldElement51.reduce

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

/-- Shifting a `U64` right by `51` bits gives a value bounded by `2 ^ 13 - 1`, and equal to
integer division by `2 ^ 51`. Packaged as a `@[progress]` lemma so it fires automatically on
each `x >>> 51#i32` occurring in `reduce` and `to_bytes`. -/
@[progress]
theorem shiftRight51_spec (x : Std.U64) :
    (x >>> 51#i32 : Result Std.U64) ⦃ z => z.val = x.val / 2 ^ 51 ∧ z.val ≤ 2 ^ 13 - 1 ⦄ := by
  progress as ⟨z, hz, _⟩
  have h1 := Aeneas.Std.U64.shiftRight_51 x
  have h2 := U64_shiftRight_le x
  omega

/-- Masking a `U64` with the 51-bit mask leaves the low 51 bits, i.e. reduces modulo `2 ^ 51`.
Packaged as a `@[progress]` lemma so it fires automatically on each `x &&& mask` occurring in
`reduce` and `to_bytes`, given a hypothesis identifying `mask` as the low-51-bit mask. -/
@[progress]
theorem mask51_spec (x mask : Std.U64) (hmask : mask.val = 2 ^ 51 - 1) :
    (lift (x &&& mask) : Result Std.U64) ⦃ z => z.val = x.val % 2 ^ 51 ∧ z.val < 2 ^ 51 ⦄ := by
  progress as ⟨z, hz, _⟩
  simp only [Aeneas.Std.UScalar.val_and, hmask] at hz
  rw [land_pow_two_sub_one_eq_mod] at hz
  omega

@[progress]
theorem reduce_spec (limbs : Array Std.U64 5#usize) :
    reduce limbs ⦃ result =>
      (∀ i < 5, result[i]!.val < 2 ^ 51 + 2 ^ 18) ∧
      Field51_as_Nat result + (limbs[4]!.val / 2 ^ 51) * p = Field51_as_Nat limbs ⦄ := by
  unfold reduce
  progress as ⟨i, hi⟩
  progress as ⟨c0, hc0, hc0b⟩
  progress as ⟨i1, hi1⟩
  progress as ⟨c1, hc1, hc1b⟩
  progress as ⟨i2, hi2⟩
  progress as ⟨c2, hc2, hc2b⟩
  progress as ⟨i3, hi3⟩
  progress as ⟨c3, hc3, hc3b⟩
  progress as ⟨i4, hi4⟩
  progress as ⟨c4, hc4, hc4b⟩
  progress as ⟨i5, hi5⟩
  progress as ⟨i6, hi6, hi6b⟩
  progress as ⟨limbs1, hlimbs1⟩
  progress as ⟨i7, hi7⟩
  progress as ⟨i8, hi8, hi8b⟩
  progress as ⟨limbs2, hlimbs2⟩
  progress as ⟨i9, hi9⟩
  progress as ⟨i10, hi10, hi10b⟩
  progress as ⟨limbs3, hlimbs3⟩
  progress as ⟨i11, hi11⟩
  progress as ⟨i12, hi12, hi12b⟩
  progress as ⟨limbs4, hlimbs4⟩
  progress as ⟨i13, hi13⟩
  progress as ⟨i14, hi14, hi14b⟩
  progress as ⟨limbs5, hlimbs5⟩
  progress as ⟨i15, hi15⟩
  progress as ⟨i16, hi16⟩
  progress as ⟨i17, hi17⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5] at hi16
  subst hi16
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs6, hlimbs6⟩
  progress as ⟨i18, hi18⟩
  progress as ⟨i19, hi19⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6] at hi18
  subst hi18
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs7, hlimbs7⟩
  progress as ⟨i20, hi20⟩
  progress as ⟨i21, hi21⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7] at hi20
  subst hi20
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs8, hlimbs8⟩
  progress as ⟨i22, hi22⟩
  progress as ⟨i23, hi23⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7, hlimbs8] at hi22
  subst hi22
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs9, hlimbs9⟩
  progress as ⟨i24, hi24⟩
  progress as ⟨i25, hi25⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7, hlimbs8, hlimbs9] at hi24
  subst hi24
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs10, hlimbs10⟩
  simp [Array.val_getElem!_eq'] at hi hi1 hi2 hi3 hi4
  subst hi; subst hi1; subst hi2; subst hi3; subst hi4
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, Array.val_getElem!_eq'] at hi7 hi9 hi11 hi13
  subst hi7; subst hi9; subst hi11; subst hi13
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7, hlimbs8, hlimbs9,
    Array.val_getElem!_eq'] at hi16 hi18 hi20 hi22 hi24
  subst hi16; subst hi18; subst hi20; subst hi22; subst hi24
  constructor
  · intro j hj
    interval_cases j <;>
      simp [hlimbs10, hlimbs9, hlimbs8, hlimbs7, hlimbs6] <;> omega
  · unfold Field51_as_Nat p
    simp only [Finset.sum_range_succ, Finset.sum_range_zero]
    norm_num
    simp [hlimbs10, hlimbs9, hlimbs8, hlimbs7, hlimbs6, hlimbs5, hlimbs4, hlimbs3, hlimbs2, hlimbs1]
    have e0 := Nat.div_add_mod limbs[0]!.val (2 ^ 51)
    have e1 := Nat.div_add_mod limbs[1]!.val (2 ^ 51)
    have e2 := Nat.div_add_mod limbs[2]!.val (2 ^ 51)
    have e3 := Nat.div_add_mod limbs[3]!.val (2 ^ 51)
    have e4 := Nat.div_add_mod limbs[4]!.val (2 ^ 51)
    omega

end curve25519_dalek.backend.serial.u64.field.FieldElement51
