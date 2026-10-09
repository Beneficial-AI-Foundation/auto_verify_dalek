/-
Copyright 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Index
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.IndexMut

attribute [-simp] Int.reducePow Nat.reducePow
set_option exponentiation.threshold 260

namespace curve25519_dalek
open Aeneas Aeneas.Std Aeneas.Std.WP Result

attribute [-progress] U64.Insts.SubtleConditionallySelectable.conditional_select_spec
end curve25519_dalek

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Proven (sorry-free) specification of `conditional_select` on `u64`, used locally. -/
theorem conditional_add_l_select_spec (a b : U64) (choice : subtle.Choice) :
    U64.Insts.SubtleConditionallySelectable.conditional_select a b choice ⦃ res =>
      res = if choice.val = 1#u8 then b else a ⦄ := by
  unfold U64.Insts.SubtleConditionallySelectable.conditional_select
  split <;> simp_all

/-- The full `Ico 0 5` limb sum (as used by `conditional_add_l_loop_spec`) is `Scalar52_as_Nat`. -/
theorem conditional_add_l_Ico_sum_eq (a : Scalar52) :
    ∑ j ∈ Finset.Ico 0 5, 2 ^ (52 * j) * (a.val[j]!).val = Scalar52_as_Nat a := by
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq,
    Finset.sum_Ico_succ_top (Nat.zero_le _), Finset.Ico_self, Finset.sum_empty]

/-- Arithmetic heart of one iteration of `conditional_add_l_loop`. -/
theorem conditional_add_l_loop_post (self s1 r : Array U64 5#usize) (Lc : Nat → Nat)
    (i A x c' : Nat) (hi : i < 5)
    (hx : x = A + (self.val[i]!).val + Lc i)
    (hri : (r.val[i]!).val = x % 2 ^ 52)
    (hs1 : ∀ j, j ≠ i → s1.val[j]! = self.val[j]!)
    (hrec : ∑ j ∈ Finset.Ico (i + 1) 5, 2 ^ (52 * j) * (r.val[j]!).val + 2 ^ 260 * c' =
      ∑ j ∈ Finset.Ico (i + 1) 5, 2 ^ (52 * j) * ((s1.val[j]!).val + Lc j) +
        2 ^ (52 * (i + 1)) * (x / 2 ^ 52)) :
    ∑ j ∈ Finset.Ico i 5, 2 ^ (52 * j) * (r.val[j]!).val + 2 ^ 260 * c' =
      ∑ j ∈ Finset.Ico i 5, 2 ^ (52 * j) * ((self.val[j]!).val + Lc j) +
        2 ^ (52 * i) * A := by
  rw [Finset.sum_eq_sum_Ico_succ_bot hi, Finset.sum_eq_sum_Ico_succ_bot hi]
  have hs : ∑ j ∈ Finset.Ico (i + 1) 5, 2 ^ (52 * j) * ((s1.val[j]!).val + Lc j) =
      ∑ j ∈ Finset.Ico (i + 1) 5, 2 ^ (52 * j) * ((self.val[j]!).val + Lc j) := by
    apply Finset.sum_congr rfl
    intro j hj
    rw [hs1 j (by simp at hj; omega)]
  rw [hs] at hrec
  have hsplit := Nat.mod_add_div x (2 ^ 52)
  have hp : 2 ^ (52 * (i + 1)) = 2 ^ (52 * i) * 2 ^ 52 := by ring
  rw [hp] at hrec
  rw [hri]
  generalize 2 ^ (52 * i) = P at *
  generalize x % 2 ^ 52 = z at *
  generalize x / 2 ^ 52 = y at *
  subst hx
  zify at *
  linear_combination hrec + P * hsplit

/-- `conditional_add_l_loop self condition carry mask i` adds (if `condition` is set) the
limbs `i..4` of `L` to the limbs `i..4` of `self`, propagating the carry and reducing
every limb modulo `2^52`. Started at `i = 0` with `carry = 0`, the result satisfies
`r.2 + 2^260 * (r.1 / 2^52) = self + (condition ? L : 0)`. -/
@[progress]
theorem conditional_add_l_loop_spec (self : Scalar52) (condition : subtle.Choice)
    (carry mask : U64) (i : Usize) (hmask : mask.val = 2 ^ 52 - 1) (hi : i.val ≤ 5)
    (hself : ∀ j, j < 5 → (self.val[j]!).val < 2 ^ 52) (hcarry : carry.val < 2 ^ 53) :
    conditional_add_l_loop self condition carry mask i ⦃ r =>
      (∀ j, j < i.val → r.2.val[j]! = self.val[j]!) ∧
      (∀ j, j < 5 → (r.2.val[j]!).val < 2 ^ 52) ∧
      r.1.val < 2 ^ 53 ∧
      ∑ j ∈ Finset.Ico i.val 5, 2 ^ (52 * j) * (r.2.val[j]!).val + 2 ^ 260 * (r.1.val / 2 ^ 52) =
        ∑ j ∈ Finset.Ico i.val 5, 2 ^ (52 * j) * ((self.val[j]!).val +
          (if condition.val = 1#u8 then (constants.L.val[j]!).val else 0)) +
          2 ^ (52 * i.val) * (carry.val / 2 ^ 52) ⦄ := by
  unfold conditional_add_l_loop
  split
  · have hilt : i.val < 5 := by scalar_tac
    progress as ⟨li, hli, hli'⟩
    progress with conditional_add_l_select_spec as ⟨addend, haddend⟩
    progress as ⟨i2, hi2⟩
    progress as ⟨i3, hi3, hi3'⟩
    have hLi : li.val < 2 ^ 52 := by rw [hli']; simpa [Array.getElem!_Nat_eq] using constants.L_bounds i.val hilt
    have hadd : addend.val = (if condition.val = 1#u8 then (constants.L.val[i.val]!).val else 0) := by
      rw [haddend]; split <;> simp_all
    have hadd_lt : addend.val < 2 ^ 52 := by rw [haddend]; split <;> simp_all
    have hselfi : i3.val < 2 ^ 52 := by rw [hi3']; exact hself i.val hilt
    have hi2v : i2.val = carry.val / 2 ^ 52 := by simp [hi2, Nat.shiftRight_eq_div_pow]
    have hi2lt : i2.val ≤ 1 := by rw [hi2v]; omega
    progress as ⟨i4, hi4⟩
    progress as ⟨carry1, hc1⟩
    progress as ⟨old, back, hold, hback, hback1, hback2, hback3⟩
    progress as ⟨i5, hi5⟩
    progress as ⟨i6, hi6⟩
    have hc1v : carry1.val = carry.val / 2 ^ 52 + (self.val[i.val]!).val + addend.val := by
      rw [hc1, hi4, hi2v, hi3']
    have hc1lt : carry1.val < 2 ^ 53 := by omega
    have hi5v : i5.val = carry1.val % 2 ^ 52 := by
      rw [hi5, UScalar.val_and, hmask, Nat.and_two_pow_sub_one_eq_mod]
    have hs1i : ((back i5).val[i.val]!) = i5 := hback2 i5
    have hs1ne : ∀ j, j ≠ i.val → (back i5).val[j]! = self.val[j]! := hback3 i5
    have hs1b : ∀ j, j < 5 → ((back i5).val[j]!).val < 2 ^ 52 := by
      intro j hj
      by_cases hji : j = i.val
      · subst hji; rw [hs1i, hi5v]; omega
      · rw [hs1ne j hji]; exact hself j hj
    have hdec : 5 - i6.val < 5 - i.val := by omega
    progress as ⟨r, hr1, hr2, hr3, hr4⟩
    refine ⟨fun j hj => ?_, hr2, hr3, ?_⟩
    · rw [hr1 j (by omega), hs1ne j (by omega)]
    · rw [hi6] at hr4
      have hri : (r.2.val[i.val]!).val = carry1.val % 2 ^ 52 := by
        rw [hr1 i.val (by omega), hs1i, hi5v]
      exact conditional_add_l_loop_post self (back i5) r.2
        (fun j => if condition.val = 1#u8 then (constants.L.val[j]!).val else 0)
        i.val (carry.val / 2 ^ 52) carry1.val (r.1.val / 2 ^ 52) hilt
        (by rw [hc1v, hadd]) hri hs1ne hr4
  · have hi5 : i.val = 5 := by scalar_tac
    rw [spec_ok]
    refine ⟨fun j _ => rfl, hself, hcarry, ?_⟩
    simp [hi5]
termination_by 5 - i.val
decreasing_by
  all_goals scalar_tac

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Splitting the conditional-addend sum into `self + (condition ? L : 0)`. -/
theorem conditional_add_l_sum_split (self : Scalar52) (b : Bool) :
    ∑ j ∈ Finset.Ico 0 5, 2 ^ (52 * j) * ((self.val[j]!).val +
      (if b then (constants.L.val[j]!).val else 0)) =
      Scalar52_as_Nat self + (if b then _root_.L else 0) := by
  rw [← conditional_add_l_Ico_sum_eq self]
  cases b
  · simp
  · simp only [if_true, mul_add, Finset.sum_add_distrib, conditional_add_l_Ico_sum_eq,
      constants.L_spec]

/-- `conditional_add_l self condition` returns `(carry, r)` where every limb of `r` is
below `2^52` and `r + 2^260 * (carry / 2^52) = self + (condition ? L : 0)`. -/
@[progress]
theorem conditional_add_l_spec (self : Scalar52) (condition : subtle.Choice)
    (hself : ∀ j, j < 5 → (self.val[j]!).val < 2 ^ 52) :
    conditional_add_l self condition ⦃ r =>
      (∀ j, j < 5 → (r.2.val[j]!).val < 2 ^ 52) ∧
      r.1.val < 2 ^ 53 ∧
      Scalar52_as_Nat r.2 + 2 ^ 260 * (r.1.val / 2 ^ 52) =
        Scalar52_as_Nat self + (if condition.val = 1#u8 then _root_.L else 0) ⦄ := by
  unfold conditional_add_l
  progress as ⟨i, hi⟩
  progress as ⟨mask, hmask⟩
  have hmv : mask.val = 2 ^ 52 - 1 := by
    rw [hmask, hi]; simp [Nat.shiftLeft_eq, U64.size, U64.numBits]
    rw [Nat.mod_eq_of_lt (by norm_num)]
  progress with conditional_add_l_loop_spec as ⟨r, _, hr2, hr3, hr4⟩
  refine ⟨hr2, hr3, ?_⟩
  have h := conditional_add_l_sum_split self (decide (condition.val = 1#u8))
  simp only [decide_eq_true_eq] at h
  rw [← h, ← conditional_add_l_Ico_sum_eq r.2]
  simpa using hr4

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
