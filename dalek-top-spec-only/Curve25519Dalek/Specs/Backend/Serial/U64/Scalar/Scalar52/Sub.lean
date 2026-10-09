/-
Copyright (c) 2025 Oliver Butterley. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aeneas
import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ConditionalAddL
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ZERO

set_option exponentiation.threshold 260

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

attribute [-simp] Int.reducePow Nat.reducePow

def Scalar52_partial_as_Nat (limbs : Array U64 5#usize) (n : Nat) : Nat :=
  ∑ j ∈ Finset.range n, 2 ^ (52 * j) * (limbs[j]!).val

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Arithmetic of one wrapping-subtraction step of `sub_loop`: for `x, y` small enough,
`w = x - y (mod 2^64)` has its top bit set exactly when `x < y`, and the low 52 bits of `w`
equal `x - y + 2^52 * (w >>> 63)`. -/
theorem sub_loop_step_arith (x y w : Nat) (hx : x < 2 ^ 52) (hy : y ≤ 2 ^ 52)
    (hw : w = (x + (2 ^ 64 - y)) % 2 ^ 64) :
    w / 2 ^ 63 ≤ 1 ∧ ((w % 2 ^ 52 : Nat) : Int) = (x : Int) - y + 2 ^ 52 * ((w / 2 ^ 63 : Nat) : Int) := by
  have h64 : (2 : Nat) ^ 64 = 18446744073709551616 := by norm_num
  have h63 : (2 : Nat) ^ 63 = 9223372036854775808 := by norm_num
  have h52 : (2 : Nat) ^ 52 = 4503599627370496 := by norm_num
  have h52' : (2 : Int) ^ 52 = 4503599627370496 := by norm_num
  rw [h64] at hw
  rw [h52] at hx hy ⊢
  rw [h63, h52']
  by_cases hxy : y ≤ x
  · have hw' : w = x - y := by omega
    have h1 : w / 9223372036854775808 = 0 := by omega
    have h2 : w % 4503599627370496 = w := by omega
    rw [h1, h2, hw']
    constructor
    · omega
    · push_cast [hxy]; ring
  · have hw' : w + y = 18446744073709551616 + x := by omega
    have h1 : w / 9223372036854775808 = 1 := by omega
    have h2 : w % 4503599627370496 + y = 4503599627370496 + x := by omega
    rw [h1]
    constructor
    · omega
    · have h3 : ((w % 4503599627370496 : Nat) : Int) + y = 4503599627370496 + x := by
        exact_mod_cast h2
      push_cast; linarith

/-- Arithmetic heart of one iteration of `sub_loop`. -/
theorem sub_loop_post (a b r : Array U64 5#usize) (i : Nat) (f0 f1 F : Int) (hi : i < 5)
    (hri : ((r.val[i]!).val : Int) = (a.val[i]!).val - ((b.val[i]!).val + f0) + 2 ^ 52 * f1)
    (hrec : ∑ j ∈ Finset.Ico (i + 1) 5, (2 : Int) ^ (52 * j) * (r.val[j]!).val - 2 ^ 260 * F =
      ∑ j ∈ Finset.Ico (i + 1) 5, (2 : Int) ^ (52 * j) * (((a.val[j]!).val : Int) - (b.val[j]!).val) -
        2 ^ (52 * (i + 1)) * f1) :
    ∑ j ∈ Finset.Ico i 5, (2 : Int) ^ (52 * j) * (r.val[j]!).val - 2 ^ 260 * F =
      ∑ j ∈ Finset.Ico i 5, (2 : Int) ^ (52 * j) * (((a.val[j]!).val : Int) - (b.val[j]!).val) -
        2 ^ (52 * i) * f0 := by
  rw [Finset.sum_eq_sum_Ico_succ_bot hi, Finset.sum_eq_sum_Ico_succ_bot hi]
  have hp : (2 : Int) ^ (52 * (i + 1)) = 2 ^ (52 * i) * 2 ^ 52 := by ring
  rw [hp] at hrec
  rw [hri]
  generalize (2 : Int) ^ (52 * i) = P at *
  linear_combination hrec

/-- `sub_loop a b difference mask borrow i` computes limbs `i..4` of `a - b` with borrow
propagation (the incoming borrow is `borrow >>> 63`), storing each limb modulo `2^52`.
The final borrow's top bit records the outgoing borrow:
`∑ r.1 - 2^260 * (r.2 >>> 63) = ∑ (a - b) - 2^(52 i) * (borrow >>> 63)` over limbs `i..4`. -/
@[progress]
theorem sub_loop_spec (a b difference : Scalar52) (mask borrow : U64) (i : Usize)
    (hmask : mask.val = 2 ^ 52 - 1) (hi : i.val ≤ 5)
    (ha : ∀ j, j < 5 → (a.val[j]!).val < 2 ^ 52)
    (hb : ∀ j, j < 5 → (b.val[j]!).val < 2 ^ 52)
    (hd : ∀ j, j < 5 → (difference.val[j]!).val < 2 ^ 52) :
    sub_loop a b difference mask borrow i ⦃ r =>
      (∀ j, j < i.val → r.1.val[j]! = difference.val[j]!) ∧
      (∀ j, j < 5 → (r.1.val[j]!).val < 2 ^ 52) ∧
      r.2.val / 2 ^ 63 ≤ 1 ∧
      ∑ j ∈ Finset.Ico i.val 5, (2 : Int) ^ (52 * j) * (r.1.val[j]!).val -
          2 ^ 260 * ((r.2.val / 2 ^ 63 : Nat) : Int) =
        ∑ j ∈ Finset.Ico i.val 5, (2 : Int) ^ (52 * j) *
          (((a.val[j]!).val : Int) - (b.val[j]!).val) -
          2 ^ (52 * i.val) * ((borrow.val / 2 ^ 63 : Nat) : Int) ⦄ := by
  unfold sub_loop
  split
  · have hilt : i.val < 5 := by scalar_tac
    progress as ⟨i1, hi1, hi1'⟩
    progress as ⟨i2, hi2, hi2'⟩
    progress as ⟨i3, hi3⟩
    have hi3v : i3.val = borrow.val / 2 ^ 63 := by simp [hi3, Nat.shiftRight_eq_div_pow]
    have hi3lt : i3.val ≤ 1 := by rw [hi3v]; scalar_tac
    have hai : i1.val < 2 ^ 52 := by rw [hi1']; exact ha i.val hilt
    have hbi : i2.val < 2 ^ 52 := by rw [hi2']; exact hb i.val hilt
    progress as ⟨i4, hi4⟩
    progress as ⟨w, hw⟩
    progress as ⟨old, back, hold, hback, hback1, hback2, hback3⟩
    progress as ⟨i5, hi5⟩
    progress as ⟨i6, hi6⟩
    have hwv : w.val = (i1.val + (2 ^ 64 - i4.val)) % 2 ^ 64 := by
      rw [hw]; simp [U64.size, U64.numBits]
    obtain ⟨hwlt, hwmod⟩ := sub_loop_step_arith i1.val i4.val w.val hai (by omega) hwv
    have hi5v : i5.val = w.val % 2 ^ 52 := by
      rw [hi5, UScalar.val_and, hmask, Nat.and_two_pow_sub_one_eq_mod]
    have hs1i : ((back i5).val[i.val]!) = i5 := hback2 i5
    have hs1ne : ∀ j, j ≠ i.val → (back i5).val[j]! = difference.val[j]! := hback3 i5
    have hs1b : ∀ j, j < 5 → ((back i5).val[j]!).val < 2 ^ 52 := by
      intro j hj
      by_cases hji : j = i.val
      · subst hji; rw [hs1i, hi5v]; omega
      · rw [hs1ne j hji]; exact hd j hj
    have hdec : 5 - i6.val < 5 - i.val := by omega
    progress as ⟨r, hr1, hr2, hr3, hr4⟩
    refine ⟨fun j hj => ?_, hr2, hr3, ?_⟩
    · rw [hr1 j (by omega), hs1ne j (by omega)]
    · rw [hi6] at hr4
      have hri : ((r.1.val[i.val]!).val : Int) = (a.val[i.val]!).val -
          ((b.val[i.val]!).val + ((borrow.val / 2 ^ 63 : Nat) : Int)) +
          2 ^ 52 * ((w.val / 2 ^ 63 : Nat) : Int) := by
        rw [hr1 i.val (by omega), hs1i, hi5v, hwmod, hi4, ← hi1', ← hi2', hi3v]
        push_cast; ring
      exact sub_loop_post a b r.1 i.val _ _ _ hilt hri hr4
  · have hi5 : i.val = 5 := by scalar_tac
    rw [spec_ok]
    refine ⟨fun j _ => rfl, hd, by scalar_tac, ?_⟩
    simp [hi5]
termination_by 5 - i.val
decreasing_by
  all_goals scalar_tac

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- A scalar with all five limbs below `2^52` is below `2^260`. -/
theorem sub_as_Nat_lt (a : Scalar52) (ha : ∀ j, j < 5 → (a.val[j]!).val < 2 ^ 52) :
    Scalar52_as_Nat a < 2 ^ 260 := by
  have h0 := ha 0 (by omega)
  have h1 := ha 1 (by omega)
  have h2 := ha 2 (by omega)
  have h3 := ha 3 (by omega)
  have h4 := ha 4 (by omega)
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq]
  norm_num at h0 h1 h2 h3 h4 ⊢
  omega

/-- The signed limb-difference sum over `Ico 0 5` is `a - b`. -/
theorem sub_Ico_sum_sub (a b : Scalar52) :
    ∑ j ∈ Finset.Ico 0 5, (2 : Int) ^ (52 * j) * (((a.val[j]!).val : Int) - (b.val[j]!).val) =
      (Scalar52_as_Nat a : Int) - Scalar52_as_Nat b := by
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq,
    Finset.sum_Ico_succ_top (Nat.zero_le _), Finset.Ico_self, Finset.sum_empty]
  push_cast
  ring

/-- Arithmetic combining the outcome of `sub_loop` and `conditional_add_l` in `sub`. -/
theorem sub_final_arith (A B D R f q : Nat) (hf : f ≤ 1) (hD : D < 2 ^ 260) (hR : R < 2 ^ 260)
    (hBA : B ≤ A + _root_.L)
    (hloop : (D : Int) - 2 ^ 260 * f = (A : Int) - B)
    (hadd : R + 2 ^ 260 * q = D + (if f = 1 then _root_.L else 0)) :
    R + B = A + (if A < B then _root_.L else 0) := by
  have hL : _root_.L < 2 ^ 260 := by unfold _root_.L; norm_num
  have h260 : (2 : Nat) ^ 260 = 1852673427797059126777135760139006525652319754650249024631321344126610074238976 := by norm_num
  have h260' : (2 : Int) ^ 260 = 1852673427797059126777135760139006525652319754650249024631321344126610074238976 := by norm_num
  rw [h260'] at hloop
  rw [h260] at hD hR hadd hL
  generalize _root_.L = L at *
  rcases Nat.le_one_iff_eq_zero_or_eq_one.mp hf with rfl | rfl
  · simp at hadd
    have hAB : ¬ A < B := by omega
    simp only [hAB, if_false]
    omega
  · simp at hadd
    have hAB : A < B := by omega
    simp only [hAB, if_true]
    omega

/-- Local spec of `Choice::from(u8)` on a bit. -/
theorem sub_choice_from_spec (x : U8) (h : x.val ≤ 1) :
    subtle.Choice.Insts.CoreConvertFromU8.from x ⦃ c => c.val = x ⦄ := by
  unfold subtle.Choice.Insts.CoreConvertFromU8.from
  split
  · simp
  · split
    · simp
    · exfalso
      rename_i h1 h2
      have : x.val = 0 ∨ x.val = 1 := by omega
      rcases this with h3 | h3
      · exact h1 (by scalar_tac)
      · exact h2 (by scalar_tac)

/-- `sub a b` computes `a - b` modulo `L`: for limbs below `2^52` and `b ≤ a + L`, the result has
limbs below `2^52` and `r + b = a + (a < b ? L : 0)`. In particular `r ≡ a + L - b [MOD L]`,
and `r < L` whenever `a < b + L`. -/
@[progress]
theorem sub_spec (a b : Scalar52)
    (ha : ∀ j, j < 5 → (a.val[j]!).val < 2 ^ 52)
    (hb : ∀ j, j < 5 → (b.val[j]!).val < 2 ^ 52)
    (hab : Scalar52_as_Nat b ≤ Scalar52_as_Nat a + _root_.L) :
    sub a b ⦃ r =>
      (∀ j, j < 5 → (r.val[j]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r + Scalar52_as_Nat b =
        Scalar52_as_Nat a + (if Scalar52_as_Nat a < Scalar52_as_Nat b then _root_.L else 0) ∧
      Scalar52_as_Nat r ≡ Scalar52_as_Nat a + _root_.L - Scalar52_as_Nat b [MOD _root_.L] ∧
      (Scalar52_as_Nat a < Scalar52_as_Nat b + _root_.L → Scalar52_as_Nat r < _root_.L) ⦄ := by
  unfold sub
  progress as ⟨i, hi⟩
  progress as ⟨mask, hmask⟩
  have hmv : mask.val = 2 ^ 52 - 1 := by
    rw [hmask, hi]; simp [Nat.shiftLeft_eq, U64.size, U64.numBits]
  have hz : ∀ j, j < 5 → (ZERO.val[j]!).val < 2 ^ 52 := by
    intro j _; rw [ZERO_val_getElem!]; simp
  progress with sub_loop_spec as ⟨d, _, hd2, hd3, hd4⟩
  progress as ⟨i1, hi1⟩
  progress as ⟨i2, hi2⟩
  have hi1v : i1.val = d.2.val / 2 ^ 63 := by simp [hi1, Nat.shiftRight_eq_div_pow]
  have hi2v : i2.val = d.2.val / 2 ^ 63 := by
    rw [← hi1v, hi2, UScalar.cast_val_eq]; simp; omega
  progress with sub_choice_from_spec as ⟨c, hc⟩
  progress with conditional_add_l_spec as ⟨res, hr1, hr2, hr3⟩
  have hcond : (c.val = 1#u8) ↔ d.2.val / 2 ^ 63 = 1 := by
    rw [hc]; constructor
    · intro h; rw [← hi2v, h]; rfl
    · intro h; apply UScalar.eq_of_val_eq; rw [hi2v, h]; rfl
  have hD := sub_as_Nat_lt d.1 hd2
  have hR := sub_as_Nat_lt res.2 hr1
  have hloop : (Scalar52_as_Nat d.1 : Int) - 2 ^ 260 * ((d.2.val / 2 ^ 63 : Nat) : Int) =
      (Scalar52_as_Nat a : Int) - Scalar52_as_Nat b := by
    rw [← sub_Ico_sum_sub, ← conditional_add_l_Ico_sum_eq d.1]
    simpa using hd4
  have hadd : Scalar52_as_Nat res.2 + 2 ^ 260 * (res.1.val / 2 ^ 52) =
      Scalar52_as_Nat d.1 + (if d.2.val / 2 ^ 63 = 1 then _root_.L else 0) := by
    rw [hr3]; simp only [hcond]
  have heq := sub_final_arith _ _ _ _ _ _ hd3 hD hR hab hloop hadd
  refine ⟨hr1, heq, ?_, ?_⟩
  · split at heq
    · have : Scalar52_as_Nat res.2 = Scalar52_as_Nat a + _root_.L - Scalar52_as_Nat b := by omega
      rw [this]
    · have : Scalar52_as_Nat a + _root_.L - Scalar52_as_Nat b =
          Scalar52_as_Nat res.2 + _root_.L := by omega
      rw [this, Nat.ModEq, Nat.add_mod_right]
  · intro h; split at heq <;> omega

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
