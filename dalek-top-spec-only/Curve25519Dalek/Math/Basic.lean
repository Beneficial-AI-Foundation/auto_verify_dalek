/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aeneas
import Curve25519Dalek.Types
import Mathlib.Algebra.Field.ZMod
import Mathlib.NumberTheory.LegendreSymbol.Basic
import Mathlib.Tactic.NormNum.LegendreSymbol
import PrimeCert.PrimeList

open Aeneas.Std Result

def p : Nat := 2^255 - 19

def L : Nat := 2^252 + 27742317777372353535851937790883648493

def h : Nat := 8

def d : Nat := 37095705934669439343138083508754565189542113879843219016388785533085940283555

def a : Int := -1

def Field51_as_Nat (limbs : Array U64 5#usize) : Nat :=
  ∑ i ∈ Finset.range 5, 2^(51 * i) * (limbs[i]!).val

def Scalar52_as_Nat (limbs : Array U64 5#usize) : Nat :=
  ∑ i ∈ Finset.range 5, 2^(52 * i) * (limbs[i]!).val

def U8x32_as_Nat (bytes : Array U8 32#usize) : Nat :=
  ∑ i ∈ Finset.range 32, 2^(8 * i) * (bytes[i]!).val

def U8x32_as_Field (bytes : Array U8 32#usize) : ZMod (2^255 - 19) :=
  bytes.val.foldr (init := (0 : ZMod (2^255 - 19))) fun b acc =>
    (b.val : ZMod (2^255 - 19)) + (256 : ZMod (2^255 - 19)) * acc

def U8x64_as_Nat (bytes : Array U8 64#usize) : Nat :=
  ∑ i ∈ Finset.range 64, 2^(8 * i) * (bytes[i]!).val

attribute [-simp] Int.reducePow Nat.reducePow

instance : Fact (Nat.Prime p) := ⟨PrimeCert.prime_25519''⟩
instance : Fact (Nat.Prime L) := ⟨PrimeCert.prime_ed25519_order⟩

namespace Edwards

abbrev CurveField : Type := ZMod p

end Edwards

namespace Edwards

open curve25519_dalek.backend.serial.u64.field ZMod

end Edwards

namespace curve25519_dalek.backend.serial.u64.field
open Edwards

def FieldElement51.toField (fe : FieldElement51) : CurveField :=
  (Field51_as_Nat fe : CurveField)

@[grind unfold]
def FieldElement51.IsValid (fe : FieldElement51) : Prop := ∀ i < 5, fe[i]!.val < 2^54

instance FieldElement51.instDecidableIsValid (fe : FieldElement51) : Decidable fe.IsValid :=
  show Decidable (∀ i < 5, fe[i]!.val < 2^54) from inferInstance

end curve25519_dalek.backend.serial.u64.field

namespace curve25519_dalek.math

open Edwards ZMod

def sqrt_m1 : ZMod p :=
  19681161376707505956807079304988542015446066515923890162744021073123829784752

lemma p_sub_one_cast : (↑(p - 1) : ZMod p) = -1 := by
  rw [Nat.cast_sub (by decide : 1 ≤ p), ZMod.natCast_self, zero_sub, Nat.cast_one]

private lemma sqrt_m1_sq_nat :
    19681161376707505956807079304988542015446066515923890162744021073123829784752 ^ 2 % p = p - 1 := by
  decide

lemma sqrt_m1_sq : (sqrt_m1 : ZMod p) ^ 2 = -1 := by
  unfold sqrt_m1
  have h : (((19681161376707505956807079304988542015446066515923890162744021073123829784752 ^ 2 : ℕ)) : ZMod p) =
      ((p - 1 : ℕ) : ZMod p) := by
    exact (ZMod.natCast_eq_natCast_iff _ _ _).2 (by simpa [Nat.ModEq] using sqrt_m1_sq_nat)
  push_cast at h
  rwa [p_sub_one_cast] at h

lemma sqrt_m1_not_square : ¬ IsSquare sqrt_m1 := by
  rintro ⟨y, hy⟩
  rw [← pow_two] at hy
  have y4 : y ^ 4 = -1 := by
    rw [show 4 = 2 * 2 by norm_num, pow_mul, ← hy, sqrt_m1_sq]
  have hy_ne_zero : y ≠ 0 := by
    intro hy0
    rw [hy0, zero_pow (by norm_num)] at y4
    norm_num at y4
  have y8 : y ^ 8 = 1 := by
    rw [show 8 = 4 * 2 by norm_num, pow_mul, y4]
    norm_num
  have h_order : orderOf y = 8 := by
    refine orderOf_eq_of_pow_and_pow_div_prime (by norm_num) y8 ?_
    intro q hprime hdvd
    have hq : q = 2 := by
      rw [show 8 = 2 ^ 3 by norm_num] at hdvd
      exact (Nat.prime_dvd_prime_iff_eq hprime Nat.prime_two).mp (hprime.dvd_of_dvd_pow hdvd)
    rw [hq, show 8 / 2 = 4 by norm_num, y4]
    intro h_eq
    have h_two : (2 : ZMod p) = 0 := by
      have := congrArg (fun z : ZMod p => z + 1) h_eq
      have h_zero : (0 : ZMod p) = 2 := by simpa using this
      exact h_zero.symm
    have h_dvd : p ∣ 2 := (ZMod.natCast_eq_zero_iff 2 p).mp h_two
    norm_num [p] at h_dvd
  have order_div : 8 ∣ (p - 1) := by
    simpa [ZMod.card, h_order] using ZMod.orderOf_dvd_card_sub_one hy_ne_zero
  have not_dvd : ¬ 8 ∣ (p - 1) := by
    intro h8
    have mod_zero : (p - 1) % 8 = 0 := Nat.mod_eq_zero_of_dvd h8
    norm_num [p] at mod_zero
  exact not_dvd order_div

private def sqrt_ad_minus_one_val : Nat :=
  25063068953384623474111414158702152701244531502492656460079210482610430750235

def sqrt_ad_minus_one : ZMod p := sqrt_ad_minus_one_val

attribute [irreducible] sqrt_ad_minus_one

noncomputable def sqrt (x : ZMod p) : ZMod p :=
  if h : IsSquare x then Classical.choose h else 0

def is_negative (x : ZMod p) : Bool :=
  x.val % 2 == 1

def abs_edwards (x : ZMod p) : ZMod p :=
  if is_negative x then -x else x

lemma abs_edwards_sq (x : ZMod p) : (abs_edwards x)^2 = x^2 := by
  unfold abs_edwards
  split_ifs <;> ring

noncomputable def sqrt_checked (x : ZMod p) : (ZMod p × Bool) :=
  if h : IsSquare x then

    let y := Classical.choose h
    (abs_edwards y, true)
  else

    have h_ix : IsSquare (x * sqrt_m1) := by
      have h_char_ne_2 : ringChar (ZMod p) ≠ 2 := by
        intro h_char; rw [ZMod.ringChar_zmod_n] at h_char;
        norm_num [p] at h_char
      have h_pow_card : Fintype.card (ZMod p) / 2 = p / 2 := by rw [ZMod.card]
      have hx_ne0 : x ≠ 0 := by intro c; rw [c] at h; simp at h
      have h_i_ne0 : sqrt_m1 ≠ 0 := by
        unfold sqrt_m1;
        try decide
      have euler {z : ZMod p} (hz : z ≠ 0) : IsSquare z ↔ z ^ (Fintype.card (ZMod p) / 2) = 1 :=
        FiniteField.isSquare_iff h_char_ne_2 hz
      simp only [h_pow_card] at euler
      have h_x_pow : x ^ (p / 2) = -1 := by
        have dic := FiniteField.pow_dichotomy h_char_ne_2 hx_ne0
        rw [h_pow_card] at dic
        cases dic with
        | inl h1 => rw [← euler hx_ne0] at h1; contradiction
        | inr h_neg => exact h_neg
      have not_sq_i : ¬ IsSquare sqrt_m1 := sqrt_m1_not_square
      have h_i_pow : sqrt_m1 ^ (p / 2) = -1 := by
        have dic := FiniteField.pow_dichotomy h_char_ne_2 h_i_ne0
        rw [h_pow_card] at dic
        cases dic with
        | inl h1 =>
          rw [← euler h_i_ne0] at h1
          grind
        | inr h_neg => exact h_neg
      rw [euler (mul_ne_zero hx_ne0 h_i_ne0)]
      rw [mul_pow, h_x_pow, h_i_pow]
      norm_num
    let y := Classical.choose h_ix
    (abs_edwards y, false)

theorem sqrt_checked_spec (u : ZMod p) {r : ZMod p} {b : Bool} :
  sqrt_checked u = (r, b) → b = true → r^2 = u := by
  intro h_call h_true
  sorry

noncomputable def inv_sqrt_checked (u : ZMod p) : (ZMod p × Bool) :=
  if u = 0 then (0, false)
  else
    let (root, was_square) := sqrt_checked u
    (root⁻¹, was_square)

theorem inv_sqrt_checked_spec (arg : ZMod p) {I : ZMod p} {was_square : Bool} :
  inv_sqrt_checked arg = (I, was_square) →
  was_square = true →
  arg ≠ 0 →
  I^2 * arg = 1 := by

  sorry

lemma inv_sqrt_checked_zero : inv_sqrt_checked (0 : ZMod p) = ((0 : ZMod p), false) := by
  delta inv_sqrt_checked; rw [if_pos rfl]

end curve25519_dalek.math
