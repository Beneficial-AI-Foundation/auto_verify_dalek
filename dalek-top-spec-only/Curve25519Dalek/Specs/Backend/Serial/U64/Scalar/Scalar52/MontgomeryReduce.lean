import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Index
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.IndexMut
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ZERO
import Curve25519Dalek.Aux

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.constants

/-- The underlying list of limbs of `L`. -/
theorem L_val : L.val = [671914833335277#u64, 3916664325105025#u64, 1367801#u64, 0#u64,
    17592186044416#u64] := by
  unfold L
  rfl

/-- The limbs of `L` as natural numbers. -/
theorem L_limbs :
    L[0]!.val = 671914833335277 ∧ L[1]!.val = 3916664325105025 ∧
    L[2]!.val = 1367801 ∧ L[3]!.val = 0 ∧
    L[4]!.val = 17592186044416 := by
  simp only [Array.getElem!_Nat_eq, L_val]
  decide

/-- All limbs of `L` are bounded by `2^52`. -/
theorem L_bounds : ∀ i < 5, L[i]!.val < 2 ^ 52 := by
  obtain ⟨h0, h1, h2, h3, h4⟩ := L_limbs
  intro i hi
  interval_cases i <;> simp only [h0, h1, h2, h3, h4] <;> norm_num

/-- `L` represents the group order `ℓ = 2^252 + 27742317777372353535851937790883648493`. -/
@[simp]
theorem L_spec : Scalar52_as_Nat L = _root_.L := by
  obtain ⟨h0, h1, h2, h3, h4⟩ := L_limbs
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, h0, h1, h2, h3, h4]
  unfold _root_.L
  rfl

end curve25519_dalek.backend.serial.u64.constants

namespace curve25519_dalek.backend.serial.u64.constants

/-- The value of `LFACTOR`. -/
@[simp]
theorem LFACTOR_val : LFACTOR.val = 1439961107955227 := by
  unfold LFACTOR
  rfl

/-- `LFACTOR` fits in 52 bits. -/
theorem LFACTOR_bound : LFACTOR.val < 2 ^ 52 := by
  rw [LFACTOR_val]; norm_num

/-- `LFACTOR = -L⁻¹ mod 2^52`, stated on the low limb `L[0]`. -/
theorem LFACTOR_spec : (L[0]!.val * LFACTOR.val + 1) % 2 ^ 52 = 0 := by
  rw [L_limbs.1, LFACTOR_val]
  norm_num

/-- `LFACTOR = -L⁻¹ mod 2^52`, stated on the full group order. -/
theorem LFACTOR_spec_L : (_root_.L * LFACTOR.val + 1) % 2 ^ 52 = 0 := by
  rw [LFACTOR_val]
  unfold _root_.L
  norm_num

end curve25519_dalek.backend.serial.u64.constants

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52.montgomery_reduce


/-- One Montgomery reduction step: `part1 sum` computes `p = sum * LFACTOR mod 2^52` and the
carry `(sum + p * L[0]) / 2^52`, where the division is exact. -/
@[progress]
theorem part1_spec (sum : U128) (h : sum.val < 2 ^ 127) :
    part1 sum ⦃ r =>
      r.2.val < 2 ^ 52 ∧
      r.2.val = sum.val * constants.LFACTOR.val % 2 ^ 52 ∧
      (sum.val + r.2.val * constants.L[0]!.val) % 2 ^ 52 = 0 ∧
      r.1.val = (sum.val + r.2.val * constants.L[0]!.val) / 2 ^ 52 ∧
      r.1.val * 2 ^ 52 = sum.val + r.2.val * constants.L[0]!.val ⦄ := by
  unfold part1
  progress as ⟨ i, hi ⟩
  progress as ⟨ i1, hi1 ⟩
  progress as ⟨ i2, hi2 ⟩
  progress as ⟨ i3, hi3 ⟩
  progress as ⟨ p, hp ⟩
  progress as ⟨ i4, hi4, hi4' ⟩
  progress as ⟨ i5, hi5 ⟩
  have hL0 : i4.val = 671914833335277 := by rw [hi4', constants.L_val]; rfl
  have hLF := constants.LFACTOR_val
  have hi3v : i3.val = 2 ^ 52 - 1 := by
    rw [hi3, hi2]; simp only [U64.size, U64.numBits, Nat.shiftLeft_eq]; norm_num
  have hpv : p.val = sum.val * constants.LFACTOR.val % 2 ^ 52 := by
    rw [hp, UScalar.val_and, hi3v, Nat.and_two_pow_sub_one_eq_mod, hi1,
      core.num.U64.wrapping_mul_val_eq, hi, UScalar.cast_val_eq]
    simp only [UScalarTy.numBits, show UScalar.size UScalarTy.U64 = 2 ^ 64 by simp [U64.size, U64.numBits]]
    rw [Nat.mod_mod_of_dvd _ (by norm_num : 2 ^ 52 ∣ 2 ^ 64), Nat.mul_mod,
      Nat.mod_mod_of_dvd _ (by norm_num : 2 ^ 52 ∣ 2 ^ 64), ← Nat.mul_mod]
  have hplt : p.val < 2 ^ 52 := by rw [hpv]; exact Nat.mod_lt _ (by norm_num)
  have hdiv : (sum.val + p.val * i4.val) % 2 ^ 52 = 0 := by
    rw [hpv, hL0, Nat.add_mod, Nat.mul_mod, Nat.mod_mod, ← Nat.mul_mod, ← Nat.add_mod, hLF]
    have : sum.val + sum.val * 1439961107955227 * 671914833335277 =
        sum.val * (1439961107955227 * 671914833335277 + 1) := by ring
    rw [this, Nat.mul_mod]
    norm_num
  have hi5lt : i5.val < 2 ^ 102 := by
    rw [hi5, hL0]
    calc p.val * 671914833335277 < 2 ^ 52 * 2 ^ 50 :=
          Nat.mul_lt_mul_of_lt_of_le hplt (by norm_num) (by norm_num)
      _ = 2 ^ 102 := by norm_num
  have hadd : sum.val + i5.val ≤ U128.max := by
    rw [U128.max_eq]
    have : (2 : ℕ) ^ 127 + 2 ^ 102 ≤ 340282366920938463463374607431768211455 := by norm_num
    omega
  progress as ⟨ i6, hi6 ⟩
  progress as ⟨ i7, hi7 ⟩
  simp only [Nat.shiftRight_eq_div_pow] at hi7
  rw [constants.L_limbs.1, ← hL0]
  refine ⟨hplt, hpv, hdiv, ?_, ?_⟩
  · rw [hi7, hi6, hi5]
  · rw [hi7, hi6, hi5]
    exact Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero hdiv)

/-- Carry split: `part2 sum` returns the carry `sum / 2^52` and the low 52-bit limb
`sum % 2^52`. -/
@[progress]
theorem part2_spec (sum : U128) :
    part2 sum ⦃ r =>
      r.2.val < 2 ^ 52 ∧
      r.2.val = sum.val % 2 ^ 52 ∧
      r.1.val = sum.val / 2 ^ 52 ∧
      r.1.val < 2 ^ 76 ∧
      r.1.val * 2 ^ 52 + r.2.val = sum.val ⦄ := by
  unfold part2
  progress as ⟨ i, hi ⟩
  progress as ⟨ i1, hi1 ⟩
  progress as ⟨ i2, hi2 ⟩
  progress as ⟨ w, hw ⟩
  progress as ⟨ i3, hi3 ⟩
  simp only [Nat.shiftRight_eq_div_pow] at hi3
  have hi2v : i2.val = 2 ^ 52 - 1 := by
    rw [hi2, hi1]; simp only [U64.size, U64.numBits, Nat.shiftLeft_eq]; norm_num
  have hwv : w.val = sum.val % 2 ^ 52 := by
    rw [hw, UScalar.val_and, hi2v, Nat.and_two_pow_sub_one_eq_mod, hi, UScalar.cast_val_eq]
    simp only [UScalarTy.numBits,
      show UScalar.size UScalarTy.U64 = 2 ^ 64 by simp [U64.size, U64.numBits]]
    rw [Nat.mod_mod_of_dvd _ (by norm_num : 2 ^ 52 ∣ 2 ^ 64)]
  have hs : sum.val < 2 ^ 128 := by scalar_tac
  refine ⟨?_, hwv, hi3, ?_, ?_⟩
  · rw [hwv]; exact Nat.mod_lt _ (by norm_num)
  · rw [hi3]; omega
  · rw [hi3, hwv]; exact Nat.div_add_mod' _ _

end curve25519_dalek.backend.serial.u64.scalar.Scalar52.montgomery_reduce

/-! ## Local specification of `sub`

`Sub.lean` (via `ConditionalAddL.lean`) imports this module, so the specifications of `sub`
and `conditional_add_l` are re-established here under `mr_`-prefixed names. -/

set_option exponentiation.threshold 260

attribute [-simp] Int.reducePow Nat.reducePow

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52.montgomery_reduce

theorem mr_sub_loop_step_arith (x y w : Nat) (hx : x < 2 ^ 52) (hy : y ≤ 2 ^ 52)
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

theorem mr_sub_loop_post (a b r : Array U64 5#usize) (i : Nat) (f0 f1 F : Int) (hi : i < 5)
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

/-- Local copy of `sub_loop_spec`. -/
theorem mr_sub_loop_spec (a b difference : Scalar52) (mask borrow : U64) (i : Usize)
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
    obtain ⟨hwlt, hwmod⟩ := mr_sub_loop_step_arith i1.val i4.val w.val hai (by omega) hwv
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
    progress with mr_sub_loop_spec as ⟨r, hr1, hr2, hr3, hr4⟩
    refine ⟨fun j hj => ?_, hr2, hr3, ?_⟩
    · rw [hr1 j (by omega), hs1ne j (by omega)]
    · rw [hi6] at hr4
      have hri : ((r.1.val[i.val]!).val : Int) = (a.val[i.val]!).val -
          ((b.val[i.val]!).val + ((borrow.val / 2 ^ 63 : Nat) : Int)) +
          2 ^ 52 * ((w.val / 2 ^ 63 : Nat) : Int) := by
        rw [hr1 i.val (by omega), hs1i, hi5v, hwmod, hi4, ← hi1', ← hi2', hi3v]
        push_cast; ring
      exact mr_sub_loop_post a b r.1 i.val _ _ _ hilt hri hr4
  · have hi5 : i.val = 5 := by scalar_tac
    rw [spec_ok]
    refine ⟨fun j _ => rfl, hd, by scalar_tac, ?_⟩
    simp [hi5]
termination_by 5 - i.val
decreasing_by
  all_goals scalar_tac

theorem mr_select_spec (a b : U64) (choice : subtle.Choice) :
    U64.Insts.SubtleConditionallySelectable.conditional_select a b choice ⦃ res =>
      res = if choice.val = 1#u8 then b else a ⦄ := by
  unfold U64.Insts.SubtleConditionallySelectable.conditional_select
  split <;> simp_all

theorem mr_Ico_sum_eq (a : Scalar52) :
    ∑ j ∈ Finset.Ico 0 5, 2 ^ (52 * j) * (a.val[j]!).val = Scalar52_as_Nat a := by
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq,
    Finset.sum_Ico_succ_top (Nat.zero_le _), Finset.Ico_self, Finset.sum_empty]

theorem mr_cal_loop_post (self s1 r : Array U64 5#usize) (Lc : Nat → Nat)
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

/-- Local copy of `conditional_add_l_loop_spec`. -/
theorem mr_cal_loop_spec (self : Scalar52) (condition : subtle.Choice)
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
    progress with mr_select_spec as ⟨addend, haddend⟩
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
    progress with mr_cal_loop_spec as ⟨r, hr1, hr2, hr3, hr4⟩
    refine ⟨fun j hj => ?_, hr2, hr3, ?_⟩
    · rw [hr1 j (by omega), hs1ne j (by omega)]
    · rw [hi6] at hr4
      have hri : (r.2.val[i.val]!).val = carry1.val % 2 ^ 52 := by
        rw [hr1 i.val (by omega), hs1i, hi5v]
      exact mr_cal_loop_post self (back i5) r.2
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

theorem mr_cal_sum_split (self : Scalar52) (b : Bool) :
    ∑ j ∈ Finset.Ico 0 5, 2 ^ (52 * j) * ((self.val[j]!).val +
      (if b then (constants.L.val[j]!).val else 0)) =
      Scalar52_as_Nat self + (if b then _root_.L else 0) := by
  rw [← mr_Ico_sum_eq self]
  cases b
  · simp
  · simp only [if_true, mul_add, Finset.sum_add_distrib, mr_Ico_sum_eq,
      constants.L_spec]

/-- Local copy of `conditional_add_l_spec`. -/
theorem mr_cal_spec (self : Scalar52) (condition : subtle.Choice)
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
  progress with mr_cal_loop_spec as ⟨r, _, hr2, hr3, hr4⟩
  refine ⟨hr2, hr3, ?_⟩
  have h := mr_cal_sum_split self (decide (condition.val = 1#u8))
  simp only [decide_eq_true_eq] at h
  rw [← h, ← mr_Ico_sum_eq r.2]
  simpa using hr4

theorem mr_as_Nat_lt (a : Scalar52) (ha : ∀ j, j < 5 → (a.val[j]!).val < 2 ^ 52) :
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

theorem mr_Ico_sum_sub (a b : Scalar52) :
    ∑ j ∈ Finset.Ico 0 5, (2 : Int) ^ (52 * j) * (((a.val[j]!).val : Int) - (b.val[j]!).val) =
      (Scalar52_as_Nat a : Int) - Scalar52_as_Nat b := by
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq,
    Finset.sum_Ico_succ_top (Nat.zero_le _), Finset.Ico_self, Finset.sum_empty]
  push_cast
  ring

theorem mr_sub_final_arith (A B D R f q : Nat) (hf : f ≤ 1) (hD : D < 2 ^ 260) (hR : R < 2 ^ 260)
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

theorem mr_choice_from_spec (x : U8) (h : x.val ≤ 1) :
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

/-- Local copy of (the first two conjuncts of) `sub_spec`. -/
theorem mr_sub_spec (a b : Scalar52)
    (ha : ∀ j, j < 5 → (a.val[j]!).val < 2 ^ 52)
    (hb : ∀ j, j < 5 → (b.val[j]!).val < 2 ^ 52)
    (hab : Scalar52_as_Nat b ≤ Scalar52_as_Nat a + _root_.L) :
    sub a b ⦃ r =>
      (∀ j, j < 5 → (r.val[j]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r + Scalar52_as_Nat b =
        Scalar52_as_Nat a + (if Scalar52_as_Nat a < Scalar52_as_Nat b then _root_.L else 0) ⦄ := by
  unfold sub
  progress as ⟨i, hi⟩
  progress as ⟨mask, hmask⟩
  have hmv : mask.val = 2 ^ 52 - 1 := by
    rw [hmask, hi]; simp [Nat.shiftLeft_eq, U64.size, U64.numBits]
    rw [Nat.mod_eq_of_lt (by norm_num)]
  have hz : ∀ j, j < 5 → (ZERO.val[j]!).val < 2 ^ 52 := by
    intro j _; rw [ZERO_val_getElem!]; simp
  progress with mr_sub_loop_spec as ⟨d, _, hd2, hd3, hd4⟩
  progress as ⟨i1, hi1⟩
  progress as ⟨i2, hi2⟩
  have hi1v : i1.val = d.2.val / 2 ^ 63 := by simp [hi1, Nat.shiftRight_eq_div_pow]
  have hi2v : i2.val = d.2.val / 2 ^ 63 := by
    rw [← hi1v, hi2, UScalar.cast_val_eq]; simp; omega
  progress with mr_choice_from_spec as ⟨c, hc⟩
  progress with mr_cal_spec as ⟨res, hr1, hr2, hr3⟩
  have hcond : (c.val = 1#u8) ↔ d.2.val / 2 ^ 63 = 1 := by
    rw [hc]; constructor
    · intro h; rw [← hi2v, h]; rfl
    · intro h; apply UScalar.eq_of_val_eq; rw [hi2v, h]; rfl
  have hD := mr_as_Nat_lt d.1 hd2
  have hR := mr_as_Nat_lt res.2 hr1
  have hloop : (Scalar52_as_Nat d.1 : Int) - 2 ^ 260 * ((d.2.val / 2 ^ 63 : Nat) : Int) =
      (Scalar52_as_Nat a : Int) - Scalar52_as_Nat b := by
    rw [← mr_Ico_sum_sub, ← mr_Ico_sum_eq d.1]
    simpa using hd4
  have hadd : Scalar52_as_Nat res.2 + 2 ^ 260 * (res.1.val / 2 ^ 52) =
      Scalar52_as_Nat d.1 + (if d.2.val / 2 ^ 63 = 1 then _root_.L else 0) := by
    rw [hr3]; simp only [hcond]
  exact ⟨hr1, mr_sub_final_arith _ _ _ _ _ _ hd3 hD hR hab hloop hadd⟩

end curve25519_dalek.backend.serial.u64.scalar.Scalar52.montgomery_reduce

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

set_option exponentiation.threshold 500 in
/-- Telescoping identity of the Montgomery reduction carry chain: the nine step equations
combine into `2^260 * (intermediate) = T + N * L`. -/
theorem montgomery_reduce_chain
    (a0 a1 a2 a3 a4 a5 a6 a7 a8 n0 n1 n2 n3 n4 c0 c1 c2 c3 c4 c5 c6 c7 c8 r0 r1 r2 r3 : Nat)
    (h0 : c0 * 2 ^ 52 = a0 + n0 * 671914833335277)
    (h1 : c1 * 2 ^ 52 = c0 + a1 + n0 * 3916664325105025 + n1 * 671914833335277)
    (h2 : c2 * 2 ^ 52 = c1 + a2 + n0 * 1367801 + n1 * 3916664325105025 + n2 * 671914833335277)
    (h3 : c3 * 2 ^ 52 = c2 + a3 + n1 * 1367801 + n2 * 3916664325105025 + n3 * 671914833335277)
    (h4 : c4 * 2 ^ 52 = c3 + a4 + n0 * 17592186044416 + n2 * 1367801 +
      n3 * 3916664325105025 + n4 * 671914833335277)
    (h5 : c5 * 2 ^ 52 + r0 = c4 + a5 + n1 * 17592186044416 + n3 * 1367801 +
      n4 * 3916664325105025)
    (h6 : c6 * 2 ^ 52 + r1 = c5 + a6 + n2 * 17592186044416 + n4 * 1367801)
    (h7 : c7 * 2 ^ 52 + r2 = c6 + a7 + n3 * 17592186044416)
    (h8 : c8 * 2 ^ 52 + r3 = c7 + a8 + n4 * 17592186044416) :
    2 ^ 260 * (r0 + 2 ^ 52 * r1 + 2 ^ 104 * r2 + 2 ^ 156 * r3 + 2 ^ 208 * c8) =
      (a0 + 2 ^ 52 * a1 + 2 ^ 104 * a2 + 2 ^ 156 * a3 + 2 ^ 208 * a4 + 2 ^ 260 * a5 +
        2 ^ 312 * a6 + 2 ^ 364 * a7 + 2 ^ 416 * a8) +
      (n0 + 2 ^ 52 * n1 + 2 ^ 104 * n2 + 2 ^ 156 * n3 + 2 ^ 208 * n4) * _root_.L := by
  have hL : _root_.L = 671914833335277 + 2 ^ 52 * 3916664325105025 + 2 ^ 104 * 1367801 +
      2 ^ 208 * 17592186044416 := by
    unfold _root_.L; norm_num
  rw [hL]
  zify at *
  linear_combination h0 + 2 ^ 52 * h1 + 2 ^ 104 * h2 + 2 ^ 156 * h3 + 2 ^ 208 * h4 +
    2 ^ 260 * h5 + 2 ^ 312 * h6 + 2 ^ 364 * h7 + 2 ^ 416 * h8

/-- From `2^260 * V = T + N * L` with `T < 2^260 * L` and `N < 2^260`, the intermediate value
`V` is below `2 * L`. -/
theorem montgomery_reduce_bound (T N V : Nat) (hT : T < 2 ^ 260 * _root_.L) (hN : N < 2 ^ 260)
    (h : 2 ^ 260 * V = T + N * _root_.L) : V < 2 * _root_.L := by
  have hLpos : 0 < _root_.L := by unfold _root_.L; norm_num
  have hNL : N * _root_.L < 2 ^ 260 * _root_.L := Nat.mul_lt_mul_of_pos_right hN hLpos
  have : 2 ^ 260 * V < 2 ^ 260 * (2 * _root_.L) := by rw [h]; linarith
  exact Nat.lt_of_mul_lt_mul_left this

/-- Final step of the Montgomery reduction: if `R` is the conditional subtraction of `L` from
`V` with `2^260 * V = T + N * L` and `V < 2 * L`, then `R * 2^260 ≡ T [MOD L]` and `R < L`. -/
theorem montgomery_reduce_final (R V T N L : Nat) (hV : 2 ^ 260 * V = T + N * L)
    (hR : R + L = V + (if V < L then L else 0)) (hV2 : V < 2 * L) :
    R * 2 ^ 260 ≡ T [MOD L] ∧ R < L := by
  split_ifs at hR with h
  · have hRV : R = V := by omega
    subst hRV
    refine ⟨?_, h⟩
    unfold Nat.ModEq
    rw [mul_comm, hV, Nat.add_mul_mod_self_right]
  · have hRV : V = R + L := by omega
    refine ⟨?_, by omega⟩
    unfold Nat.ModEq
    calc R * 2 ^ 260 % L = (R * 2 ^ 260 + 2 ^ 260 * L) % L := (Nat.add_mul_mod_self_right _ _ _).symm
      _ = (T + N * L) % L := by rw [← hV, hRV]; ring_nf
      _ = T % L := Nat.add_mul_mod_self_right _ _ _

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

set_option exponentiation.threshold 500 in
/-- Montgomery reduction: for nine `u128` limbs below `2^126` whose value `T` is below
`2^260 * L`, the result has limbs below `2^52`, is canonical (`< L`) and satisfies
`r * 2^260 ≡ T [MOD L]`. -/
@[progress]
theorem montgomery_reduce_spec (limbs : Array U128 9#usize)
    (hlimbs : ∀ i, i < 9 → (limbs.val[i]!).val < 2 ^ 126)
    (hT : U128x9_as_Nat limbs < 2 ^ 260 * _root_.L) :
    montgomery_reduce limbs ⦃ r =>
      (∀ i, i < 5 → (r.val[i]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r * 2 ^ 260 ≡ U128x9_as_Nat limbs [MOD _root_.L] ∧
      Scalar52_as_Nat r < _root_.L ⦄ := by
  have hL0 : (constants.L[0]!).val = 671914833335277 := constants.L_limbs.1
  unfold montgomery_reduce
  progress as ⟨a0, ha0⟩
  have ha0b : a0.val < 2 ^ 126 := by rw [ha0]; exact hlimbs 0 (by norm_num)
  have ha0b' : a0.val < 2 ^ 127 := by clear * - ha0b; omega
  progress as ⟨p0, hn0, _, _, _, hc0⟩
  rw [hL0] at hc0
  have hc0b : p0.1.val < 2 ^ 76 := by clear * - hc0 hn0 ha0b'; omega
  progress as ⟨a1, ha1⟩
  have ha1b : a1.val < 2 ^ 126 := by rw [ha1]; exact hlimbs 1 (by norm_num)
  have : p0.1.val + a1.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc0b ha1b; omega
  progress as ⟨i2, hi2⟩
  have hi2b : i2.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi2 hc0b ha1b; omega
  progress as ⟨i3, _, hi3'⟩
  have hi3v : i3.val = 3916664325105025 := by rw [hi3', constants.L_val]; rfl
  progress as ⟨i4, hi4⟩
  rw [hi3v] at hi4
  have hi4b : i4.val < 2 ^ 104 := by clear * - hi4 hn0; omega
  have : i2.val + i4.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi2b hi4b; omega
  progress as ⟨i5, hi5⟩
  have : i5.val < 2 ^ 127 := by clear * - hi5 hi2b hi4b; omega
  progress as ⟨p1, hn1, _, _, _, hc1⟩
  rw [hL0] at hc1
  have hc1b : p1.1.val < 2 ^ 76 := by clear * - hc1 hn1 this; omega
  -- step 2
  progress as ⟨a2, ha2⟩
  have ha2b : a2.val < 2 ^ 126 := by rw [ha2]; exact hlimbs 2 (by norm_num)
  have : p1.1.val + a2.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc1b ha2b; omega
  progress as ⟨i7, hi7⟩
  have hi7b : i7.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi7 hc1b ha2b; omega
  progress as ⟨i8, _, hi8'⟩
  have hi8v : i8.val = 1367801 := by rw [hi8', constants.L_val]; rfl
  progress as ⟨i9, hi9⟩
  rw [hi8v] at hi9
  have hi9b : i9.val < 2 ^ 104 := by clear * - hi9 hn0; omega
  have : i7.val + i9.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi7b hi9b; omega
  progress as ⟨i10, hi10⟩
  have hi10b : i10.val < 2 ^ 126 + 2 ^ 76 + 2 ^ 104 := by clear * - hi10 hi7b hi9b; omega
  progress as ⟨i11, hi11⟩
  rw [hi3v] at hi11
  have hi11b : i11.val < 2 ^ 104 := by clear * - hi11 hn1; omega
  have : i10.val + i11.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi10b hi11b; omega
  progress as ⟨i12, hi12⟩
  have : i12.val < 2 ^ 127 := by clear * - hi12 hi10b hi11b; omega
  progress as ⟨p2, hn2, _, _, _, hc2⟩
  rw [hL0] at hc2
  have hc2b : p2.1.val < 2 ^ 76 := by clear * - hc2 hn2 this; omega
  -- step 3
  progress as ⟨a3, ha3⟩
  have ha3b : a3.val < 2 ^ 126 := by rw [ha3]; exact hlimbs 3 (by norm_num)
  have : p2.1.val + a3.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc2b ha3b; omega
  progress as ⟨i14, hi14⟩
  have hi14b : i14.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi14 hc2b ha3b; omega
  progress as ⟨i15, hi15⟩
  rw [hi8v] at hi15
  have hi15b : i15.val < 2 ^ 104 := by clear * - hi15 hn1; omega
  have : i14.val + i15.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi14b hi15b; omega
  progress as ⟨i16, hi16⟩
  have hi16b : i16.val < 2 ^ 126 + 2 ^ 76 + 2 ^ 104 := by clear * - hi16 hi14b hi15b; omega
  progress as ⟨i17, hi17⟩
  rw [hi3v] at hi17
  have hi17b : i17.val < 2 ^ 104 := by clear * - hi17 hn2; omega
  have : i16.val + i17.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi16b hi17b; omega
  progress as ⟨i18, hi18⟩
  have : i18.val < 2 ^ 127 := by clear * - hi18 hi16b hi17b; omega
  progress as ⟨p3, hn3, _, _, _, hc3⟩
  rw [hL0] at hc3
  have hc3b : p3.1.val < 2 ^ 76 := by clear * - hc3 hn3 this; omega
  -- step 4
  progress as ⟨a4, ha4⟩
  have ha4b : a4.val < 2 ^ 126 := by rw [ha4]; exact hlimbs 4 (by norm_num)
  have : p3.1.val + a4.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc3b ha4b; omega
  progress as ⟨i20, hi20⟩
  have hi20b : i20.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi20 hc3b ha4b; omega
  progress as ⟨i21, _, hi21'⟩
  have hi21v : i21.val = 17592186044416 := by rw [hi21', constants.L_val]; rfl
  progress as ⟨i22, hi22⟩
  rw [hi21v] at hi22
  have hi22b : i22.val < 2 ^ 104 := by clear * - hi22 hn0; omega
  have : i20.val + i22.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi20b hi22b; omega
  progress as ⟨i23, hi23⟩
  have hi23b : i23.val < 2 ^ 126 + 2 ^ 76 + 2 ^ 104 := by clear * - hi23 hi20b hi22b; omega
  progress as ⟨i24, hi24⟩
  rw [hi8v] at hi24
  have hi24b : i24.val < 2 ^ 104 := by clear * - hi24 hn2; omega
  have : i23.val + i24.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi23b hi24b; omega
  progress as ⟨i25, hi25⟩
  have hi25b : i25.val < 2 ^ 126 + 2 ^ 76 + 2 * 2 ^ 104 := by clear * - hi25 hi23b hi24b; omega
  progress as ⟨i26, hi26⟩
  rw [hi3v] at hi26
  have hi26b : i26.val < 2 ^ 104 := by clear * - hi26 hn3; omega
  have : i25.val + i26.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi25b hi26b; omega
  progress as ⟨i27, hi27⟩
  have : i27.val < 2 ^ 127 := by clear * - hi27 hi25b hi26b; omega
  progress as ⟨p4, hn4, _, _, _, hc4⟩
  rw [hL0] at hc4
  have hc4b : p4.1.val < 2 ^ 76 := by clear * - hc4 hn4 this; omega
  -- step 5
  progress as ⟨a5, ha5⟩
  have ha5b : a5.val < 2 ^ 126 := by rw [ha5]; exact hlimbs 5 (by norm_num)
  have : p4.1.val + a5.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc4b ha5b; omega
  progress as ⟨i29, hi29⟩
  have hi29b : i29.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi29 hc4b ha5b; omega
  progress as ⟨i30, hi30⟩
  rw [hi21v] at hi30
  have hi30b : i30.val < 2 ^ 104 := by clear * - hi30 hn1; omega
  have : i29.val + i30.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi29b hi30b; omega
  progress as ⟨i31, hi31⟩
  have hi31b : i31.val < 2 ^ 126 + 2 ^ 76 + 2 ^ 104 := by clear * - hi31 hi29b hi30b; omega
  progress as ⟨i32, hi32⟩
  rw [hi8v] at hi32
  have hi32b : i32.val < 2 ^ 104 := by clear * - hi32 hn3; omega
  have : i31.val + i32.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi31b hi32b; omega
  progress as ⟨i33, hi33⟩
  have hi33b : i33.val < 2 ^ 126 + 2 ^ 76 + 2 * 2 ^ 104 := by clear * - hi33 hi31b hi32b; omega
  progress as ⟨i34, hi34⟩
  rw [hi3v] at hi34
  have hi34b : i34.val < 2 ^ 104 := by clear * - hi34 hn4; omega
  have : i33.val + i34.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi33b hi34b; omega
  progress as ⟨i35, hi35⟩
  progress as ⟨p5, hr0, _, _, hc5b, hc5⟩
  -- step 6
  progress as ⟨a6, ha6⟩
  have ha6b : a6.val < 2 ^ 126 := by rw [ha6]; exact hlimbs 6 (by norm_num)
  have : p5.1.val + a6.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc5b ha6b; omega
  progress as ⟨i37, hi37⟩
  have hi37b : i37.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi37 hc5b ha6b; omega
  progress as ⟨i38, hi38⟩
  rw [hi21v] at hi38
  have hi38b : i38.val < 2 ^ 104 := by clear * - hi38 hn2; omega
  have : i37.val + i38.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi37b hi38b; omega
  progress as ⟨i39, hi39⟩
  have hi39b : i39.val < 2 ^ 126 + 2 ^ 76 + 2 ^ 104 := by clear * - hi39 hi37b hi38b; omega
  progress as ⟨i40, hi40⟩
  rw [hi8v] at hi40
  have hi40b : i40.val < 2 ^ 104 := by clear * - hi40 hn4; omega
  have : i39.val + i40.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi39b hi40b; omega
  progress as ⟨i41, hi41⟩
  progress as ⟨p6, hr1, _, _, hc6b, hc6⟩
  -- step 7
  progress as ⟨a7, ha7⟩
  have ha7b : a7.val < 2 ^ 126 := by rw [ha7]; exact hlimbs 7 (by norm_num)
  have : p6.1.val + a7.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc6b ha7b; omega
  progress as ⟨i43, hi43⟩
  have hi43b : i43.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi43 hc6b ha7b; omega
  progress as ⟨i44, hi44⟩
  rw [hi21v] at hi44
  have hi44b : i44.val < 2 ^ 104 := by clear * - hi44 hn3; omega
  have : i43.val + i44.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi43b hi44b; omega
  progress as ⟨i45, hi45⟩
  progress as ⟨p7, hr2, _, _, hc7b, hc7⟩
  -- step 8
  progress as ⟨a8, ha8⟩
  have ha8b : a8.val < 2 ^ 126 := by rw [ha8]; exact hlimbs 8 (by norm_num)
  have : p7.1.val + a8.val ≤ U128.max := by rw [U128.max_eq]; clear * - hc7b ha8b; omega
  progress as ⟨i47, hi47⟩
  have hi47b : i47.val < 2 ^ 126 + 2 ^ 76 := by clear * - hi47 hc7b ha8b; omega
  progress as ⟨i48, hi48⟩
  rw [hi21v] at hi48
  have hi48b : i48.val < 2 ^ 104 := by clear * - hi48 hn4; omega
  have : i47.val + i48.val ≤ U128.max := by rw [U128.max_eq]; clear * - hi47b hi48b; omega
  progress as ⟨i49, hi49⟩
  progress as ⟨p8, hr3, _, _, hc8b, hc8⟩
  progress as ⟨r4, hr4⟩
  -- value of the intermediate result
  have hchain := montgomery_reduce_chain a0.val a1.val a2.val a3.val a4.val a5.val a6.val
    a7.val a8.val p0.2.val p1.2.val p2.2.val p3.2.val p4.2.val p0.1.val p1.1.val p2.1.val
    p3.1.val p4.1.val p5.1.val p6.1.val p7.1.val p8.1.val p5.2.val p6.2.val p7.2.val p8.2.val hc0
    (by clear * - hc1 hi5 hi2 hi4; omega)
    (by clear * - hc2 hi12 hi10 hi7 hi9 hi11; omega)
    (by clear * - hc3 hi18 hi16 hi14 hi15 hi17; omega)
    (by clear * - hc4 hi27 hi25 hi23 hi20 hi22 hi24 hi26; omega)
    (by clear * - hc5 hi35 hi33 hi31 hi29 hi30 hi32 hi34; omega)
    (by clear * - hc6 hi41 hi39 hi37 hi38 hi40; omega)
    (by clear * - hc7 hi45 hi43 hi44; omega)
    (by clear * - hc8 hi49 hi47 hi48; omega)
  have hTv : U128x9_as_Nat limbs = a0.val + 2 ^ 52 * a1.val + 2 ^ 104 * a2.val +
      2 ^ 156 * a3.val + 2 ^ 208 * a4.val + 2 ^ 260 * a5.val + 2 ^ 312 * a6.val +
      2 ^ 364 * a7.val + 2 ^ 416 * a8.val := by
    rw [U128x9_as_Nat_expand, ha0, ha1, ha2, ha3, ha4, ha5, ha6, ha7, ha8]
  rw [← hTv] at hchain
  have hN : p0.2.val + 2 ^ 52 * p1.2.val + 2 ^ 104 * p2.2.val + 2 ^ 156 * p3.2.val +
      2 ^ 208 * p4.2.val < 2 ^ 260 := by
    clear * - hn0 hn1 hn2 hn3 hn4; omega
  have hV2 := montgomery_reduce_bound _ _ _ hT hN hchain
  have hLnum : _root_.L =
      7237005577332262213973186563042994240857116359379907606001950938285454250989 := by
    unfold _root_.L; norm_num
  have hc8s : p8.1.val < 2 ^ 52 := by
    have h := hV2
    rw [hLnum] at h
    clear * - h; omega
  have hr4v : r4.val = p8.1.val := by
    clear * - hr4 hc8s; rw [hr4, UScalar.cast_val_eq]; simp; omega
  -- final conditional subtraction
  have hmk : ∀ j, j < 5 →
      ((Array.make 5#usize [p5.2, p6.2, p7.2, p8.2, r4]).val[j]!).val < 2 ^ 52 := by
    intro j hj
    interval_cases j <;>
      simp only [Array.make, List.getElem!_cons_zero, List.getElem!_cons_succ] <;>
      first | assumption | (rw [hr4v]; exact hc8s)
  have hLb : ∀ j, j < 5 → (constants.L.val[j]!).val < 2 ^ 52 := by
    intro j hj; simpa [Array.getElem!_Nat_eq] using constants.L_bounds j hj
  have hab : Scalar52_as_Nat constants.L ≤
      Scalar52_as_Nat (Array.make 5#usize [p5.2, p6.2, p7.2, p8.2, r4]) + _root_.L := by
    rw [constants.L_spec]; exact Nat.le_add_left _ _
  refine spec_mono (montgomery_reduce.mr_sub_spec _ _ hmk hLb hab) ?_
  rintro res ⟨hres1, hres2⟩
  rw [constants.L_spec, Scalar52_as_Nat_make, hr4v] at hres2
  obtain ⟨h1, h2⟩ := montgomery_reduce_final _ _ _ _ _ hchain hres2 hV2
  exact ⟨hres1, h1, h2⟩
