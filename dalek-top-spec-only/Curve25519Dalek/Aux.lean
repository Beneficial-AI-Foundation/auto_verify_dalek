import Aeneas
import Curve25519Dalek.Math.Basic
import Mathlib.Data.Nat.Digits.Lemmas
import Mathlib.Algebra.Order.BigOperators.Group.Finset

set_option linter.style.longLine false

set_option linter.hashCommand false
#setup_aeneas_simps

open Aeneas.Std Result

attribute [-simp] Int.reducePow Nat.reducePow


/-- OR-ing a value `b < 2^8` shifted by `n` (with `n + 8 ≤ 64`, truncated mod `2^64`) into an
accumulator `acc < 2^n` is the same as adding `2^n * b`. Used for byte-packing loops. -/
theorem Nat.or_shiftLeft_mod_eq_add {acc b n : ℕ} (hacc : acc < 2 ^ n) (hb : b < 2 ^ 8)
    (hn : n + 8 ≤ 64) : acc ||| (b <<< n % 2 ^ 64) = acc + 2 ^ n * b := by
  have hlt : b * 2 ^ n < 2 ^ 64 := by
    calc b * 2 ^ n < 2 ^ 8 * 2 ^ n := Nat.mul_lt_mul_of_pos_right hb (Nat.two_pow_pos n)
      _ = 2 ^ (8 + n) := (Nat.pow_add 2 8 n).symm
      _ ≤ 2 ^ 64 := Nat.pow_le_pow_right (by decide) (by omega)
  rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt hlt, Nat.or_comm, Nat.mul_comm,
    ← Nat.two_pow_add_eq_or_of_lt hacc]
  omega

/-- Bound companion of `Nat.or_shiftLeft_mod_eq_add`. -/
theorem Nat.add_two_pow_mul_lt {acc b n : ℕ} (hacc : acc < 2 ^ n) (hb : b < 2 ^ 8) :
    acc + 2 ^ n * b < 2 ^ (n + 8) := by
  have : 2 ^ n * b ≤ 2 ^ n * (2 ^ 8 - 1) := Nat.mul_le_mul_left _ (by omega)
  rw [Nat.pow_add]
  have h2 : 2 ^ n * (2 ^ 8 - 1) + 2 ^ n = 2 ^ n * 2 ^ 8 := by
    rw [Nat.mul_sub, Nat.mul_one]; have : 2 ^ n ≤ 2 ^ n * 2 ^ 8 := Nat.le_mul_of_pos_right _ (by decide); omega
  omega

/-- Limb repacking from 64-bit words into 52-bit limbs: combining the high `m` bits of `a`
(shifted right by `k`, with `k + m = 64`) with `b` shifted left by `m` (truncated mod `2^64`)
and masking to 52 bits yields `a / 2^k + 2^m * (b % 2^(52 - m))`. -/
theorem Nat.shr_or_shl_mask52 {a b k m : ℕ} (ha : a < 2 ^ 64) (hkm : k + m = 64)
    (hm : m ≤ 52) :
    (a >>> k ||| (b <<< m % 2 ^ 64)) &&& (2 ^ 52 - 1) = a / 2 ^ k + 2 ^ m * (b % 2 ^ (52 - m)) := by
  have hpow : (2 : ℕ) ^ 64 = 2 ^ m * 2 ^ k := by rw [← Nat.pow_add]; congr 1; omega
  have hlo : a / 2 ^ k < 2 ^ m := by
    rw [Nat.div_lt_iff_lt_mul (Nat.two_pow_pos k), ← hpow]; exact ha
  have hshl : b <<< m % 2 ^ 64 = 2 ^ m * (b % 2 ^ k) := by
    rw [Nat.shiftLeft_eq, hpow, Nat.mul_comm b, Nat.mul_mod_mul_left]
  rw [Nat.shiftRight_eq_div_pow, hshl, Nat.or_comm, ← Nat.two_pow_add_eq_or_of_lt hlo,
    Nat.and_two_pow_sub_one_eq_mod]
  have h52 : (2 : ℕ) ^ 52 = 2 ^ m * 2 ^ (52 - m) := by rw [← Nat.pow_add]; congr 1; omega
  have e1 : (2 ^ m * (b % 2 ^ k) + a / 2 ^ k) % 2 ^ m = a / 2 ^ k := by
    rw [Nat.mul_add_mod, Nat.mod_eq_of_lt hlo]
  have e2 : (2 ^ m * (b % 2 ^ k) + a / 2 ^ k) / 2 ^ m = b % 2 ^ k := by
    rw [Nat.add_comm, Nat.add_mul_div_left _ _ (Nat.two_pow_pos m), Nat.div_eq_of_lt hlo,
      Nat.zero_add]
  rw [h52, Nat.mod_mul, e1, e2, Nat.mod_mod_of_dvd _ (Nat.pow_dvd_pow 2 (by omega)),
    Nat.add_comm]

/-- Little-endian value of nine 52-bit-radix `u128` limbs (e.g. the unreduced product of two
`Scalar52`s fed to `montgomery_reduce`). -/
def U128x9_as_Nat (limbs : Array U128 9#usize) : Nat :=
  ∑ i ∈ Finset.range 9, 2 ^ (52 * i) * (limbs[i]!).val

set_option exponentiation.threshold 500 in
/-- Expansion of `U128x9_as_Nat` into its nine limbs. -/
theorem U128x9_as_Nat_expand (limbs : Array U128 9#usize) :
    U128x9_as_Nat limbs = (limbs.val[0]!).val + 2 ^ 52 * (limbs.val[1]!).val +
      2 ^ 104 * (limbs.val[2]!).val + 2 ^ 156 * (limbs.val[3]!).val +
      2 ^ 208 * (limbs.val[4]!).val + 2 ^ 260 * (limbs.val[5]!).val +
      2 ^ 312 * (limbs.val[6]!).val + 2 ^ 364 * (limbs.val[7]!).val +
      2 ^ 416 * (limbs.val[8]!).val := by
  unfold U128x9_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq]
  ring_nf

/-- Expansion of `Scalar52_as_Nat` of an explicitly built five-limb array. -/
theorem Scalar52_as_Nat_make (r0 r1 r2 r3 r4 : U64) :
    Scalar52_as_Nat (Array.make 5#usize [r0, r1, r2, r3, r4]) =
      r0.val + 2 ^ 52 * r1.val + 2 ^ 104 * r2.val + 2 ^ 156 * r3.val + 2 ^ 208 * r4.val := by
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq, Array.make]
  simp only [List.getElem!_cons_zero, List.getElem!_cons_succ]
  ring_nf
