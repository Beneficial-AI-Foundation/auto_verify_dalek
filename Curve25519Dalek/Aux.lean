import Aeneas
import Curve25519Dalek.Math.Basic
import Mathlib.Data.Nat.Digits.Lemmas
import Mathlib.Algebra.Order.BigOperators.Group.Finset

set_option linter.style.longLine false






set_option linter.hashCommand false
#setup_aeneas_simps

open Aeneas.Std Result

attribute [-simp] Int.reducePow Nat.reducePow


theorem U64_shiftRight_le (a : U64) : a.val >>> 51 ≤ 2 ^ 13 - 1 := by
  sorry

theorem Aeneas.Std.U64.shiftRight_51 (x : U64) : x.val >>> 51 = x.val / 2^51 := by
  sorry
theorem Array.val_getElem!_eq' (bs : Array U64 5#usize) (i : Nat) (h : i < bs.length) :
    (bs.val)[i]! = bs[i] := by
  sorry

@[simp]
theorem Array.set_of_ne (bs : Array U64 5#usize) (a : U64) (i j : Nat) (hi : i < bs.length)
    (hj : j < bs.length) (h : i ≠ j) :
    (bs.set j#usize a)[i]! = bs[i] := by
  sorry

theorem Array.set_of_ne' (bs : Array U64 5#usize) (a : U64) (i : Nat) (j : Usize) (hi : i < bs.length)
    (h : i ≠ j) :
    (bs.set j a)[i]! = bs[i] := by
  sorry

theorem Array.getElem_eq_getElem! (bs : Array U64 5#usize) (i : Nat) (hi : i < bs.length) :
    (bs[i] : U64) = bs[i]! := by
  sorry

theorem Array.getElem_usize_eq_getElem! (bs : Array U64 5#usize) (i : Usize)
    (hi : i.val < bs.length) :
    (bs[i] : U64) = bs[i.val]! := by
  sorry

theorem Array.set_of_ne_getElem! (bs : Array U64 5#usize) (a : U64) (i j : Nat) (hi : i < bs.length)
    (hj : j < bs.length) (h : i ≠ j) :
    (bs.set j#usize a)[i]! = bs[i]! := by
  sorry

theorem Array.set_of_eq (bs : Array U64 5#usize) (a : U64) (i : Nat) (hi : i < bs.length) :
    (bs.set i#usize a)[i]! = a := by
  sorry


theorem high_bit_zero_of_lt_255 (bytes : Array U8 32#usize) (h : U8x32_as_Nat bytes < 2 ^ 255) :
    bytes.val[31]!.val >>> 7 = 0 := by
  sorry


theorem high_bit_zero_of_lt_L (bytes : Array U8 32#usize) (h : U8x32_as_Nat bytes < L) :
    bytes.val[31]!.val >>> 7 = 0 := by
  sorry


theorem Scalar52_top_limb_lt_of_as_Nat_lt (a : Array U64 5#usize)
    (h : Scalar52_as_Nat a < 2 ^ 259) : a[4]!.val < 2 ^ 51 := by
  sorry


lemma U8x32_as_Nat_is_NatofDigits (a : Aeneas.Std.Array U8 32#usize) :
    U8x32_as_Nat a = Nat.ofDigits (2 ^ 8) (List.ofFn fun i : Fin 32 => a[i]!.val) := by
  sorry














private lemma ofDigits_eq_foldr (b : ℕ) (l : List ℕ) :
    Nat.ofDigits b l = l.foldr (fun d acc => d + b * acc) 0 := by
  induction l with
  | nil => simp [Nat.ofDigits]
  | cons h t ih => simp [Nat.ofDigits, ih]


 lemma horner_natCast (l : List U8) :
    ((l.foldr (fun (b : U8) (acc : ℕ) => b.val + 256 * acc) 0 : ℕ) : ZMod p) =
    l.foldr (fun (b : U8) (acc : ZMod p) => (b.val : ZMod p) + 256 * acc) 0 := by
  sorry


private lemma ofFn_val_eq_map_val (a : Aeneas.Std.Array U8 32#usize) :
    (List.ofFn fun i : Fin 32 => (a[i]! : U8).val) = a.val.map (fun b => b.val) := by
  simp only [Fin.getElem!_fin, Array.getElem!_Nat_eq]
  apply List.ext_getElem
  · simp [a.property]
  · intro i hi1 hi2
    simp only [List.getElem_ofFn, List.getElem_map]
    congr 1
    rw [getElem!_pos (h := by rw [List.length_map] at hi2; omega)]


lemma U8x32_as_Nat_eq_foldr (a : Aeneas.Std.Array U8 32#usize) :
    U8x32_as_Nat a = a.val.foldr (fun b (acc : ℕ) => b.val + 256 * acc) 0 := by
  sorry


lemma U8x32_as_Field_eq_cast (a : Aeneas.Std.Array U8 32#usize) :
    U8x32_as_Field a = ((U8x32_as_Nat a : ℕ) : ZMod p) := by
  sorry


lemma U8x32_as_Nat_injective : Function.Injective U8x32_as_Nat := by
  sorry
lemma land_pow_two_sub_one_eq_mod (a n : Nat) :
    a &&& (2^n - 1) = a % 2^n := by
  sorry









@[simp]
theorem U128_cast_U64_val (x : U128) : (UScalar.cast .U64 x).val = x.val % 2^64 := by
  sorry

@[simp]
theorem U64_cast_U128_val (x : U64) : (UScalar.cast .U128 x).val = x.val := by
  sorry

@[simp]
theorem U128_cast_U64_cast_U128_val (x : U128) :
    (UScalar.cast .U128 (UScalar.cast .U64 x)).val = x.val % 2^64 := by
  sorry

theorem carry_fits_U64 (x : ℕ) (hx : x < 2 ^ 115) : x / 2 ^ 51 < 2 ^ 64 := by
  sorry

theorem double_cast_of_lt (x : ℕ) (hx : x < 2 ^ 64) :
    x % 2 ^ 64 % 2 ^ 128 = x := by
  sorry

theorem carry_mod_eq (c : ℕ) (hc : c < 2 ^ 115) : (c / 2 ^ 51) % 2 ^ 64 = c / 2 ^ 51 := by
  sorry



private lemma bit_decomp (a : Nat) : a = Nat.bit (a.testBit 0) (a / 2) := by
  rw [Nat.testBit_zero]
  unfold Nat.bit
  have := Nat.div_add_mod a 2
  rcases Nat.mod_two_eq_zero_or_one a with h | h <;> simp [h] <;> omega



lemma or_mul_pow_two_eq_add (a b k : Nat) (ha : a < 2 ^ k) :
    a ||| (b * 2 ^ k) = a + b * 2 ^ k := by
  sorry

lemma modeq_of_add_mul_eq (x y n m : ℕ) (h : x + n * m = y) :
    Nat.ModEq m x y := by
  sorry

lemma pointwise_add_Field51_as_Nat (a b c : Array U64 5#usize)
    (h : ∀ i < 5, c[i]!.val = a[i]!.val + b[i]!.val) :
    Field51_as_Nat c = Field51_as_Nat a + Field51_as_Nat b := by
  sorry
