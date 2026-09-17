import Aeneas
import Curve25519Dalek.Math.Basic
import Mathlib.Data.Nat.Digits.Lemmas
import Mathlib.Algebra.Order.BigOperators.Group.Finset

set_option linter.style.longLine false

/-! # Auxiliary theorems

Theorems which are useful for proving spec theorems in this project but aren't available upstream.
This file is for theorems which depend only on Defs.lean, not on Funs.lean or Types.lean. -/

set_option linter.hashCommand false
#setup_aeneas_simps

open Aeneas.Std Result

attribute [-simp] Int.reducePow Nat.reducePow

/-- Right-shifting a 64-bit value by 51 bits leaves at most 13 bits so bounded by 2^13 - 1. -/
theorem U64_shiftRight_le (a : U64) : a.val >>> 51 ≤ 2 ^ 13 - 1 := by
  sorry
/-- Right shift by 51 is equivalent to division by 2^51 -/
theorem Aeneas.Std.U64.shiftRight_51 (x : U64) : x.val >>> 51 = x.val / 2^51 := by
  sorry
theorem Array.val_getElem!_eq' (bs : Array U64 5#usize) (i : Nat) (h : i < bs.length) :
    (bs.val)[i]! = bs[i] := by
  sorry
/-- Setting the j part of an array doesn't change the i part if i ≠ j -/
@[simp]
theorem Array.set_of_ne (bs : Array U64 5#usize) (a : U64) (i j : Nat) (hi : i < bs.length)
    (hj : j < bs.length) (h : i ≠ j) :
    (bs.set j#usize a)[i]! = bs[i] := by
  sorry
/-- Setting the j part of an array doesn't change the i part if i ≠ j -/
theorem Array.set_of_ne' (bs : Array U64 5#usize) (a : U64) (i : Nat) (j : Usize) (hi : i < bs.length)
    (h : i ≠ j) :
    (bs.set j a)[i]! = bs[i] := by
  sorry
/-- Convert GetElem (Nat index) to getElem! for Aeneas Array -/
theorem Array.getElem_eq_getElem! (bs : Array U64 5#usize) (i : Nat) (hi : i < bs.length) :
    (bs[i] : U64) = bs[i]! := by
  sorry
/-- Convert GetElem (Usize index) to getElem! for Aeneas Array -/
theorem Array.getElem_usize_eq_getElem! (bs : Array U64 5#usize) (i : Usize)
    (hi : i.val < bs.length) :
    (bs[i] : U64) = bs[i.val]! := by
  sorry
/-- Like set_of_ne but returns getElem! on both sides -/
theorem Array.set_of_ne_getElem! (bs : Array U64 5#usize) (a : U64) (i j : Nat) (hi : i < bs.length)
    (hj : j < bs.length) (h : i ≠ j) :
    (bs.set j#usize a)[i]! = bs[i]! := by
  sorry
/-- Setting the j part of an array gives exactly the i part if i = j -/
theorem Array.set_of_eq (bs : Array U64 5#usize) (a : U64) (i : Nat) (hi : i < bs.length) :
    (bs.set i#usize a)[i]! = a := by
  sorry
/-- If a 32-byte array represents a value less than `2 ^ 252`, then the high bit (bit 7) of byte 31
must be 0. -/
theorem high_bit_zero_of_lt_255 (bytes : Array U8 32#usize) (h : U8x32_as_Nat bytes < 2 ^ 255) :
    bytes.val[31]!.val >>> 7 = 0 := by
  sorry
/-- If a 32-byte array represents a value less than `L`, then the high bit (bit 7) of byte 31
must be 0. -/
theorem high_bit_zero_of_lt_L (bytes : Array U8 32#usize) (h : U8x32_as_Nat bytes < L) :
    bytes.val[31]!.val >>> 7 = 0 := by
  sorry
/-- If `Scalar52_as_Nat a < 2^259`, then the top limb `a[4]` is bounded by `2^51`.
This follows because `2^208 * a[4] ≤ Scalar52_as_Nat a < 2^259` implies `a[4] < 2^51`. -/
theorem Scalar52_top_limb_lt_of_as_Nat_lt (a : Array U64 5#usize)
    (h : Scalar52_as_Nat a < 2 ^ 259) : a[4]!.val < 2 ^ 51 := by
  sorry
/-- The function U8x32_as_Nat can be represented via Nat.ofDigits applied to an appropriate
list representation of the input array -/
lemma U8x32_as_Nat_is_NatofDigits (a : Aeneas.Std.Array U8 32#usize) :
    U8x32_as_Nat a = Nat.ofDigits (2 ^ 8) (List.ofFn fun i : Fin 32 => a[i]!.val) := by
  sorry
/-! ## Bridge between U8x32_as_Nat and U8x32_as_Field

`U8x32_as_Nat` (Finset.sum in ℕ) and `U8x32_as_Field` (Horner foldr in ZMod p) compute the same
little-endian byte interpretation but in different types. The bridge goes through `Nat.ofDigits`:

  U8x32_as_Nat ──(is_NatofDigits)──▶ Nat.ofDigits 256 [b₀.val, ..., b₃₁.val]
                                        │
                                   (ofDigits = foldr)
                                        │
                                        ▼
  U8x32_as_Field ◀──(Nat.cast)──── List.foldr Horner₂₅₆ 0 bytes.val
-/

/-- `Nat.ofDigits b l` equals Horner evaluation via `foldr`. -/
private lemma ofDigits_eq_foldr (b : ℕ) (l : List ℕ) :
    Nat.ofDigits b l = l.foldr (fun d acc => d + b * acc) 0 := by
  induction l with
  | nil => simp [Nat.ofDigits]
  | cons h t ih => simp [Nat.ofDigits, ih]

/-- `Nat.cast` commutes with Horner evaluation on a byte list. -/
 lemma horner_natCast (l : List U8) :
    ((l.foldr (fun (b : U8) (acc : ℕ) => b.val + 256 * acc) 0 : ℕ) : ZMod p) =
    l.foldr (fun (b : U8) (acc : ZMod p) => (b.val : ZMod p) + 256 * acc) 0 := by
  sorry
/-- The byte-value list produced by `List.ofFn` on Array indices equals `List.map` on the
    underlying list. Bridges the `Fin`-indexed view from `Nat.ofDigits` to the raw list view. -/
private lemma ofFn_val_eq_map_val (a : Aeneas.Std.Array U8 32#usize) :
    (List.ofFn fun i : Fin 32 => (a[i]! : U8).val) = a.val.map (fun b => b.val) := by
  simp only [Fin.getElem!_fin, Array.getElem!_Nat_eq]
  apply List.ext_getElem
  · simp [a.property]
  · intro i hi1 hi2
    simp only [List.getElem_ofFn, List.getElem_map]
    congr 1
    rw [getElem!_pos (h := by rw [List.length_map] at hi2; omega)]

/-- `U8x32_as_Nat` equals Horner evaluation at base 256 on the underlying byte list. -/
lemma U8x32_as_Nat_eq_foldr (a : Aeneas.Std.Array U8 32#usize) :
    U8x32_as_Nat a = a.val.foldr (fun b (acc : ℕ) => b.val + 256 * acc) 0 := by
  sorry
/-- **Bridge lemma**: `U8x32_as_Field` and `U8x32_as_Nat` compute the same value,
    just in different types (ZMod p vs ℕ). -/
lemma U8x32_as_Field_eq_cast (a : Aeneas.Std.Array U8 32#usize) :
    U8x32_as_Field a = ((U8x32_as_Nat a : ℕ) : ZMod p) := by
  sorry
/-- The function `U8x32_as_Nat` is injective: if two 32-byte arrays produce the same natural
number representation, then the input arrays must be equal. -/
lemma U8x32_as_Nat_injective : Function.Injective U8x32_as_Nat := by
  sorry
lemma land_pow_two_sub_one_eq_mod (a n : Nat) :
    a &&& (2^n - 1) = a % 2^n := by
  sorry
/-! ## UScalar cast lemmas for carry propagation

These lemmas capture the Nat interpretation of casting patterns used in
field element carry propagation:
- `((x >> 51) as u64) as u128` extracts carry: `(x / 2^51) % 2^64`
- `(x as u64) & MASK` extracts remainder: `x % 2^51`
-/

/-- Casting U128 to U64 truncates to lower 64 bits -/
@[simp]
theorem U128_cast_U64_val (x : U128) : (UScalar.cast .U64 x).val = x.val % 2^64 := by
  sorry
/-- Casting U64 to U128 preserves value (widening) -/
@[simp]
theorem U64_cast_U128_val (x : U64) : (UScalar.cast .U128 x).val = x.val := by
  sorry
/-- The double-cast pattern `((x : U128).cast U64).cast U128` gives `x % 2^64` -/
@[simp]
theorem U128_cast_U64_cast_U128_val (x : U128) :
    (UScalar.cast .U128 (UScalar.cast .U64 x)).val = x.val % 2^64 := by
  sorry
/-- When `x < 2^115`, the carry `x / 2^51` fits in U64 without truncation -/
theorem carry_fits_U64 (x : ℕ) (hx : x < 2 ^ 115) : x / 2 ^ 51 < 2 ^ 64 := by
  sorry
/-- When the shift result fits in U64, the double-cast preserves it exactly -/
theorem double_cast_of_lt (x : ℕ) (hx : x < 2 ^ 64) :
    x % 2 ^ 64 % 2 ^ 128 = x := by
  sorry
/-- Key lemma: when `c < 2^115`, the carry extraction `(c / 2^51) % 2^64` equals `c / 2^51` -/
theorem carry_mod_eq (c : ℕ) (hc : c < 2 ^ 115) : (c / 2 ^ 51) % 2 ^ 64 = c / 2 ^ 51 := by
  sorry
/-! ## Bitwise OR equals addition for disjoint ranges -/

/-- Nat.bit decomposition: every natural number is `bit (testBit 0) (n / 2)`. -/
private lemma bit_decomp (a : Nat) : a = Nat.bit (a.testBit 0) (a / 2) := by
  rw [Nat.testBit_zero]
  unfold Nat.bit
  have := Nat.div_add_mod a 2
  rcases Nat.mod_two_eq_zero_or_one a with h | h <;> simp [h] <;> omega

/-- OR of a value below `2^k` with a multiple of `2^k` equals their sum,
    because the bit ranges are disjoint. -/
lemma or_mul_pow_two_eq_add (a b k : Nat) (ha : a < 2 ^ k) :
    a ||| (b * 2 ^ k) = a + b * 2 ^ k := by
  sorry
/-- If `x + n * m = y` then `x ≡ y [MOD m]`. -/
lemma modeq_of_add_mul_eq (x y n m : ℕ) (h : x + n * m = y) :
    Nat.ModEq m x y := by
  sorry
/-- Converts pointwise limb-wise addition to `Field51_as_Nat` addition. -/
lemma pointwise_add_Field51_as_Nat (a b c : Array U64 5#usize)
    (h : ∀ i < 5, c[i]!.val = a[i]!.val + b[i]!.val) :
    Field51_as_Nat c = Field51_as_Nat a + Field51_as_Nat b := by
  sorry
