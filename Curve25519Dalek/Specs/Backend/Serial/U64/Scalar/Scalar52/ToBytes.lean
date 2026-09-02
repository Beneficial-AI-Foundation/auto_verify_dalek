




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.BitList















































































open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52
open List BitList
attribute [local simp] Array.length_eq














theorem List.extract_append_extract {α : Type*} (l : List α) (a b c : Nat)
    (hab : a ≤ b) (hbc : b ≤ c) :
    l.extract a b ++ l.extract b c = l.extract a c := by
  sorry
private lemma testBit_add_mul_pow_low (b q k i : Nat) (hb : b < 2 ^ k) (hi : i < k) :
    (b + 2^k * q).testBit i = b.testBit i := by
  have h1 : (b + 2^k * q) % 2^k = b := by
    rw [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hb]
  have h2 := Nat.testBit_mod_two_pow (b + 2^k * q) k i
  rw [h1] at h2; simp [hi] at h2; exact h2.symm

private lemma testBit_add_mul_pow_high (b q k i : Nat) (hb : b < 2 ^ k) (hi : k ≤ i) :
    (b + 2^k * q).testBit i = (2^k * q).testBit i := by
  set n := i - k
  have hi_eq : i = n + k := by omega
  rw [hi_eq, Nat.testBit_add, Nat.testBit_add]
  congr 1
  rw [Nat.add_mul_div_left _ _ (by positivity : (0 : Nat) < 2^k),
      Nat.div_eq_of_lt hb, Nat.zero_add,
      Nat.mul_div_cancel_left _ (by positivity : (0 : Nat) < 2^k)]



private theorem nat_or_eq_add (a b k : Nat) (ha : a % 2 ^ k = 0) (hb : b < 2 ^ k) :
    a ||| b = a + b := by
  have ha_low : ∀ j, j < k → a.testBit j = false := by
    intro j hj
    have h1 := Nat.testBit_mod_two_pow a k j
    rw [ha] at h1; simp_all
  have hb_high : ∀ j, j ≥ k → b.testBit j = false := by
    intro j hj
    exact Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le hb (Nat.pow_le_pow_right (by omega) hj))
  have ha_eq : a = 2^k * (a / 2^k) := by have := Nat.div_add_mod a (2^k); omega
  apply Nat.eq_of_testBit_eq; intro i
  rw [Nat.testBit_or]
  by_cases hi : i < k
  · rw [ha_low i hi, Bool.false_or, ha_eq, Nat.add_comm]
    exact (testBit_add_mul_pow_low b (a / 2^k) k i hb hi).symm
  · rw [hb_high i (by omega), Bool.or_false, ha_eq, Nat.add_comm]
    exact (testBit_add_mul_pow_high b (a / 2^k) k i hb (by omega)).symm


private theorem ofNat_zero (w : Nat) : ofNat w 0 = List.replicate w false := by
  induction w with
  | zero => simp [ofNat]
  | succ w ih => simp [ofNat, ih, List.replicate_succ]


private theorem toNat_replicate_false (k : Nat) : toNat (List.replicate k false) = 0 := by
  induction k with
  | zero => simp [toNat]
  | succ k ih => simp [List.replicate_succ, toNat, ih]


private theorem val_mod_of_replicate_prefix (x : U64) (k : Nat) (rest : List Bool)
    (hx : ofU64 x = List.replicate k false ++ rest) : x.val % 2 ^ k = 0 := by
  have := congr_arg toNat hx
  grind [Nat.mul_comm, Nat.mul_mod_right, toNat_ofU64, toNat_append, toNat_replicate_false]


private theorem val_lt_of_shift_right (x y : U64) (shift bits : Nat)
    (hx : ofU64 x = (ofU64 y).drop shift ++ List.replicate shift false)
    (hy : y.val < 2 ^ (shift + bits)) : x.val < 2 ^ bits := by
  have h := congr_arg toNat hx
  rw [toNat_ofU64, toNat_append, toNat_drop, toNat_ofU64,
    toNat_replicate_false, length_drop, ofU64_length] at h
  simp only [Nat.zero_mul, Nat.add_zero] at h
  rw [h]; exact Nat.div_lt_of_lt_mul (by rwa [← Nat.pow_add])


theorem U64.ShiftRight_IScalar_bitList_spec {ty1} (x : U64) (y : IScalar ty1)
    (hy0 : 0 ≤ y.val) (hy1 : y.val < 64) :
    (x >>> y) ⦃ (z : UScalar UScalarTy.U64) =>
      ofU64 z = (ofU64 x).drop y.toNat ++ List.replicate y.toNat false ⦄ := by
  sorry

@[simp]
theorem ofU8_cast_eq_ofU64_take (x : U64) : ofU8 (UScalar.cast .U8 x) = (ofU64 x).take 8 := by
  sorry

theorem U64.ShiftLeft_IScalar_bitList_spec {ty1} (x : U64) (y : IScalar ty1)
    (hy : 0 ≤ y.val) (hy' : y.val < 64) :
    (x <<< y) ⦃ (z : UScalar UScalarTy.U64) =>
      ofU64 z = List.replicate y.toNat false ++ (ofU64 x).take (64 - y.toNat) ⦄ := by
  sorry


theorem ofU64_or_non_overlapping (x y : U64) (k : Nat) (hk : k ≤ 64)
    (hx : x.val % 2 ^ k = 0) (hy : y.val < 2 ^ k) :
    ofU64 (x ||| y) = (ofU64 y).take k ++ (ofU64 x).drop k := by
  sorry


private theorem ofU64_of_or_bv (x y z : U64) (k : Nat) (hk : k ≤ 64) (hx : x.val % 2 ^ k = 0)
    (hy : y.val < 2 ^ k) (hbv : z.bv = y.bv ||| x.bv) :
    ofU64 z = (ofU64 y).take k ++ (ofU64 x).drop k := by
  have heq : z = x ||| y := by
    have : z.bv = (x ||| y).bv := by
      rw [hbv, UScalar.bv_or]; ext i; simp [Bool.or_comm]
    have := congrArg BitVec.toNat this; scalar_tac
  rw [heq]; exact ofU64_or_non_overlapping x y k hk hx hy





theorem Scalar52_top_limb_lt_of_canonical (a : Array U64 5#usize) (h : Scalar52_as_Nat a < L) :
  (a : List U64)[4]!.val < 2 ^ 45 := by
  sorry


private theorem shared_byte_recombine (x a : Nat) :
    (x % 2 ^ 4) * 2 ^ a + (x / 2 ^ 4) * 2 ^ (a + 4) = x * 2 ^ a := by
  conv_lhs => rw [show (2 : Nat) ^ (a + 4) = 2 ^ 4 * 2 ^ a from by ring]
  have : x / 2 ^ 4 * (2 ^ 4 * 2 ^ a) = x / 2 ^ 4 * 2 ^ 4 * 2 ^ a := by ring
  rw [this, ← Nat.add_mul]
  grind


private theorem scalar52_eq_of_bitList_limbs (a : Scalar52) (b : Aeneas.Std.Array U8 32#usize)
    (h : ∀ i < 5, (a : List U64)[i]!.val < 2 ^ 52) (h' : (a : List U64)[4]!.val < 2 ^ 48)
    (hlimb0 : (ofU64 (a : List U64)[0]!).take 52 ≈ₗ ofU8 b[0]! ++ ofU8 b[1]! ++ ofU8 b[2]! ++
        ofU8 b[3]! ++ ofU8 b[4]! ++ ofU8 b[5]! ++ (ofU8 b[6]!).take 4)
    (hlimb1 : (ofU64 (a : List U64)[1]!).take 52 ≈ₗ (ofU8 b[6]!).drop 4 ++
        ofU8 b[7]! ++ ofU8 b[8]! ++ ofU8 b[9]! ++ ofU8 b[10]! ++ ofU8 b[11]! ++ ofU8 b[12]!)
    (hlimb2 : (ofU64 (a : List U64)[2]!).take 52 ≈ₗ ofU8 b[13]! ++ ofU8 b[14]! ++ ofU8 b[15]! ++
        ofU8 b[16]! ++ ofU8 b[17]! ++ ofU8 b[18]! ++ (ofU8 b[19]!).take 4)
    (hlimb3 : (ofU64 (a : List U64)[3]!).take 52 ≈ₗ (ofU8 b[19]!).drop 4 ++
        ofU8 b[20]! ++ ofU8 b[21]! ++ ofU8 b[22]! ++ ofU8 b[23]! ++ ofU8 b[24]! ++ ofU8 b[25]!)
    (hlimb4 : (ofU64 (a : List U64)[4]!).take 48 ≈ₗ ofU8 b[26]! ++ ofU8 b[27]! ++ ofU8 b[28]! ++
        ofU8 b[29]! ++ ofU8 b[30]! ++ ofU8 b[31]!) :
    U8x32_as_Nat b = Scalar52_as_Nat a := by

  have h0 := hlimb0.toNat_eq
  have h1 := hlimb1.toNat_eq
  have h2 := hlimb2.toNat_eq
  have h3 := hlimb3.toNat_eq
  have h4 := hlimb4.toNat_eq

  simp only [toNat_take, toNat_drop, toNat_append, toNat_ofU8, toNat_ofU64, ofU8_length,
    length_drop, length_append, Nat.reducePow, Nat.reduceSub, Nat.reduceAdd] at h0 h1 h2 h3 h4

  unfold U8x32_as_Nat Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.range_zero, Finset.sum_empty, zero_add,
    Nat.reducePow, Nat.reduceMul, one_mul]

  have hb0 := h 0 (by omega)
  have hb1 := h 1 (by omega)
  have hb2 := h 2 (by omega)
  have hb3 := h 3 (by omega)
  have hb6 := shared_byte_recombine b[6]!.val 48
  have hb19 := shared_byte_recombine b[19]!.val 152




  have hls : a.val.length = 5 := a.property
  have hlr : b.val.length = 32 := b.property
  simp only [Array.getElem!_Nat_eq, List.getElem!_eq_getElem?_getD,
    List.getElem?_eq_getElem, Option.getD_some, hls, hlr, Nat.reduceLT] at *
  grind



theorem scalar52_eq_of_bitList_bytes
    (self : Scalar52) (result : Aeneas.Std.Array U8 32#usize)
    (h : ∀ i < 5, (self : List U64)[i]!.val < 2 ^ 52) (h' : Scalar52_as_Nat self < L)
    (hb0 : ofU8 result[0]! = (ofU64 (self : List U64)[0]!).extract 0 8)
    (hb1 : ofU8 result[1]! = (ofU64 (self : List U64)[0]!).extract 8 16)
    (hb2 : ofU8 result[2]! = (ofU64 (self : List U64)[0]!).extract 16 24)
    (hb3 : ofU8 result[3]! = (ofU64 (self : List U64)[0]!).extract 24 32)
    (hb4 : ofU8 result[4]! = (ofU64 (self : List U64)[0]!).extract 32 40)
    (hb5 : ofU8 result[5]! = (ofU64 (self : List U64)[0]!).extract 40 48)
    (hb6 : ofU8 result[6]! = (ofU64 (self : List U64)[0]!).extract 48 52 ++
                             (ofU64 (self : List U64)[1]!).extract 0 4)
    (hb7 : ofU8 result[7]! = (ofU64 (self : List U64)[1]!).extract 4 12)
    (hb8 : ofU8 result[8]! = (ofU64 (self : List U64)[1]!).extract 12 20)
    (hb9 : ofU8 result[9]! = (ofU64 (self : List U64)[1]!).extract 20 28)
    (hb10 : ofU8 result[10]! = (ofU64 (self : List U64)[1]!).extract 28 36)
    (hb11 : ofU8 result[11]! = (ofU64 (self : List U64)[1]!).extract 36 44)
    (hb12 : ofU8 result[12]! = (ofU64 (self : List U64)[1]!).extract 44 52)
    (hb13 : ofU8 result[13]! = (ofU64 (self : List U64)[2]!).extract 0 8)
    (hb14 : ofU8 result[14]! = (ofU64 (self : List U64)[2]!).extract 8 16)
    (hb15 : ofU8 result[15]! = (ofU64 (self : List U64)[2]!).extract 16 24)
    (hb16 : ofU8 result[16]! = (ofU64 (self : List U64)[2]!).extract 24 32)
    (hb17 : ofU8 result[17]! = (ofU64 (self : List U64)[2]!).extract 32 40)
    (hb18 : ofU8 result[18]! = (ofU64 (self : List U64)[2]!).extract 40 48)
    (hb19 : ofU8 result[19]! = (ofU64 (self : List U64)[2]!).extract 48 52 ++
                               (ofU64 (self : List U64)[3]!).extract 0 4)
    (hb20 : ofU8 result[20]! = (ofU64 (self : List U64)[3]!).extract 4 12)
    (hb21 : ofU8 result[21]! = (ofU64 (self : List U64)[3]!).extract 12 20)
    (hb22 : ofU8 result[22]! = (ofU64 (self : List U64)[3]!).extract 20 28)
    (hb23 : ofU8 result[23]! = (ofU64 (self : List U64)[3]!).extract 28 36)
    (hb24 : ofU8 result[24]! = (ofU64 (self : List U64)[3]!).extract 36 44)
    (hb25 : ofU8 result[25]! = (ofU64 (self : List U64)[3]!).extract 44 52)
    (hb26 : ofU8 result[26]! = (ofU64 (self : List U64)[4]!).extract 0 8)
    (hb27 : ofU8 result[27]! = (ofU64 (self : List U64)[4]!).extract 8 16)
    (hb28 : ofU8 result[28]! = (ofU64 (self : List U64)[4]!).extract 16 24)
    (hb29 : ofU8 result[29]! = (ofU64 (self : List U64)[4]!).extract 24 32)
    (hb30 : ofU8 result[30]! = (ofU64 (self : List U64)[4]!).extract 32 40)
    (hb31 : ofU8 result[31]! = (ofU64 (self : List U64)[4]!).extract 40 48) :
    U8x32_as_Nat result = Scalar52_as_Nat self := by
  sorry
set_option maxHeartbeats 1600000 in



@[progress]
theorem to_bytes_spec (self : Scalar52) (h : ∀ i < 5, self[i]!.val < 2 ^ 52)
    (h' : Scalar52_as_Nat self < L) :
    to_bytes self ⦃ (result : Std.Array U8 32#usize) =>
      U8x32_as_Nat result = Scalar52_as_Nat self ∧ U8x32_as_Nat result < L ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
