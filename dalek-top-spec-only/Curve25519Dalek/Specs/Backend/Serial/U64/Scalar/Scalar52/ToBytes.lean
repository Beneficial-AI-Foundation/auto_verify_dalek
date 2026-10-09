/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52
open List
attribute [local simp] Array.length_eq

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Writing all 32 bytes of a zero-initialised array in order yields exactly those bytes. -/
theorem to_bytes_set32_val (b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16 b17 b18
    b19 b20 b21 b22 b23 b24 b25 b26 b27 b28 b29 b30 b31 : U8) :
    (((((((((((((((((((((((((((((((((Array.repeat 32#usize 0#u8).set 0#usize b0).set 1#usize b1).set
      2#usize b2).set 3#usize b3).set 4#usize b4).set 5#usize b5).set 6#usize b6).set 7#usize b7).set
      8#usize b8).set 9#usize b9).set 10#usize b10).set 11#usize b11).set 12#usize b12).set
      13#usize b13).set 14#usize b14).set 15#usize b15).set 16#usize b16).set 17#usize b17).set
      18#usize b18).set 19#usize b19).set 20#usize b20).set 21#usize b21).set 22#usize b22).set
      23#usize b23).set 24#usize b24).set 25#usize b25).set 26#usize b26).set 27#usize b27).set
      28#usize b28).set 29#usize b29).set 30#usize b30).set 31#usize b31).val =
      [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19,
        b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31] := by
  simp [Array.set_val_eq, Array.repeat_val]

set_option exponentiation.threshold 500 in
/-- Expansion of `U8x32_as_Nat` for an array with explicitly known bytes. -/
theorem U8x32_as_Nat_of_val (r : Array U8 32#usize) (b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12
    b13 b14 b15 b16 b17 b18 b19 b20 b21 b22 b23 b24 b25 b26 b27 b28 b29 b30 b31 : U8)
    (hr : r.val = [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17,
      b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31]) :
    U8x32_as_Nat r = b0.val + 2 ^ 8 * b1.val + 2 ^ 16 * b2.val + 2 ^ 24 * b3.val +
      2 ^ 32 * b4.val + 2 ^ 40 * b5.val + 2 ^ 48 * b6.val + 2 ^ 56 * b7.val + 2 ^ 64 * b8.val +
      2 ^ 72 * b9.val + 2 ^ 80 * b10.val + 2 ^ 88 * b11.val + 2 ^ 96 * b12.val +
      2 ^ 104 * b13.val + 2 ^ 112 * b14.val + 2 ^ 120 * b15.val + 2 ^ 128 * b16.val +
      2 ^ 136 * b17.val + 2 ^ 144 * b18.val + 2 ^ 152 * b19.val + 2 ^ 160 * b20.val +
      2 ^ 168 * b21.val + 2 ^ 176 * b22.val + 2 ^ 184 * b23.val + 2 ^ 192 * b24.val +
      2 ^ 200 * b25.val + 2 ^ 208 * b26.val + 2 ^ 216 * b27.val + 2 ^ 224 * b28.val +
      2 ^ 232 * b29.val + 2 ^ 240 * b30.val + 2 ^ 248 * b31.val := by
  unfold U8x32_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq, hr]
  simp only [List.getElem!_cons_zero, List.getElem!_cons_succ]
  ring_nf

/-- The byte straddling two 52-bit limbs: the top 4 bits of `x` and the low 4 bits of `y`. -/
theorem to_bytes_straddle (x y : ℕ) (hx : x < 2 ^ 52) :
    (x >>> 48 ||| y <<< 4 % U64.size) % 2 ^ 8 = x / 2 ^ 48 + 2 ^ 4 * (y % 2 ^ 4) := by
  have hlo : x / 2 ^ 48 < 2 ^ 4 := by omega
  have hshl : y <<< 4 % U64.size = 2 ^ 4 * (y % 2 ^ 60) := by
    rw [Nat.shiftLeft_eq, show U64.size = 2 ^ 4 * 2 ^ 60 by simp [U64.size_def, U64.numBits], Nat.mul_comm y,
      Nat.mul_mod_mul_left]
  rw [Nat.shiftRight_eq_div_pow, hshl, Nat.or_comm, ← Nat.two_pow_add_eq_or_of_lt hlo]
  omega

/-- Expansion of `Scalar52_as_Nat` into its five limbs. -/
theorem to_bytes_Scalar52_as_Nat_expand (s : Scalar52) :
    Scalar52_as_Nat s = (s.val[0]!).val + 2 ^ 52 * (s.val[1]!).val +
      2 ^ 104 * (s.val[2]!).val + 2 ^ 156 * (s.val[3]!).val + 2 ^ 208 * (s.val[4]!).val := by
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq]
  ring_nf

/-- Arithmetic core of `to_bytes`: the 32 extracted bytes recombine to the limb value
modulo `2^256`. -/
theorem to_bytes_arith (a0 a1 a2 a3 a4 : ℕ) (h0 : a0 < 2 ^ 52) (h1 : a1 < 2 ^ 52)
    (h2 : a2 < 2 ^ 52) (h3 : a3 < 2 ^ 52) (_h4 : a4 < 2 ^ 52) :
    a0 >>> 0 % 2 ^ 8 + 2 ^ 8 * (a0 >>> 8 % 2 ^ 8) + 2 ^ 16 * (a0 >>> 16 % 2 ^ 8) +
      2 ^ 24 * (a0 >>> 24 % 2 ^ 8) + 2 ^ 32 * (a0 >>> 32 % 2 ^ 8) +
      2 ^ 40 * (a0 >>> 40 % 2 ^ 8) + 2 ^ 48 * ((a0 >>> 48 ||| a1 <<< 4 % U64.size) % 2 ^ 8) +
      2 ^ 56 * (a1 >>> 4 % 2 ^ 8) + 2 ^ 64 * (a1 >>> 12 % 2 ^ 8) +
      2 ^ 72 * (a1 >>> 20 % 2 ^ 8) + 2 ^ 80 * (a1 >>> 28 % 2 ^ 8) +
      2 ^ 88 * (a1 >>> 36 % 2 ^ 8) + 2 ^ 96 * (a1 >>> 44 % 2 ^ 8) +
      2 ^ 104 * (a2 >>> 0 % 2 ^ 8) + 2 ^ 112 * (a2 >>> 8 % 2 ^ 8) +
      2 ^ 120 * (a2 >>> 16 % 2 ^ 8) + 2 ^ 128 * (a2 >>> 24 % 2 ^ 8) +
      2 ^ 136 * (a2 >>> 32 % 2 ^ 8) + 2 ^ 144 * (a2 >>> 40 % 2 ^ 8) +
      2 ^ 152 * ((a2 >>> 48 ||| a3 <<< 4 % U64.size) % 2 ^ 8) +
      2 ^ 160 * (a3 >>> 4 % 2 ^ 8) + 2 ^ 168 * (a3 >>> 12 % 2 ^ 8) +
      2 ^ 176 * (a3 >>> 20 % 2 ^ 8) + 2 ^ 184 * (a3 >>> 28 % 2 ^ 8) +
      2 ^ 192 * (a3 >>> 36 % 2 ^ 8) + 2 ^ 200 * (a3 >>> 44 % 2 ^ 8) +
      2 ^ 208 * (a4 >>> 0 % 2 ^ 8) + 2 ^ 216 * (a4 >>> 8 % 2 ^ 8) +
      2 ^ 224 * (a4 >>> 16 % 2 ^ 8) + 2 ^ 232 * (a4 >>> 24 % 2 ^ 8) +
      2 ^ 240 * (a4 >>> 32 % 2 ^ 8) + 2 ^ 248 * (a4 >>> 40 % 2 ^ 8) =
    (a0 + 2 ^ 52 * a1 + 2 ^ 104 * a2 + 2 ^ 156 * a3 + 2 ^ 208 * a4) % 2 ^ 256 := by
  rw [to_bytes_straddle _ _ h0, to_bytes_straddle _ _ h2]
  simp only [Nat.shiftRight_eq_div_pow]
  have e0 : a0 / 2 ^ 0 % 2 ^ 8 + 2 ^ 8 * (a0 / 2 ^ 8 % 2 ^ 8) + 2 ^ 16 * (a0 / 2 ^ 16 % 2 ^ 8) +
      2 ^ 24 * (a0 / 2 ^ 24 % 2 ^ 8) + 2 ^ 32 * (a0 / 2 ^ 32 % 2 ^ 8) +
      2 ^ 40 * (a0 / 2 ^ 40 % 2 ^ 8) = a0 % 2 ^ 48 := by omega
  have e1 : a1 / 2 ^ 4 % 2 ^ 8 + 2 ^ 8 * (a1 / 2 ^ 12 % 2 ^ 8) + 2 ^ 16 * (a1 / 2 ^ 20 % 2 ^ 8) +
      2 ^ 24 * (a1 / 2 ^ 28 % 2 ^ 8) + 2 ^ 32 * (a1 / 2 ^ 36 % 2 ^ 8) +
      2 ^ 40 * (a1 / 2 ^ 44 % 2 ^ 8) = a1 / 2 ^ 4 := by omega
  have e2 : a2 / 2 ^ 0 % 2 ^ 8 + 2 ^ 8 * (a2 / 2 ^ 8 % 2 ^ 8) + 2 ^ 16 * (a2 / 2 ^ 16 % 2 ^ 8) +
      2 ^ 24 * (a2 / 2 ^ 24 % 2 ^ 8) + 2 ^ 32 * (a2 / 2 ^ 32 % 2 ^ 8) +
      2 ^ 40 * (a2 / 2 ^ 40 % 2 ^ 8) = a2 % 2 ^ 48 := by omega
  have e3 : a3 / 2 ^ 4 % 2 ^ 8 + 2 ^ 8 * (a3 / 2 ^ 12 % 2 ^ 8) + 2 ^ 16 * (a3 / 2 ^ 20 % 2 ^ 8) +
      2 ^ 24 * (a3 / 2 ^ 28 % 2 ^ 8) + 2 ^ 32 * (a3 / 2 ^ 36 % 2 ^ 8) +
      2 ^ 40 * (a3 / 2 ^ 44 % 2 ^ 8) = a3 / 2 ^ 4 := by omega
  have e4 : a4 / 2 ^ 0 % 2 ^ 8 + 2 ^ 8 * (a4 / 2 ^ 8 % 2 ^ 8) + 2 ^ 16 * (a4 / 2 ^ 16 % 2 ^ 8) +
      2 ^ 24 * (a4 / 2 ^ 24 % 2 ^ 8) + 2 ^ 32 * (a4 / 2 ^ 32 % 2 ^ 8) +
      2 ^ 40 * (a4 / 2 ^ 40 % 2 ^ 8) = a4 % 2 ^ 48 := by omega
  have e : (a0 + 2 ^ 52 * a1 + 2 ^ 104 * a2 + 2 ^ 156 * a3 + 2 ^ 208 * a4) % 2 ^ 256 =
      a0 % 2 ^ 48 + 2 ^ 48 * (a0 / 2 ^ 48 + 2 ^ 4 * (a1 % 2 ^ 4)) + 2 ^ 56 * (a1 / 2 ^ 4) +
      2 ^ 104 * (a2 % 2 ^ 48) + 2 ^ 152 * (a2 / 2 ^ 48 + 2 ^ 4 * (a3 % 2 ^ 4)) +
      2 ^ 160 * (a3 / 2 ^ 4) + 2 ^ 208 * (a4 % 2 ^ 48) := by omega
  rw [e]
  linarith

/-- `to_bytes` serialises five 52-bit limbs into 32 little-endian bytes. The top 4 bits of the
last limb are dropped, so the byte value is the limb value modulo `2^256`. -/
@[progress]
theorem to_bytes_spec (self : Scalar52) (h : ∀ i < 5, self[i]!.val < 2 ^ 52) :
    to_bytes self ⦃ r => U8x32_as_Nat r = Scalar52_as_Nat self % 2 ^ 256 ⦄ := by
  have h0 := h 0 (by simp); have h1 := h 1 (by simp); have h2 := h 2 (by simp)
  have h3 := h 3 (by simp); have h4 := h 4 (by simp)
  simp only [Array.getElem!_Nat_eq] at h0 h1 h2 h3 h4
  unfold to_bytes
  progress*
  subst_vars
  rw [U8x32_as_Nat_of_val _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
    (to_bytes_set32_val _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _),
    to_bytes_Scalar52_as_Nat_expand]
  simp only [UScalar.cast_val_eq, UScalarTy.numBits, UScalar.val_or, *]
  exact to_bytes_arith _ _ _ _ _ h0 h1 h2 h3 h4

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
