/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Hoang Le Truong
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Scalar.Scalar.FromU128


/-! # Spec Theorem for `Scalar::from` (From<u16>)

Specification and proof for the `From<u16>` trait implementation for Scalar.

This function constructs a `Scalar` from a `u16` value by writing its 2
little-endian bytes into the first 2 bytes of a 32-byte zero array.
Because every `u16` value is less than 2¹⁶, and 2¹⁶ < L (the group order,
≈ 2²⁵²), the resulting `Scalar` is automatically in canonical form.

**Source**: curve25519-dalek/src/scalar.rs (lines 499:4-504:5)
-/
open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU16

/-
natural language description:

• Takes a u16 value `x`
• Creates a 32-byte array initialized to zero
• Converts `x` to its 2-byte little-endian representation `x_bytes`
• Copies `x_bytes` into the first 2 bytes of the 32-byte array
• Returns a Scalar wrapping the resulting 32-byte array

natural language specs:

• The function always succeeds (no panic) for any u16 input
• The resulting Scalar's byte representation, interpreted as a little-endian
  natural number via U8x32_as_Nat, equals x.val (the natural number value of x)
• Since x.val < 2^16 < L, the resulting Scalar is automatically canonical
-/


private lemma hdigits (x : Std.U16) :
      Nat.ofDigits (2^8) (x.bv.toLEBytes.map (fun b => b.toNat))
        = (BitVec.fromLEBytes x.bv.toLEBytes).toNat := by
    rw[hdigits_aux]

private lemma U16_ofDigits_toLEBytes (x : Std.U16) :
    Nat.ofDigits (2^8)
      ((x.bv.toLEBytes.map (@UScalar.mk UScalarTy.U8)).map (·.val)) = x.val := by
  have hmap :
      ((x.bv.toLEBytes.map (@UScalar.mk UScalarTy.U8)).map (·.val))
        = x.bv.toLEBytes.map (fun b => b.toNat) := by
    simp only [UScalarTy.U8_numBits_eq, List.map_map, List.map_inj_left, Function.comp_apply]
    intro a ha
    rfl
  simp only [Nat.reducePow, UScalarTy.U8_numBits_eq, hmap]
  have hdigits :
      Nat.ofDigits (2^8) (x.bv.toLEBytes.map (fun b => b.toNat))
        = (BitVec.fromLEBytes x.bv.toLEBytes).toNat := by
    rw[hdigits]
  simp only [Nat.reducePow, Nat.reduceMod, BitVec.fromLEBytes_toLEBytes, BitVec.toNat_cast,
    UScalar.bv_toNat] at hdigits
  rw [hdigits]

private lemma U8x32_as_Nat_setSlice_zeroI (bs : List Std.U8) (h_len : bs.length = 2) :
    U8x32_as_Nat ⟨(List.replicate 32 (0#u8)).setSlice! 0 bs, by simp⟩ =
    Nat.ofDigits (2^8) (List.ofFn (fun i : Fin 2 => (bs[i]!).val)) := by
    unfold U8x32_as_Nat List.setSlice!
    simp [Finset.sum_range_succ, h_len, Nat.ofDigits]

private lemma hmap (bs : List Std.U8) (h_len : bs.length = 2) :
    bs.map (·.val) = List.ofFn (fun i : Fin 2 => (bs[i]!).val) := by
  apply List.ext_getElem
  · simp [h_len]
  · intro i hi _
    simp only [List.getElem_map, List.getElem_ofFn]
    congr 1
    grind

private lemma U8x32_as_Nat_setSlice_zero (bs : List Std.U8) (h_len : bs.length = 2) :
    U8x32_as_Nat ⟨(List.replicate 32 (0#u8)).setSlice! 0 bs, by simp⟩ =
    Nat.ofDigits (2^8) (bs.map (·.val)) := by
    rw[U8x32_as_Nat_setSlice_zeroI _ h_len, hmap]
    exact h_len

/-- **Spec and proof concerning `scalar.Scalar.Insts.CoreConvertFromU16.from`**:
• The function always succeeds (no panic)
• The resulting Scalar's byte representation equals x.val
  (i.e., U8x32_as_Nat result.bytes = x.val)
• The result is automatically canonical (less than L) since x.val < 2^16 < L
-/
@[progress]
theorem from_spec (x : Std.U16) :
    «from» x ⦃ result =>
    U8x32_as_Nat result.bytes = x.val ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU16
