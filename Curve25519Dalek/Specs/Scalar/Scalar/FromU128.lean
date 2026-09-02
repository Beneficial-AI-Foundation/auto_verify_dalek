




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux












open Aeneas Aeneas.Std Result Aeneas.Std.WP










private lemma fromLEBytes_toNat_lt_two_pow (tail : List (BitVec 8)) :
    (BitVec.fromLEBytes tail).toNat < 2 ^ (8 * tail.length) := by
  induction tail with
  | nil =>
    simp [BitVec.fromLEBytes]
  | cons h t ih =>
    simp only [List.length_cons, BitVec.fromLEBytes, BitVec.toNat_or, BitVec.toNat_setWidth, BitVec.toNat_shiftLeft,
      Nat.ofNat_pos, mul_lt_mul_iff_right₀, lt_add_iff_pos_right, zero_lt_one, BitVec.toNat_mod_cancel_of_lt]
    have hshift : (BitVec.fromLEBytes t).toNat <<< 8 = (BitVec.fromLEBytes t).toNat * 2^8 := by
      simp[Nat.shiftLeft_eq]
    rw [hshift]
    have hh : h.toNat < 2^8 := by scalar_tac
    have htbound : (BitVec.fromLEBytes t).toNat * 2^8 < 2^(8 * t.length) * 2^8 := by
      ring_nf
      grind
    apply Nat.or_lt_two_pow <;> exact Nat.mod_lt _ (by positivity)

private lemma hdigits_bv_step (head : BitVec 8) (tail : List (BitVec 8)) :
  BitVec.toNat head + 256 * (BitVec.fromLEBytes tail).toNat
    = (BitVec.toNat head % 2 ^ (8 * (tail.length + 1))) +
      ((BitVec.fromLEBytes tail).toNat <<< 8 % 2 ^ (8 * (tail.length + 1))) := by
  have hshift : (BitVec.fromLEBytes tail).toNat <<< 8 = 256 * (BitVec.fromLEBytes tail).toNat := by
    simp[Nat.shiftLeft_eq]
    ring_nf
  rw [hshift]
  have hbound : BitVec.toNat head + 256 * (BitVec.fromLEBytes tail).toNat < 2 ^ (8 * (tail.length + 1)) := by
    have hh : BitVec.toNat head < 2 ^ 8 := by scalar_tac
    have ht : (BitVec.fromLEBytes tail).toNat < 2 ^ (8 * tail.length) := by
      simp[fromLEBytes_toNat_lt_two_pow]
    grind
  have hbound : 256 * (BitVec.fromLEBytes tail).toNat < 2 ^ (8 * (tail.length + 1)) := by  grind
  have hbound1 : BitVec.toNat head  < 2 ^ (8 * (tail.length + 1)) := by  grind
  have :=Nat.mod_eq_of_lt hbound
  rw[this]
  have :=Nat.mod_eq_of_lt hbound1
  rw[this]

private lemma hdigits_aux_ha (head : BitVec 8) (tail : List (BitVec 8)) :
    BitVec.toNat head % 2 ^ (8 * (tail.length + 1)) < 2 ^ 8 :=
  Nat.lt_of_le_of_lt (Nat.mod_le _ _) (by scalar_tac)


private lemma hdigits_aux_hb_dvd (tail : List (BitVec 8)) :
    2 ^ 8 ∣ (BitVec.fromLEBytes tail).toNat <<< 8 % 2 ^ (8 * (tail.length + 1)) := by
  rw [Nat.shiftLeft_eq, Nat.mul_comm,
      show 8 * (tail.length + 1) = 8 + 8 * tail.length from by ring,
      pow_add, Nat.mul_mod_mul_left]
  grind

lemma hdigits_aux (l : List Byte) :
    Nat.ofDigits (2^8) (l.map (fun b => b.toNat))
      = (BitVec.fromLEBytes l).toNat := by
  sorry
lemma hdigits (x : Std.U128) :
      Nat.ofDigits (2^8) (x.bv.toLEBytes.map (fun b => b.toNat))
        = (BitVec.fromLEBytes x.bv.toLEBytes).toNat := by
  sorry
namespace curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU128



















private lemma U128_ofDigits_toLEBytes (x : Std.U128) :
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

private lemma U8x32_as_Nat_setSlice_zeroI (bs : List Std.U8) (h_len : bs.length = 16) :
    U8x32_as_Nat ⟨(List.replicate 32 (0#u8)).setSlice! 0 bs, by simp⟩ =
    Nat.ofDigits (2^8) (List.ofFn (fun i : Fin 16 => (bs[i]!).val)) := by
    unfold U8x32_as_Nat List.setSlice!
    simp [Finset.sum_range_succ, h_len, Nat.ofDigits]
    ring_nf

private lemma hmap (bs : List Std.U8) (h_len : bs.length = 16) :
    bs.map (·.val) = List.ofFn (fun i : Fin 16 => (bs[i]!).val) := by
  apply List.ext_getElem
  · simp [h_len]
  · intro i hi _
    simp only [List.getElem_map, List.getElem_ofFn]
    congr 1
    grind

private lemma U8x32_as_Nat_setSlice_zero (bs : List Std.U8) (h_len : bs.length = 16) :
    U8x32_as_Nat ⟨(List.replicate 32 (0#u8)).setSlice! 0 bs, by simp⟩ =
    Nat.ofDigits (2^8) (bs.map (·.val)) := by
    rw[U8x32_as_Nat_setSlice_zeroI _ h_len, hmap]
    exact h_len







@[progress]
theorem from_spec (x : Std.U128) :
    «from» x ⦃ result =>
    U8x32_as_Nat result.bytes = x.val ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU128
