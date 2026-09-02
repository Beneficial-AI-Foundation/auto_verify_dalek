




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Scalar.Scalar.FromU128













open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64

















private lemma hdigits (x : Std.U64) :
      Nat.ofDigits (2^8) (x.bv.toLEBytes.map (fun b => b.toNat))
        = (BitVec.fromLEBytes x.bv.toLEBytes).toNat := by
    rw[hdigits_aux]

private lemma U64_ofDigits_toLEBytes (x : Std.U64) :
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

private lemma U8x32_as_Nat_setSlice_zeroI (bs : List Std.U8) (h_len : bs.length = 8) :
    U8x32_as_Nat ⟨(List.replicate 32 (0#u8)).setSlice! 0 bs, by simp⟩ =
    Nat.ofDigits (2^8) (List.ofFn (fun i : Fin 8 => (bs[i]!).val)) := by
    unfold U8x32_as_Nat List.setSlice!
    simp [Finset.sum_range_succ, h_len, Nat.ofDigits]
    ring_nf

private lemma hmap (bs : List Std.U8) (h_len : bs.length = 8) :
    bs.map (·.val) = List.ofFn (fun i : Fin 8 => (bs[i]!).val) := by
  apply List.ext_getElem
  · simp [h_len]
  · intro i hi _
    simp only [List.getElem_map, List.getElem_ofFn]
    congr 1
    grind

private lemma U8x32_as_Nat_setSlice_zero (bs : List Std.U8) (h_len : bs.length = 8) :
    U8x32_as_Nat ⟨(List.replicate 32 (0#u8)).setSlice! 0 bs, by simp⟩ =
    Nat.ofDigits (2^8) (bs.map (·.val)) := by
    rw[U8x32_as_Nat_setSlice_zeroI _ h_len, hmap]
    exact h_len







@[progress]
theorem from_spec (x : Std.U64) :
    «from» x ⦃ result =>
    U8x32_as_Nat result.bytes = x.val ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64

