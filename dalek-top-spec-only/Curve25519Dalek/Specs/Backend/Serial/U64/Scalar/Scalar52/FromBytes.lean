import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.IndexMut
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ZERO
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytesLoop

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Equational form of `index_mut_spec`. Rewriting with it (instead of using `progress` on
`index_mut`) avoids an expensive kernel check in `from_bytes_spec`. -/
theorem from_bytes_index_mut_eq (z : Scalar52) (i : Usize) (h : i.val < 5) :
    Insts.CoreOpsIndexIndexMutUsizeU64.index_mut z i =
      ok (z.val[i.val]!, Aeneas.Std.Array.set z i) := by
  obtain ⟨⟨x, back⟩, heq, hx, hback, _⟩ :=
    spec_imp_exists (Insts.CoreOpsIndexIndexMutUsizeU64.index_mut_spec z i h)
  rw [heq, hx, hback]

/-- Writing all five limbs of a `Scalar52` in order yields exactly those limbs. -/
theorem from_bytes_set5_val (z : Scalar52) (l0 l1 l2 l3 l4 : U64) :
    (Aeneas.Std.Array.set (Aeneas.Std.Array.set (Aeneas.Std.Array.set (Aeneas.Std.Array.set
      (Aeneas.Std.Array.set z 0#usize l0) 1#usize l1) 2#usize l2) 3#usize l3) 4#usize l4).val =
      [l0, l1, l2, l3, l4] := by
  obtain ⟨l, hl⟩ := z
  match l, hl with
  | [a, b, c, d, e], _ => simp [Aeneas.Std.Array.set_val_eq]

/-- Value and bounds of five limbs `l0..l4` (radix `2^52`). -/
theorem from_bytes_limbs_post (s : Scalar52) (l0 l1 l2 l3 l4 : U64)
    (hs : s.val = [l0, l1, l2, l3, l4]) :
    Scalar52_as_Nat s = l0.val + 2 ^ 52 * l1.val + 2 ^ 104 * l2.val + 2 ^ 156 * l3.val +
      2 ^ 208 * l4.val ∧
    (∀ i < 5, s[i]!.val = [l0, l1, l2, l3, l4][i]!.val) := by
  refine ⟨?_, fun i _ => by rw [Array.getElem!_Nat_eq, hs]⟩
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq, hs]
  simp

/-- Arithmetic core of `from_bytes`: repacking four 64-bit words into 52-bit limbs
preserves the value. -/
theorem from_bytes_repack_sum (a0 a1 a2 a3 : ℕ) (h0 : a0 < 2 ^ 64) (h1 : a1 < 2 ^ 64)
    (h2 : a2 < 2 ^ 64) (h3 : a3 < 2 ^ 64) :
    a0 % 2 ^ 52 + 2 ^ 52 * (a0 / 2 ^ 52 + 2 ^ 12 * (a1 % 2 ^ 40)) +
      2 ^ 104 * (a1 / 2 ^ 40 + 2 ^ 24 * (a2 % 2 ^ 28)) +
      2 ^ 156 * (a2 / 2 ^ 28 + 2 ^ 36 * (a3 % 2 ^ 16)) + 2 ^ 208 * (a3 / 2 ^ 16 % 2 ^ 48) =
    a0 + 2 ^ 64 * a1 + 2 ^ 128 * a2 + 2 ^ 192 * a3 := by
  norm_num at *
  omega

/-- `from_bytes` unpacks 32 little-endian bytes into five 52-bit limbs representing the
same natural number (no reduction modulo `L` is performed). -/
@[progress]
theorem from_bytes_spec (bytes : Array U8 32#usize) :
    from_bytes bytes ⦃ s =>
      Scalar52_as_Nat s = U8x32_as_Nat bytes ∧ (∀ i < 5, s[i]!.val < 2 ^ 52) ⦄ := by
  unfold from_bytes
  simp only [from_bytes_index_mut_eq _ 0#usize (by simp),
    from_bytes_index_mut_eq _ 1#usize (by simp), from_bytes_index_mut_eq _ 2#usize (by simp),
    from_bytes_index_mut_eq _ 3#usize (by simp), from_bytes_index_mut_eq _ 4#usize (by simp),
    bind_tc_ok]
  progress as ⟨w, _, _, hw⟩
  progress as ⟨i, hi⟩
  progress as ⟨mask, hmask⟩
  progress as ⟨i1, hi1⟩
  progress as ⟨top_mask, htop⟩
  progress as ⟨a0, ha0⟩
  progress as ⟨l0, hl0⟩
  progress as ⟨i4, hi4⟩
  progress as ⟨a1, ha1⟩
  progress as ⟨i6, hi6⟩
  progress as ⟨i7, hi7⟩
  progress as ⟨l1, hl1⟩
  progress as ⟨i9, hi9⟩
  progress as ⟨a2, ha2⟩
  progress as ⟨i11, hi11⟩
  progress as ⟨i12, hi12⟩
  progress as ⟨l2, hl2⟩
  progress as ⟨i14, hi14⟩
  progress as ⟨a3, ha3⟩
  progress as ⟨i16, hi16⟩
  progress as ⟨i17, hi17⟩
  progress as ⟨l3, hl3⟩
  progress as ⟨i19, hi19⟩
  progress as ⟨l4, hl4⟩
  have hsz : U64.size = 2 ^ 64 := by simp [U64.size, U64.numBits]
  have hm : mask.val = 2 ^ 52 - 1 := by
    rw [hmask, hi, hsz, Nat.one_shiftLeft]; norm_num
  have htm : top_mask.val = 2 ^ 48 - 1 := by
    rw [htop, hi1, hsz, Nat.one_shiftLeft]; norm_num
  have b0 : a0.val < 2 ^ 64 := by scalar_tac
  have b1 : a1.val < 2 ^ 64 := by scalar_tac
  have b2 : a2.val < 2 ^ 64 := by scalar_tac
  have b3 : a3.val < 2 ^ 64 := by scalar_tac
  have e0 : l0.val = a0.val % 2 ^ 52 := by
    rw [hl0, UScalar.val_and, hm, Nat.and_two_pow_sub_one_eq_mod]
  have e1 : l1.val = a0.val / 2 ^ 52 + 2 ^ 12 * (a1.val % 2 ^ 40) := by
    rw [hl1, UScalar.val_and, hm, hi7, UScalar.val_or, hi4, hi6, hsz]
    exact Nat.shr_or_shl_mask52 b0 (by norm_num) (by norm_num)
  have e2 : l2.val = a1.val / 2 ^ 40 + 2 ^ 24 * (a2.val % 2 ^ 28) := by
    rw [hl2, UScalar.val_and, hm, hi12, UScalar.val_or, hi9, hi11, hsz]
    exact Nat.shr_or_shl_mask52 b1 (by norm_num) (by norm_num)
  have e3 : l3.val = a2.val / 2 ^ 28 + 2 ^ 36 * (a3.val % 2 ^ 16) := by
    rw [hl3, UScalar.val_and, hm, hi17, UScalar.val_or, hi14, hi16, hsz]
    exact Nat.shr_or_shl_mask52 b2 (by norm_num) (by norm_num)
  have e4 : l4.val = a3.val / 2 ^ 16 % 2 ^ 48 := by
    rw [hl4, UScalar.val_and, htm, hi19, Nat.shiftRight_eq_div_pow,
      Nat.and_two_pow_sub_one_eq_mod]
  have lt0 : l0.val < 2 ^ 52 := by rw [hl0, UScalar.val_and, hm, Nat.and_two_pow_sub_one_eq_mod]; exact Nat.mod_lt _ (by norm_num)
  have lt1 : l1.val < 2 ^ 52 := by rw [hl1, UScalar.val_and, hm, Nat.and_two_pow_sub_one_eq_mod]; exact Nat.mod_lt _ (by norm_num)
  have lt2 : l2.val < 2 ^ 52 := by rw [hl2, UScalar.val_and, hm, Nat.and_two_pow_sub_one_eq_mod]; exact Nat.mod_lt _ (by norm_num)
  have lt3 : l3.val < 2 ^ 52 := by rw [hl3, UScalar.val_and, hm, Nat.and_two_pow_sub_one_eq_mod]; exact Nat.mod_lt _ (by norm_num)
  have lt4 : l4.val < 2 ^ 52 := by
    rw [e4]; exact lt_of_lt_of_le (Nat.mod_lt _ (by norm_num)) (by norm_num)
  obtain ⟨hv, hidx⟩ := from_bytes_limbs_post _ l0 l1 l2 l3 l4 (from_bytes_set5_val _ _ _ _ _ _)
  refine ⟨?_, fun j hj => ?_⟩
  · rw [hv, e0, e1, e2, e3, e4, from_bytes_repack_sum _ _ _ _ b0 b1 b2 b3, ← hw trivial]
    simp only [Finset.sum_range_succ, Finset.sum_range_zero, ha0, ha1, ha2, ha3]
    ring
  · rw [hidx j hj]
    interval_cases j <;> simpa
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
