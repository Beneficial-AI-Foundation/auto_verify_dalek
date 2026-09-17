




import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Funs
import Mathlib.Tactic.IntervalCases
import Mathlib.Tactic.GCongr
import Mathlib.Algebra.BigOperators.Ring.Finset

set_option linter.style.setOption false
set_option grind.warning false



open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek
open scalar

attribute [-simp] Int.reducePow Nat.reducePow





attribute [bvify_simps] Nat.dvd_iff_mod_eq_zero



namespace curve25519_dalek.scalar







@[progress]
theorem clamp_integer_spec (bytes : Array U8 32#usize) :
    clamp_integer bytes ⦃ result =>
    h ∣ U8x32_as_Nat result ∧
    U8x32_as_Nat result < 2^255 ∧
    2^254 ≤ U8x32_as_Nat result ⦄ := by
  unfold clamp_integer
  progress as ⟨i, hi⟩
  progress as ⟨i1, hi1, hi1_bv⟩
  progress as ⟨bytes1, hbytes1⟩
  progress as ⟨i2, hi2⟩
  progress as ⟨i3, hi3, hi3_bv⟩
  progress as ⟨bytes2, hbytes2⟩
  progress as ⟨i4, hi4⟩
  progress as ⟨i5, hi5, hi5_bv⟩
  progress as ⟨result, hresult⟩
  have h0 : result[0]! = i1 := by
    simp [hresult, hbytes2, hbytes1]
  have h31 : result[31]! = i5 := by
    simp [hresult]
  have hi4_eq : i4 = i3 := by simp [hi4, hbytes2]
  have hmod8 : i1.val % 8 = 0 := by rw [hi1]; exact u8_and_248_mod8 i
  have hi3_lt : i3.val < 128 := by rw [hi3]; exact u8_and_127_lt_128 i2
  have hi5_lt : i5.val < 128 := by rw [hi5, hi4_eq]; exact u8_or_64_lt_128 i3 hi3_lt
  have hi5_ge : 64 ≤ i5.val := by rw [hi5]; exact u8_or_64_ge_64 i4
  have hb0 : i1.val < 2 ^ 8 := UScalar.hBounds _
  have hbound : ∀ (i : Nat), (result[i]! : U8).val < 2 ^ 8 := fun i => UScalar.hBounds _
  have hb1 := hbound 1; have hb2 := hbound 2
  have hb3 := hbound 3; have hb4 := hbound 4
  have hb5 := hbound 5; have hb6 := hbound 6
  have hb7 := hbound 7; have hb8 := hbound 8
  have hb9 := hbound 9; have hb10 := hbound 10
  have hb11 := hbound 11; have hb12 := hbound 12
  have hb13 := hbound 13; have hb14 := hbound 14
  have hb15 := hbound 15; have hb16 := hbound 16
  have hb17 := hbound 17; have hb18 := hbound 18
  have hb19 := hbound 19; have hb20 := hbound 20
  have hb21 := hbound 21; have hb22 := hbound 22
  have hb23 := hbound 23; have hb24 := hbound 24
  have hb25 := hbound 25; have hb26 := hbound 26
  have hb27 := hbound 27; have hb28 := hbound 28
  have hb29 := hbound 29; have hb30 := hbound 30
  unfold U8x32_as_Nat h
  simp only [Finset.sum_range_succ, Finset.range_zero, Finset.sum_empty, zero_add]
  rw [h0, h31]
  refine ⟨?_, ?_, ?_⟩
  · rw [Nat.dvd_iff_mod_eq_zero]; omega
  · omega
  · omega
end curve25519_dalek.scalar
