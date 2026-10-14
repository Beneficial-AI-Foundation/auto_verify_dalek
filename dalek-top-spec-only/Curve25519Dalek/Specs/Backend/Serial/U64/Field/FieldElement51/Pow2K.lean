import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.pow2k

/-- `LOW_51_BIT_MASK` evaluates to `2 ^ 51 - 1`. -/
@[progress]
theorem LOW_51_BIT_MASK_spec :
    LOW_51_BIT_MASK ⦃ r => r.val = 2 ^ 51 - 1 ⦄ := by
  unfold LOW_51_BIT_MASK
  progress as ⟨i, hi⟩
  progress as ⟨r, hr⟩
  scalar_tac

/-- `m x y` computes the full 128-bit product of two `u64` values; it never overflows. -/
@[progress]
theorem m_spec (x y : U64) :
    m x y ⦃ r => r.val = x.val * y.val ⦄ := by
  unfold m
  progress as ⟨i, hi⟩
  progress as ⟨i1, hi1⟩
  have hx := x.hBounds
  have hy := y.hBounds
  have : x.val * y.val < 2 ^ 64 * 2 ^ 64 := Nat.mul_lt_mul'' hx hy
  progress as ⟨r, hr⟩
  simp_all

end curve25519_dalek.backend.serial.u64.field.FieldElement51.pow2k

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

open pow2k

attribute [-simp] Int.reducePow Nat.reducePow

theorem pow2k_prod_le {x y : U64} {r : U128} {X Y : Nat} (h : r.val = x.val * y.val)
    (hx : x.val < X) (hy : y.val < Y) : r.val ≤ X * Y := by
  rw [h]; exact Nat.mul_le_mul hx.le hy.le

theorem pow2k_cast_U64_val (x : U128) : (UScalar.cast .U64 x).val = x.val % 2 ^ 64 := by
  rw [UScalar.cast_val_eq]; rfl

theorem pow2k_cast_U128_val (x : U64) : (UScalar.cast .U128 x).val = x.val :=
  U64.cast_U128_val_eq x

/-- Masking a `U64` with the low-51-bit mask reduces it modulo `2 ^ 51`. -/
theorem pow2k_mask51_spec (x mask : Std.U64) (hmask : mask.val = 2 ^ 51 - 1) :
    (lift (x &&& mask) : Result Std.U64) ⦃ z => z.val = x.val % 2 ^ 51 ∧ z.val < 2 ^ 51 ⦄ := by
  progress as ⟨z, hz, _⟩
  simp only [Aeneas.Std.UScalar.val_and, hmask] at hz
  rw [Nat.and_two_pow_sub_one_eq_mod] at hz
  exact ⟨hz, hz ▸ Nat.mod_lt _ (by norm_num)⟩

/-- Unrolls `Field51_as_Nat` into its five limb terms (list-level indexing). -/
theorem pow2k_Field51_as_Nat_eq (X : Array Std.U64 5#usize) :
    Field51_as_Nat X =
      X.val[0]!.val + 2 ^ 51 * X.val[1]!.val + 2 ^ 102 * X.val[2]!.val +
        2 ^ 153 * X.val[3]!.val + 2 ^ 204 * X.val[4]!.val := by
  unfold Field51_as_Nat
  simp only [Array.getElem!_Nat_eq, Finset.sum_range_succ, Finset.sum_range_zero]
  ring

/-- Squaring a radix-`2^51` number, with the high columns folded back using `2^255 = p + 19`. -/
theorem pow2k_square_identity (a0 a1 a2 a3 a4 : Nat) :
    (a0 + 2 ^ 51 * a1 + 2 ^ 102 * a2 + 2 ^ 153 * a3 + 2 ^ 204 * a4) ^ 2 =
    (a0 * a0 + 2 * (a1 * (19 * a4) + a2 * (19 * a3))) +
      2 ^ 51 * (a3 * (19 * a3) + 2 * (a0 * a1 + a2 * (19 * a4))) +
      2 ^ 102 * (a1 * a1 + 2 * (a0 * a2 + a4 * (19 * a3))) +
      2 ^ 153 * (a4 * (19 * a4) + 2 * (a0 * a3 + a1 * a2)) +
      2 ^ 204 * (a2 * a2 + 2 * (a0 * a4 + a1 * a3)) +
    p * (2 * (a1 * a4 + a2 * a3) + 2 ^ 51 * (a3 * a3 + 2 * (a2 * a4)) +
      2 ^ 102 * (2 * (a3 * a4)) + 2 ^ 153 * (a4 * a4)) := by
  have hp : ((p : Nat) : ℤ) = 2 ^ 255 - 19 := by unfold p; norm_num
  zify
  rw [hp]
  ring

/-- The carry-propagation tail of one `pow2k_loop` iteration (a verbatim copy of the extracted
code after the five 128-bit column sums), followed by an arbitrary continuation `f`. -/
theorem pow2k_tail_spec {α : Type} (a : Array U64 5#usize) (c0 c1 c2 c3 c4 : U128)
    (f : Array U64 5#usize → Result α) (Q : α → Prop)
    (h0 : c0.val ≤ 77 * 2 ^ 108) (h1 : c1.val ≤ 77 * 2 ^ 108) (h2 : c2.val ≤ 77 * 2 ^ 108)
    (h3 : c3.val ≤ 77 * 2 ^ 108) (h4 : c4.val ≤ 5 * 2 ^ 108)
    (hf : ∀ a8 : Array U64 5#usize, (∀ j < 5, a8[j]!.val < 2 ^ 52) →
      (∃ q, Field51_as_Nat a8 + q * p =
        c0.val + 2 ^ 51 * c1.val + 2 ^ 102 * c2.val + 2 ^ 153 * c3.val + 2 ^ 204 * c4.val) →
      f a8 ⦃ r => Q r ⦄) :
    (do
      let i30 ← c0 >>> 51#i32
      let i31 ← lift (UScalar.cast .U64 i30)
      let i32 ← lift (UScalar.cast .U128 i31)
      let c11 ← c1 + i32
      let i33 ← lift (UScalar.cast .U64 c0)
      let i34 ← backend.serial.u64.field.FieldElement51.pow2k.LOW_51_BIT_MASK
      let i35 ← lift (i33 &&& i34)
      let a1 ← Array.update a 0#usize i35
      let i36 ← c11 >>> 51#i32
      let i37 ← lift (UScalar.cast .U64 i36)
      let i38 ← lift (UScalar.cast .U128 i37)
      let c21 ← c2 + i38
      let i39 ← lift (UScalar.cast .U64 c11)
      let i40 ← lift (i39 &&& i34)
      let a2 ← Array.update a1 1#usize i40
      let i41 ← c21 >>> 51#i32
      let i42 ← lift (UScalar.cast .U64 i41)
      let i43 ← lift (UScalar.cast .U128 i42)
      let c31 ← c3 + i43
      let i44 ← lift (UScalar.cast .U64 c21)
      let i45 ← lift (i44 &&& i34)
      let a3 ← Array.update a2 2#usize i45
      let i46 ← c31 >>> 51#i32
      let i47 ← lift (UScalar.cast .U64 i46)
      let i48 ← lift (UScalar.cast .U128 i47)
      let c41 ← c4 + i48
      let i49 ← lift (UScalar.cast .U64 c31)
      let i50 ← lift (i49 &&& i34)
      let a4 ← Array.update a3 3#usize i50
      let i51 ← c41 >>> 51#i32
      let carry ← lift (UScalar.cast .U64 i51)
      let i52 ← lift (UScalar.cast .U64 c41)
      let i53 ← lift (i52 &&& i34)
      let a5 ← Array.update a4 4#usize i53
      let i54 ← carry * 19#u64
      let i55 ← Array.index_usize a5 0#usize
      let i56 ← i55 + i54
      let a6 ← Array.update a5 0#usize i56
      let i57 ← Array.index_usize a6 0#usize
      let i58 ← i57 >>> 51#i32
      let i59 ← Array.index_usize a6 1#usize
      let i60 ← i59 + i58
      let a7 ← Array.update a6 1#usize i60
      let i61 ← Array.index_usize a7 0#usize
      let i62 ← lift (i61 &&& i34)
      let a8 ← Array.update a7 0#usize i62
      f a8) ⦃ r => Q r ⦄ := by
  progress as ⟨i30, hi30⟩
  progress as ⟨i31, hi31⟩
  progress as ⟨i32, hi32⟩
  progress as ⟨c11, hc11⟩
  progress as ⟨i33, hi33⟩
  progress as ⟨i34, hi34⟩
  progress with pow2k_mask51_spec as ⟨i35, hi35, hi35b⟩
  progress as ⟨a1, ha1⟩
  progress as ⟨i36, hi36⟩
  progress as ⟨i37, hi37⟩
  progress as ⟨i38, hi38⟩
  progress as ⟨c21, hc21⟩
  progress as ⟨i39, hi39⟩
  progress with pow2k_mask51_spec as ⟨i40, hi40, hi40b⟩
  progress as ⟨a2, ha2⟩
  progress as ⟨i41, hi41⟩
  progress as ⟨i42, hi42⟩
  progress as ⟨i43, hi43⟩
  progress as ⟨c31, hc31⟩
  progress as ⟨i44, hi44⟩
  progress with pow2k_mask51_spec as ⟨i45, hi45, hi45b⟩
  progress as ⟨a3, ha3⟩
  progress as ⟨i46, hi46⟩
  progress as ⟨i47, hi47⟩
  progress as ⟨i48, hi48⟩
  progress as ⟨c41, hc41⟩
  progress as ⟨i49, hi49⟩
  progress with pow2k_mask51_spec as ⟨i50, hi50, hi50b⟩
  progress as ⟨a4, ha4⟩
  progress as ⟨i51, hi51⟩
  progress as ⟨carry, hcarry⟩
  progress as ⟨i52, hi52⟩
  progress with pow2k_mask51_spec as ⟨i53, hi53, hi53b⟩
  progress as ⟨a5, ha5⟩
  have e30 : i30.val = c0.val / 2 ^ 51 := by rw [hi30, Nat.shiftRight_eq_div_pow]
  have e31 : i31.val = i30.val % 2 ^ 64 := by rw [hi31, pow2k_cast_U64_val]
  have e32 : i32.val = i31.val := by rw [hi32, pow2k_cast_U128_val]
  have e33 : i33.val = c0.val % 2 ^ 64 := by rw [hi33, pow2k_cast_U64_val]
  have e36 : i36.val = c11.val / 2 ^ 51 := by rw [hi36, Nat.shiftRight_eq_div_pow]
  have e37 : i37.val = i36.val % 2 ^ 64 := by rw [hi37, pow2k_cast_U64_val]
  have e38 : i38.val = i37.val := by rw [hi38, pow2k_cast_U128_val]
  have e39 : i39.val = c11.val % 2 ^ 64 := by rw [hi39, pow2k_cast_U64_val]
  have e41 : i41.val = c21.val / 2 ^ 51 := by rw [hi41, Nat.shiftRight_eq_div_pow]
  have e42 : i42.val = i41.val % 2 ^ 64 := by rw [hi42, pow2k_cast_U64_val]
  have e43 : i43.val = i42.val := by rw [hi43, pow2k_cast_U128_val]
  have e44 : i44.val = c21.val % 2 ^ 64 := by rw [hi44, pow2k_cast_U64_val]
  have e46 : i46.val = c31.val / 2 ^ 51 := by rw [hi46, Nat.shiftRight_eq_div_pow]
  have e47 : i47.val = i46.val % 2 ^ 64 := by rw [hi47, pow2k_cast_U64_val]
  have e48 : i48.val = i47.val := by rw [hi48, pow2k_cast_U128_val]
  have e49 : i49.val = c31.val % 2 ^ 64 := by rw [hi49, pow2k_cast_U64_val]
  have e51 : i51.val = c41.val / 2 ^ 51 := by rw [hi51, Nat.shiftRight_eq_div_pow]
  have ecarry : carry.val = i51.val % 2 ^ 64 := by rw [hcarry, pow2k_cast_U64_val]
  have e52 : i52.val = c41.val % 2 ^ 64 := by rw [hi52, pow2k_cast_U64_val]
  clear hi30 hi31 hi32 hi33 hi36 hi37 hi38 hi39 hi41 hi42 hi43 hi44 hi46 hi47 hi48 hi49
    hi51 hcarry hi52
  have hcarry_b : carry.val ≤ 5 * 2 ^ 57 + 2 ^ 14 := by omega
  progress as ⟨i54, hi54⟩
  progress as ⟨i55, hi55⟩
  have g55 : i55 = i35 := by simp [hi55, ha5, ha4, ha3, ha2, ha1]
  progress as ⟨i56, hi56⟩
  progress as ⟨a6, ha6⟩
  progress as ⟨i57, hi57⟩
  have g57 : i57 = i56 := by simp [hi57, ha6]
  progress as ⟨i58, hi58⟩
  have e58 : i58.val = i57.val / 2 ^ 51 := by rw [hi58, Nat.shiftRight_eq_div_pow]
  progress as ⟨i59, hi59⟩
  have g59 : i59 = i40 := by simp [hi59, ha6, ha5, ha4, ha3, ha2]
  progress as ⟨i60, hi60⟩
  progress as ⟨a7, ha7⟩
  progress as ⟨i61, hi61⟩
  have g61 : i61 = i56 := by simp [hi61, ha7, ha6]
  progress with pow2k_mask51_spec as ⟨i62, hi62, hi62b⟩
  progress as ⟨a8, ha8⟩
  have r0 : a8.val[0]! = i62 := by simp [ha8]
  have r1 : a8.val[1]! = i60 := by simp [ha8, ha7]
  have r2 : a8.val[2]! = i45 := by simp [ha8, ha7, ha6, ha5, ha4, ha3]
  have r3 : a8.val[3]! = i50 := by simp [ha8, ha7, ha6, ha5, ha4]
  have r4 : a8.val[4]! = i53 := by simp [ha8, ha7, ha6, ha5]
  rw [g55] at hi56
  rw [g57] at e58
  rw [g59] at hi60
  rw [g61] at hi62
  apply hf
  · intro j hj
    rw [Array.getElem!_Nat_eq]
    interval_cases j
    · rw [r0]; omega
    · rw [r1]; omega
    · rw [r2]; omega
    · rw [r3]; omega
    · rw [r4]; omega
  · refine ⟨carry.val, ?_⟩
    rw [pow2k_Field51_as_Nat_eq, r0, r1, r2, r3, r4]
    have m64 : ∀ x : Nat, x % 2 ^ 64 % 2 ^ 51 = x % 2 ^ 51 := fun x =>
      Nat.mod_mod_of_dvd x (by norm_num)
    have f0 : i35.val = c0.val % 2 ^ 51 := by rw [hi35, e33, m64]
    have f1 : i40.val = c11.val % 2 ^ 51 := by rw [hi40, e39, m64]
    have f2 : i45.val = c21.val % 2 ^ 51 := by rw [hi45, e44, m64]
    have f3 : i50.val = c31.val % 2 ^ 51 := by rw [hi50, e49, m64]
    have f4 : i53.val = c41.val % 2 ^ 51 := by rw [hi53, e52, m64]
    have q0 : i32.val = c0.val / 2 ^ 51 := by omega
    have q1 : i38.val = c11.val / 2 ^ 51 := by omega
    have q2 : i43.val = c21.val / 2 ^ 51 := by omega
    have q3 : i48.val = c31.val / 2 ^ 51 := by omega
    have q4 : carry.val = c41.val / 2 ^ 51 := by omega
    have d0 := Nat.div_add_mod c0.val (2 ^ 51)
    have d1 := Nat.div_add_mod c11.val (2 ^ 51)
    have d2 := Nat.div_add_mod c21.val (2 ^ 51)
    have d3 := Nat.div_add_mod c31.val (2 ^ 51)
    have d4 := Nat.div_add_mod c41.val (2 ^ 51)
    have d6 : i62.val + 2 ^ 51 * i58.val = i35.val + i54.val := by
      rw [hi62, e58, ← hi56]; omega
    rw [hi60]
    clear e30 e31 e32 e33 e36 e37 e38 e39 e41 e42 e43 e44 e46 e47 e48 e49 e51 ecarry e52
      hi35 hi40 hi45 hi50 hi53 hi62 e58 hi56 m64
    unfold p
    omega

/-- Loop spec for `pow2k`: squares the input `k` times (modulo `p`). After at least one
iteration the limbs are bounded by `2 ^ 52`; with `k = 0` the input is returned unchanged. -/
@[progress]
theorem pow2k_loop_spec (k : U32) (a : Array U64 5#usize)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 54) :
    pow2k_loop k a ⦃ (r : Array U64 5#usize) =>
      (∀ i < 5, r[i]!.val < 2 ^ 54) ∧
      (0 < k.val → ∀ i < 5, r[i]!.val < 2 ^ 52) ∧
      (k.val = 0 → r = a) ∧
      Field51_as_Nat r % p = Field51_as_Nat a ^ (2 ^ k.val) % p ⦄ := by
  unfold pow2k_loop
  split
  · rename_i hkpos
    simp only [Array.getElem!_Nat_eq] at ha
    have ha0 := ha 0 (by omega)
    have ha1 := ha 1 (by omega)
    have ha2 := ha 2 (by omega)
    have ha3 := ha 3 (by omega)
    have ha4 := ha 4 (by omega)
    progress as ⟨i, hi⟩
    rw [← hi] at ha3
    progress as ⟨a3_19, ha3_19⟩
    progress as ⟨i1, hi1⟩
    rw [← hi1] at ha4
    progress as ⟨a4_19, ha4_19⟩
    have ha3' : a3_19.val < 19 * 2 ^ 54 := by omega
    have ha4' : a4_19.val < 19 * 2 ^ 54 := by omega
    progress as ⟨i2, hi2⟩
    rw [← hi2] at ha0
    progress as ⟨i3, hi3⟩
    have := pow2k_prod_le hi3 ha0 ha0
    progress as ⟨i4, hi4⟩
    rw [← hi4] at ha1
    progress as ⟨i5, hi5⟩
    have := pow2k_prod_le hi5 ha1 ha4'
    progress as ⟨i6, hi6⟩
    rw [← hi6] at ha2
    progress as ⟨i7, hi7⟩
    have := pow2k_prod_le hi7 ha2 ha3'
    progress as ⟨i8, hi8⟩
    progress as ⟨i9, hi9⟩
    progress as ⟨c0, hc0⟩
    progress as ⟨i10, hi10⟩
    have := pow2k_prod_le hi10 ha3 ha3'
    progress as ⟨i11, hi11⟩
    have := pow2k_prod_le hi11 ha0 ha1
    progress as ⟨i12, hi12⟩
    have := pow2k_prod_le hi12 ha2 ha4'
    progress as ⟨i13, hi13⟩
    progress as ⟨i14, hi14⟩
    progress as ⟨c1, hc1⟩
    progress as ⟨i15, hi15⟩
    have := pow2k_prod_le hi15 ha1 ha1
    progress as ⟨i16, hi16⟩
    have := pow2k_prod_le hi16 ha0 ha2
    progress as ⟨i17, hi17⟩
    have := pow2k_prod_le hi17 ha4 ha3'
    progress as ⟨i18, hi18⟩
    progress as ⟨i19, hi19⟩
    progress as ⟨c2, hc2⟩
    progress as ⟨i20, hi20⟩
    have := pow2k_prod_le hi20 ha4 ha4'
    progress as ⟨i21, hi21⟩
    have := pow2k_prod_le hi21 ha0 ha3
    progress as ⟨i22, hi22⟩
    have := pow2k_prod_le hi22 ha1 ha2
    progress as ⟨i23, hi23⟩
    progress as ⟨i24, hi24⟩
    progress as ⟨c3, hc3⟩
    progress as ⟨i25, hi25⟩
    have := pow2k_prod_le hi25 ha2 ha2
    progress as ⟨i26, hi26⟩
    have := pow2k_prod_le hi26 ha0 ha4
    progress as ⟨i27, hi27⟩
    have := pow2k_prod_le hi27 ha1 ha3
    progress as ⟨i28, hi28⟩
    progress as ⟨i29, hi29⟩
    progress as ⟨c4, hc4⟩
    rw [ha4_19] at hi5 hi12 hi20
    rw [ha3_19] at hi7 hi10 hi17
    have hC0 : c0.val = i2.val * i2.val + 2 * (i4.val * (19 * i1.val) + i6.val * (19 * i.val)) := by
      omega
    have hC1 : c1.val = i.val * (19 * i.val) + 2 * (i2.val * i4.val + i6.val * (19 * i1.val)) := by
      omega
    have hC2 : c2.val = i4.val * i4.val + 2 * (i2.val * i6.val + i1.val * (19 * i.val)) := by
      omega
    have hC3 : c3.val = i1.val * (19 * i1.val) + 2 * (i2.val * i.val + i4.val * i6.val) := by
      omega
    have hC4 : c4.val = i6.val * i6.val + 2 * (i2.val * i1.val + i4.val * i.val) := by
      omega
    have hC0b : c0.val ≤ 77 * 2 ^ 108 := by omega
    have hC1b : c1.val ≤ 77 * 2 ^ 108 := by omega
    have hC2b : c2.val ≤ 77 * 2 ^ 108 := by omega
    have hC3b : c3.val ≤ 77 * 2 ^ 108 := by omega
    have hC4b : c4.val ≤ 5 * 2 ^ 108 := by omega
    have hA : Field51_as_Nat a = i2.val + 2 ^ 51 * i4.val + 2 ^ 102 * i6.val +
        2 ^ 153 * i.val + 2 ^ 204 * i1.val := by
      rw [pow2k_Field51_as_Nat_eq, ← hi2, ← hi4, ← hi6, ← hi, ← hi1]
    have hsq : ∃ K, Field51_as_Nat a ^ 2 = c0.val + 2 ^ 51 * c1.val + 2 ^ 102 * c2.val +
        2 ^ 153 * c3.val + 2 ^ 204 * c4.val + p * K := by
      refine ⟨2 * (i4.val * i1.val + i6.val * i.val) +
        2 ^ 51 * (i.val * i.val + 2 * (i6.val * i1.val)) +
        2 ^ 102 * (2 * (i.val * i1.val)) + 2 ^ 153 * (i1.val * i1.val), ?_⟩
      rw [hA, pow2k_square_identity, hC0, hC1, hC2, hC3, hC4]
    obtain ⟨K, hsq⟩ := hsq
    clear hC0 hC1 hC2 hC3 hC4 hA hi hi1 hi2 hi4 hi6 ha3_19 ha4_19 hi3 hi5 hi7 hi8 hi9 hc0
      hi10 hi11 hi12 hi13 hi14 hc1 hi15 hi16 hi17 hi18 hi19 hc2 hi20 hi21 hi22 hi23 hi24 hc3
      hi25 hi26 hi27 hi28 hi29 hc4
    apply pow2k_tail_spec a c0 c1 c2 c3 c4 _ _ hC0b hC1b hC2b hC3b hC4b
    intro a8 hb8 ⟨q, hval⟩
    have hsq8 : Field51_as_Nat a8 % p = Field51_as_Nat a ^ 2 % p := by
      rw [hsq, ← hval, Nat.add_assoc, Nat.mul_comm q p, ← Nat.mul_add,
        Nat.add_mul_mod_self_left]
    progress as ⟨k1, hk1⟩
    progress with pow2k_loop_spec k1 a8 (fun j hj => by have := hb8 j hj; omega)
      as ⟨r, hr1, hr2, hr3, hr4⟩
    refine ⟨hr1, fun _ => ?_, fun h => by omega, ?_⟩
    · by_cases hk0 : k1.val = 0
      · rw [hr3 hk0]; exact hb8
      · exact hr2 (by omega)
    · have hk2 : 2 ^ k.val = 2 * 2 ^ k1.val := by
        rw [← pow_succ']; congr 1; omega
      rw [hr4, Nat.pow_mod, hsq8, ← Nat.pow_mod, ← pow_mul, hk2]
  · have hk : k.val = 0 := by scalar_tac
    refine ⟨ha, fun h => by omega, fun _ => rfl, ?_⟩
    rw [hk]; simp
termination_by k.val
decreasing_by scalar_tac

/-- `pow2k self k` computes `self ^ (2 ^ k)` modulo `p` for `k > 0`, with output limbs bounded
by `2 ^ 52`. -/
@[progress]
theorem pow2k_spec (self : backend.serial.u64.field.FieldElement51) (k : U32)
    (hk : 0 < k.val) (ha : ∀ i < 5, self[i]!.val < 2 ^ 54) :
    pow2k self k ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val < 2 ^ 52) ∧
      Field51_as_Nat result % p = Field51_as_Nat self ^ (2 ^ k.val) % p ⦄ := by
  unfold pow2k
  progress
  progress with pow2k_loop_spec k self ha as ⟨r, _, hr2, _, hr4⟩
  exact ⟨hr2 hk, hr4⟩

end curve25519_dalek.backend.serial.u64.field.FieldElement51
