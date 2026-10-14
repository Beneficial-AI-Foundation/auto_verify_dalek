import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.field.MulShared0FieldElement51SharedAFieldElement51FieldElement51.mul

@[progress]
theorem LOW_51_BIT_MASK_spec :
    LOW_51_BIT_MASK ⦃ r => r.val = 2 ^ 51 - 1 ⦄ := by
  unfold LOW_51_BIT_MASK
  progress as ⟨i, hi⟩
  progress as ⟨r, hr⟩
  scalar_tac

/-- `m x y` computes the full 128-bit product of two `u64`s; it never overflows. -/
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

end curve25519_dalek.backend.serial.u64.field.MulShared0FieldElement51SharedAFieldElement51FieldElement51.mul

namespace curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51

open backend.serial.u64.field.MulShared0FieldElement51SharedAFieldElement51FieldElement51.mul

attribute [-simp] Int.reducePow Nat.reducePow

theorem prod_le {x y : U64} {r : U128} {X Y : Nat} (h : r.val = x.val * y.val)
    (hx : x.val < X) (hy : y.val < Y) : r.val ≤ X * Y := by
  rw [h]; exact Nat.mul_le_mul hx.le hy.le

theorem cast_U64_val' (x : U128) : (UScalar.cast .U64 x).val = x.val % 2 ^ 64 := by
  rw [UScalar.cast_val_eq]; rfl

theorem cast_U128_val' (x : U64) : (UScalar.cast .U128 x).val = x.val :=
  U64.cast_U128_val_eq x

/-- Masking a `U64` with the low-51-bit mask reduces it modulo `2 ^ 51`. -/
@[progress]
theorem mask51_spec' (x mask : Std.U64) (hmask : mask.val = 2 ^ 51 - 1) :
    (lift (x &&& mask) : Result Std.U64) ⦃ z => z.val = x.val % 2 ^ 51 ∧ z.val < 2 ^ 51 ⦄ := by
  progress as ⟨z, hz, _⟩
  simp only [Aeneas.Std.UScalar.val_and, hmask] at hz
  rw [Nat.and_two_pow_sub_one_eq_mod] at hz
  exact ⟨hz, hz ▸ Nat.mod_lt _ (by norm_num)⟩

/-- Shifting a `U64` right by `51` bits is division by `2 ^ 51`. -/
@[progress]
theorem shiftRight51_spec' (x : Std.U64) :
    (x >>> 51#i32 : Result Std.U64) ⦃ z => z.val = x.val / 2 ^ 51 ∧ z.val ≤ 2 ^ 13 - 1 ⦄ := by
  progress as ⟨z, hz, _⟩
  rw [Nat.shiftRight_eq_div_pow] at hz
  have := x.hBounds
  refine ⟨hz, ?_⟩
  rw [hz]
  have : x.val < 2 ^ 64 := by simpa using this
  omega

/-- Unrolls `Field51_as_Nat` into its five limb terms (list-level indexing). -/
theorem Field51_as_Nat_eq' (X : Array Std.U64 5#usize) :
    Field51_as_Nat X =
      X.val[0]!.val + 2 ^ 51 * X.val[1]!.val + 2 ^ 102 * X.val[2]!.val +
        2 ^ 153 * X.val[3]!.val + 2 ^ 204 * X.val[4]!.val := by
  unfold Field51_as_Nat
  simp only [Array.getElem!_Nat_eq, Finset.sum_range_succ, Finset.sum_range_zero]
  ring

/-- Schoolbook product of two radix-`2^51` numbers, with the high columns folded back using
`2^255 = p + 19`. -/
theorem ring_identity (a0 a1 a2 a3 a4 b0 b1 b2 b3 b4 : Nat) :
    (a0 + 2 ^ 51 * a1 + 2 ^ 102 * a2 + 2 ^ 153 * a3 + 2 ^ 204 * a4) *
      (b0 + 2 ^ 51 * b1 + 2 ^ 102 * b2 + 2 ^ 153 * b3 + 2 ^ 204 * b4) =
    (a0 * b0 + a4 * (b1 * 19) + a3 * (b2 * 19) + a2 * (b3 * 19) + a1 * (b4 * 19)) +
      2 ^ 51 * (a1 * b0 + a0 * b1 + a4 * (b2 * 19) + a3 * (b3 * 19) + a2 * (b4 * 19)) +
      2 ^ 102 * (a2 * b0 + a1 * b1 + a0 * b2 + a4 * (b3 * 19) + a3 * (b4 * 19)) +
      2 ^ 153 * (a3 * b0 + a2 * b1 + a1 * b2 + a0 * b3 + a4 * (b4 * 19)) +
      2 ^ 204 * (a4 * b0 + a3 * b1 + a2 * b2 + a1 * b3 + a0 * b4) +
    p * ((a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1) + 2 ^ 51 * (a2 * b4 + a3 * b3 + a4 * b2) +
      2 ^ 102 * (a3 * b4 + a4 * b3) + 2 ^ 153 * (a4 * b4)) := by
  have hp : ((p : Nat) : ℤ) = 2 ^ 255 - 19 := by unfold p; norm_num
  zify
  rw [hp]
  ring

/-- The carry-propagation tail of `mul`, after the five 128-bit column sums are computed.
It is a verbatim copy of the corresponding suffix of the extracted code. -/
def mul_tail (c0 c1 c2 c3 c4 : U128) : Result backend.serial.u64.field.FieldElement51 := do
  let out := Array.repeat 5#usize 0#u64
  let i51 ← c0 >>> 51#i32
  let i52 ← lift (UScalar.cast .U64 i51)
  let i53 ← lift (UScalar.cast .U128 i52)
  let c11 ← c1 + i53
  let i54 ← lift (UScalar.cast .U64 c0)
  let i55 ←
    backend.serial.u64.field.MulShared0FieldElement51SharedAFieldElement51FieldElement51.mul.LOW_51_BIT_MASK
  let i56 ← lift (i54 &&& i55)
  let out1 ← Array.update out 0#usize i56
  let i57 ← c11 >>> 51#i32
  let i58 ← lift (UScalar.cast .U64 i57)
  let i59 ← lift (UScalar.cast .U128 i58)
  let c21 ← c2 + i59
  let i60 ← lift (UScalar.cast .U64 c11)
  let i61 ← lift (i60 &&& i55)
  let out2 ← Array.update out1 1#usize i61
  let i62 ← c21 >>> 51#i32
  let i63 ← lift (UScalar.cast .U64 i62)
  let i64 ← lift (UScalar.cast .U128 i63)
  let c31 ← c3 + i64
  let i65 ← lift (UScalar.cast .U64 c21)
  let i66 ← lift (i65 &&& i55)
  let out3 ← Array.update out2 2#usize i66
  let i67 ← c31 >>> 51#i32
  let i68 ← lift (UScalar.cast .U64 i67)
  let i69 ← lift (UScalar.cast .U128 i68)
  let c41 ← c4 + i69
  let i70 ← lift (UScalar.cast .U64 c31)
  let i71 ← lift (i70 &&& i55)
  let out4 ← Array.update out3 3#usize i71
  let i72 ← c41 >>> 51#i32
  let carry ← lift (UScalar.cast .U64 i72)
  let i73 ← lift (UScalar.cast .U64 c41)
  let i74 ← lift (i73 &&& i55)
  let out5 ← Array.update out4 4#usize i74
  let i75 ← carry * 19#u64
  let i76 ← Array.index_usize out5 0#usize
  let i77 ← i76 + i75
  let out6 ← Array.update out5 0#usize i77
  let i78 ← Array.index_usize out6 0#usize
  let i79 ← i78 >>> 51#i32
  let i80 ← Array.index_usize out6 1#usize
  let i81 ← i80 + i79
  let out7 ← Array.update out6 1#usize i81
  let i82 ← Array.index_usize out7 0#usize
  let i83 ← lift (i82 &&& i55)
  let out8 ← Array.update out7 0#usize i83
  ok out8

theorem mul_tail_spec (c0 c1 c2 c3 c4 : U128)
    (h0 : c0.val ≤ 77 * 2 ^ 108) (h1 : c1.val ≤ 77 * 2 ^ 108) (h2 : c2.val ≤ 77 * 2 ^ 108)
    (h3 : c3.val ≤ 77 * 2 ^ 108) (h4 : c4.val ≤ 5 * 2 ^ 108) :
    mul_tail c0 c1 c2 c3 c4 ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val < 2 ^ 52) ∧
      ∃ k, Field51_as_Nat result + k * p =
        c0.val + 2 ^ 51 * c1.val + 2 ^ 102 * c2.val + 2 ^ 153 * c3.val + 2 ^ 204 * c4.val ⦄ := by
  unfold mul_tail
  progress as ⟨i51, hi51⟩
  progress as ⟨i52, hi52⟩
  progress as ⟨i53, hi53⟩
  progress as ⟨c11, hc11⟩
  progress as ⟨i54, hi54⟩
  progress as ⟨i55, hi55⟩
  progress as ⟨i56, hi56, hi56b⟩
  progress as ⟨out1, hout1⟩
  progress as ⟨i57, hi57⟩
  progress as ⟨i58, hi58⟩
  progress as ⟨i59, hi59⟩
  progress as ⟨c21, hc21⟩
  progress as ⟨i60, hi60⟩
  progress as ⟨i61, hi61, hi61b⟩
  progress as ⟨out2, hout2⟩
  progress as ⟨i62, hi62⟩
  progress as ⟨i63, hi63⟩
  progress as ⟨i64, hi64⟩
  progress as ⟨c31, hc31⟩
  progress as ⟨i65, hi65⟩
  progress as ⟨i66, hi66, hi66b⟩
  progress as ⟨out3, hout3⟩
  progress as ⟨i67, hi67⟩
  progress as ⟨i68, hi68⟩
  progress as ⟨i69, hi69⟩
  progress as ⟨c41, hc41⟩
  progress as ⟨i70, hi70⟩
  progress as ⟨i71, hi71, hi71b⟩
  progress as ⟨out4, hout4⟩
  progress as ⟨i72, hi72⟩
  progress as ⟨carry, hcarry⟩
  progress as ⟨i73, hi73⟩
  progress as ⟨i74, hi74, hi74b⟩
  progress as ⟨out5, hout5⟩
  have e51 : i51.val = c0.val / 2 ^ 51 := by rw [hi51, Nat.shiftRight_eq_div_pow]
  have e52 : i52.val = i51.val % 2 ^ 64 := by rw [hi52, cast_U64_val']
  have e53 : i53.val = i52.val := by rw [hi53, cast_U128_val']
  have e54 : i54.val = c0.val % 2 ^ 64 := by rw [hi54, cast_U64_val']
  have e57 : i57.val = c11.val / 2 ^ 51 := by rw [hi57, Nat.shiftRight_eq_div_pow]
  have e58 : i58.val = i57.val % 2 ^ 64 := by rw [hi58, cast_U64_val']
  have e59 : i59.val = i58.val := by rw [hi59, cast_U128_val']
  have e60 : i60.val = c11.val % 2 ^ 64 := by rw [hi60, cast_U64_val']
  have e62 : i62.val = c21.val / 2 ^ 51 := by rw [hi62, Nat.shiftRight_eq_div_pow]
  have e63 : i63.val = i62.val % 2 ^ 64 := by rw [hi63, cast_U64_val']
  have e64 : i64.val = i63.val := by rw [hi64, cast_U128_val']
  have e65 : i65.val = c21.val % 2 ^ 64 := by rw [hi65, cast_U64_val']
  have e67 : i67.val = c31.val / 2 ^ 51 := by rw [hi67, Nat.shiftRight_eq_div_pow]
  have e68 : i68.val = i67.val % 2 ^ 64 := by rw [hi68, cast_U64_val']
  have e69 : i69.val = i68.val := by rw [hi69, cast_U128_val']
  have e70 : i70.val = c31.val % 2 ^ 64 := by rw [hi70, cast_U64_val']
  have e72 : i72.val = c41.val / 2 ^ 51 := by rw [hi72, Nat.shiftRight_eq_div_pow]
  have ecarry : carry.val = i72.val % 2 ^ 64 := by rw [hcarry, cast_U64_val']
  have e73 : i73.val = c41.val % 2 ^ 64 := by rw [hi73, cast_U64_val']
  clear hi51 hi52 hi53 hi54 hi57 hi58 hi59 hi60 hi62 hi63 hi64 hi65 hi67 hi68 hi69 hi70
    hi72 hcarry hi73
  have hcarry_b : carry.val ≤ 5 * 2 ^ 57 + 2 ^ 14 := by omega
  progress as ⟨i75, hi75⟩
  progress as ⟨i76, hi76⟩
  have g76 : i76 = i56 := by simp [hi76, hout5, hout4, hout3, hout2, hout1]
  progress as ⟨i77, hi77⟩
  progress as ⟨out6, hout6⟩
  progress as ⟨i78, hi78⟩
  have g78 : i78 = i77 := by simp [hi78, hout6]
  progress as ⟨i79, hi79, hi79b⟩
  progress as ⟨i80, hi80⟩
  have g80 : i80 = i61 := by simp [hi80, hout6, hout5, hout4, hout3, hout2]
  progress as ⟨i81, hi81⟩
  progress as ⟨out7, hout7⟩
  progress as ⟨i82, hi82⟩
  have g82 : i82 = i77 := by simp [hi82, hout7, hout6]
  progress as ⟨i83, hi83, hi83b⟩
  progress as ⟨out8, hout8⟩
  have r0 : out8.val[0]! = i83 := by simp [hout8]
  have r1 : out8.val[1]! = i81 := by simp [hout8, hout7]
  have r2 : out8.val[2]! = i66 := by simp [hout8, hout7, hout6, hout5, hout4, hout3]
  have r3 : out8.val[3]! = i71 := by simp [hout8, hout7, hout6, hout5, hout4]
  have r4 : out8.val[4]! = i74 := by simp [hout8, hout7, hout6, hout5]
  rw [g76] at hi77
  rw [g78] at hi79
  rw [g80] at hi81
  rw [g82] at hi83
  refine ⟨?_, carry.val, ?_⟩
  · intro j hj
    rw [Array.getElem!_Nat_eq]
    interval_cases j
    · rw [r0]; omega
    · rw [r1]; omega
    · rw [r2]; omega
    · rw [r3]; omega
    · rw [r4]; omega
  · rw [Field51_as_Nat_eq', r0, r1, r2, r3, r4]
    have m64 : ∀ x : Nat, x % 2 ^ 64 % 2 ^ 51 = x % 2 ^ 51 := fun x =>
      Nat.mod_mod_of_dvd x (by norm_num)
    have f0 : i56.val = c0.val % 2 ^ 51 := by rw [hi56, e54, m64]
    have f1 : i61.val = c11.val % 2 ^ 51 := by rw [hi61, e60, m64]
    have f2 : i66.val = c21.val % 2 ^ 51 := by rw [hi66, e65, m64]
    have f3 : i71.val = c31.val % 2 ^ 51 := by rw [hi71, e70, m64]
    have f4 : i74.val = c41.val % 2 ^ 51 := by rw [hi74, e73, m64]
    have q0 : i53.val = c0.val / 2 ^ 51 := by omega
    have q1 : i59.val = c11.val / 2 ^ 51 := by omega
    have q2 : i64.val = c21.val / 2 ^ 51 := by omega
    have q3 : i69.val = c31.val / 2 ^ 51 := by omega
    have q4 : carry.val = c41.val / 2 ^ 51 := by omega
    have d0 := Nat.div_add_mod c0.val (2 ^ 51)
    have d1 := Nat.div_add_mod c11.val (2 ^ 51)
    have d2 := Nat.div_add_mod c21.val (2 ^ 51)
    have d3 := Nat.div_add_mod c31.val (2 ^ 51)
    have d4 := Nat.div_add_mod c41.val (2 ^ 51)
    have d6 : i83.val + 2 ^ 51 * i79.val = i56.val + i75.val := by
      rw [hi83, hi79, ← hi77]; omega
    rw [hi81]
    clear e51 e52 e53 e54 e57 e58 e59 e60 e62 e63 e64 e65 e67 e68 e69 e70 e72 ecarry e73
      hi56 hi61 hi66 hi71 hi74 hi83 hi79 hi77 m64 hi79b
    unfold p
    omega

@[progress]
theorem mul_spec (self _rhs : backend.serial.u64.field.FieldElement51)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 54)
    (hb : ∀ i < 5, _rhs[i]!.val < 2 ^ 54) :
    mul self _rhs ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val < 2 ^ 52) ∧
      Field51_as_Nat result % p = (Field51_as_Nat self * Field51_as_Nat _rhs) % p ⦄ := by
  unfold mul
  simp only [Array.getElem!_Nat_eq] at ha hb
  have ha0 := ha 0 (by omega)
  have ha1 := ha 1 (by omega)
  have ha2 := ha 2 (by omega)
  have ha3 := ha 3 (by omega)
  have ha4 := ha 4 (by omega)
  have hb0 := hb 0 (by omega)
  have hb1 := hb 1 (by omega)
  have hb2 := hb 2 (by omega)
  have hb3 := hb 3 (by omega)
  have hb4 := hb 4 (by omega)
  progress as ⟨i, hi⟩
  progress as ⟨b1_19, hb1_19⟩
  progress as ⟨i1, hi1⟩
  progress as ⟨b2_19, hb2_19⟩
  progress as ⟨i2, hi2⟩
  progress as ⟨b3_19, hb3_19⟩
  progress as ⟨i3, hi3⟩
  progress as ⟨b4_19, hb4_19⟩
  progress as ⟨i4, hi4⟩
  progress as ⟨i5, hi5⟩
  rw [← hi] at hb1; rw [← hi1] at hb2; rw [← hi2] at hb3; rw [← hi3] at hb4
  rw [← hi4] at ha0; rw [← hi5] at hb0
  progress as ⟨i6, hi6⟩
  have := prod_le hi6 ha0 hb0
  progress as ⟨i7, hi7⟩
  rw [← hi7] at ha4
  progress as ⟨i8, hi8⟩
  have := prod_le hi8 ha4 (by omega : b1_19.val < 2 ^ 54 * 19)
  have hb1' : b1_19.val < 2 ^ 54 * 19 := by omega
  have hb2' : b2_19.val < 2 ^ 54 * 19 := by omega
  have hb3' : b3_19.val < 2 ^ 54 * 19 := by omega
  have hb4' : b4_19.val < 2 ^ 54 * 19 := by omega
  progress as ⟨i9, hi9⟩
  progress as ⟨i10, hi10⟩
  rw [← hi10] at ha3
  progress as ⟨i11, hi11⟩
  have := prod_le hi11 ha3 hb2'
  progress as ⟨i12, hi12⟩
  progress as ⟨i13, hi13⟩
  rw [← hi13] at ha2
  progress as ⟨i14, hi14⟩
  have := prod_le hi14 ha2 hb3'
  progress as ⟨i15, hi15⟩
  progress as ⟨i16, hi16⟩
  rw [← hi16] at ha1
  progress as ⟨i17, hi17⟩
  have := prod_le hi17 ha1 hb4'
  progress as ⟨c0, hc0⟩
  -- c1
  progress as ⟨i18, hi18⟩
  have := prod_le hi18 ha1 hb0
  progress as ⟨i19, hi19⟩
  have := prod_le hi19 ha0 hb1
  progress as ⟨i20, hi20⟩
  progress as ⟨i21, hi21⟩
  have := prod_le hi21 ha4 hb2'
  progress as ⟨i22, hi22⟩
  progress as ⟨i23, hi23⟩
  have := prod_le hi23 ha3 hb3'
  progress as ⟨i24, hi24⟩
  progress as ⟨i25, hi25⟩
  have := prod_le hi25 ha2 hb4'
  progress as ⟨c1, hc1⟩
  -- c2
  progress as ⟨i26, hi26⟩
  have := prod_le hi26 ha2 hb0
  progress as ⟨i27, hi27⟩
  have := prod_le hi27 ha1 hb1
  progress as ⟨i28, hi28⟩
  progress as ⟨i29, hi29⟩
  have := prod_le hi29 ha0 hb2
  progress as ⟨i30, hi30⟩
  progress as ⟨i31, hi31⟩
  have := prod_le hi31 ha4 hb3'
  progress as ⟨i32, hi32⟩
  progress as ⟨i33, hi33⟩
  have := prod_le hi33 ha3 hb4'
  progress as ⟨c2, hc2⟩
  -- c3
  progress as ⟨i34, hi34⟩
  have := prod_le hi34 ha3 hb0
  progress as ⟨i35, hi35⟩
  have := prod_le hi35 ha2 hb1
  progress as ⟨i36, hi36⟩
  progress as ⟨i37, hi37⟩
  have := prod_le hi37 ha1 hb2
  progress as ⟨i38, hi38⟩
  progress as ⟨i39, hi39⟩
  have := prod_le hi39 ha0 hb3
  progress as ⟨i40, hi40⟩
  progress as ⟨i41, hi41⟩
  have := prod_le hi41 ha4 hb4'
  progress as ⟨c3, hc3⟩
  -- c4
  progress as ⟨i42, hi42⟩
  have := prod_le hi42 ha4 hb0
  progress as ⟨i43, hi43⟩
  have := prod_le hi43 ha3 hb1
  progress as ⟨i44, hi44⟩
  progress as ⟨i45, hi45⟩
  have := prod_le hi45 ha2 hb2
  progress as ⟨i46, hi46⟩
  progress as ⟨i47, hi47⟩
  have := prod_le hi47 ha1 hb3
  progress as ⟨i48, hi48⟩
  progress as ⟨i49, hi49⟩
  have := prod_le hi49 ha0 hb4
  progress as ⟨c4, hc4⟩
  have hC0 : c0.val = i4.val * i5.val + i7.val * b1_19.val + i10.val * b2_19.val +
      i13.val * b3_19.val + i16.val * b4_19.val := by omega
  have hC1 : c1.val = i16.val * i5.val + i4.val * i.val + i7.val * b2_19.val +
      i10.val * b3_19.val + i13.val * b4_19.val := by omega
  have hC2 : c2.val = i13.val * i5.val + i16.val * i.val + i4.val * i1.val +
      i7.val * b3_19.val + i10.val * b4_19.val := by omega
  have hC3 : c3.val = i10.val * i5.val + i13.val * i.val + i16.val * i1.val +
      i4.val * i2.val + i7.val * b4_19.val := by omega
  have hC4 : c4.val = i7.val * i5.val + i10.val * i.val + i13.val * i1.val +
      i16.val * i2.val + i4.val * i3.val := by omega
  have hC0b : c0.val ≤ 77 * 2 ^ 108 := by omega
  have hC1b : c1.val ≤ 77 * 2 ^ 108 := by omega
  have hC2b : c2.val ≤ 77 * 2 ^ 108 := by omega
  have hC3b : c3.val ≤ 77 * 2 ^ 108 := by omega
  have hC4b : c4.val ≤ 5 * 2 ^ 108 := by omega
  clear * - hi hi1 hi2 hi3 hi4 hi5 hi7 hi10 hi13 hi16 hb1_19 hb2_19 hb3_19 hb4_19
    ha0 ha1 ha2 ha3 ha4 hb0 hb1 hb2 hb3 hb4 hC0 hC1 hC2 hC3 hC4 hC0b hC1b hC2b hC3b hC4b
  progress as ⟨i50, hi50⟩
  progress
  progress
  progress
  progress
  progress
  progress
  progress
  progress
  progress
  progress
  apply spec_mono (mul_tail_spec c0 c1 c2 c3 c4 hC0b hC1b hC2b hC3b hC4b)
  rintro r ⟨hr, k, hk⟩
  refine ⟨hr, ?_⟩
  have hA : Field51_as_Nat self = i4.val + 2 ^ 51 * i16.val + 2 ^ 102 * i13.val +
      2 ^ 153 * i10.val + 2 ^ 204 * i7.val := by
    rw [Field51_as_Nat_eq', ← hi4, ← hi16, ← hi13, ← hi10, ← hi7]
  have hB : Field51_as_Nat _rhs = i5.val + 2 ^ 51 * i.val + 2 ^ 102 * i1.val +
      2 ^ 153 * i2.val + 2 ^ 204 * i3.val := by
    rw [Field51_as_Nat_eq', ← hi5, ← hi, ← hi1, ← hi2, ← hi3]
  rw [hA, hB, ring_identity, ← hb1_19, ← hb2_19, ← hb3_19, ← hb4_19, ← hC0, ← hC1, ← hC2,
    ← hC3, ← hC4, ← hk, Nat.add_assoc, Nat.mul_comm k p, ← Nat.mul_add,
    Nat.add_mul_mod_self_left]

end curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51
