




import Curve25519Dalek.Math.BitList
import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Curve25519Dalek.ExternallyVerified






































































namespace curve25519_dalek.backend.serial.u64.field.FieldElement51
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open scoped BigOperators
open List BitList







private lemma u8_mul_pow_lt_u64_size (x : U8) (k : Nat) (hk : k ≤ 56) :
    x.val * 2 ^ k < U64.size := calc
  _ ≤ 255 * 2 ^ 56 := Nat.mul_le_mul (Nat.lt_succ_iff.mp x.hmax)
        (Nat.pow_le_pow_right (by omega) hk)
  _ < U64.size := by scalar_tac

private lemma u8_val_mod_u64_numBits (x : U8) :
    x.val % 2 ^ UScalarTy.U64.numBits = x.val :=
  Nat.mod_eq_of_lt (Nat.lt_of_lt_of_le x.hmax (by norm_num))

private lemma u8_mul_pow_mod_u64 (x : U8) (k : Nat) (hk : k ≤ 56) :
    x.val * 2 ^ k % U64.size = x.val * 2 ^ k :=
  Nat.mod_eq_of_lt (u8_mul_pow_lt_u64_size x k hk)


private lemma or_bytes_eq_sum (b0 b1 b2 b3 b4 b5 b6 b7 : Nat) (_ : b0 < 256) (_ : b1 < 256)
    (_ : b2 < 256) (_ : b3 < 256) (_ : b4 < 256) (_ : b5 < 256) (_ : b6 < 256) (_ : b7 < 256) :
    ((((((b0 ||| b1 * 2^8) ||| b2 * 2^16) ||| b3 * 2^24) |||
      b4 * 2^32) ||| b5 * 2^40) ||| b6 * 2^48) ||| b7 * 2^56 =
      b0 + b1 * 2^8 + b2 * 2^16 + b3 * 2^24 + b4 * 2^32 + b5 * 2^40 + b6 * 2^48 + b7 * 2^56 := by
  rw [or_mul_pow_two_eq_add _ _ 8 (by omega), or_mul_pow_two_eq_add _ _ 16 (by grind),
    or_mul_pow_two_eq_add _ _ 24 (by grind), or_mul_pow_two_eq_add _ _ 32 (by grind),
    or_mul_pow_two_eq_add _ _ 40 (by grind), or_mul_pow_two_eq_add _ _ 48 (by grind),
    or_mul_pow_two_eq_add _ _ 56 (by grind)]


@[progress]
theorem load8_at_val_spec (input : Slice U8) (i : Usize) (h : i.val + 8 ≤ input.val.length) :
    from_bytes.load8_at input i ⦃ (result : U64) =>
      result.val = ∑ j ∈ Finset.range 8, input[i.val + j]!.val * 2 ^ (8 * j) ⦄ := by
  sorry
private lemma extract_getElem! (l : List U8) (i j : Nat) (hj : j < 8) :
    (l.extract i (i + 8))[j]! = l[i + j]! := by grind

private lemma sum_extract_eq (l : List U8) (i : Nat) (hi : i + 8 ≤ l.length) :
    ∑ j ∈ Finset.range 8, l[i + j]!.val * 2 ^ (8 * j) =
      Nat.ofDigits 256 ((l.extract i (i + 8)).map (·.val)) := by
  have hlen : (l.extract i (i + 8)).length = 8 := by
    simp [extract_eq_drop_take, length_take, length_drop]; omega
  rw [ofDigits_map_val_eq_sum, hlen]
  apply Finset.sum_congr rfl; intro j hj; rw [Finset.mem_range] at hj
  rw [extract_getElem! l i j hj, show (256 : Nat) = 2 ^ 8 from by norm_num, ← Nat.pow_mul]


@[progress]
theorem load8_at_bitList_spec (input : Slice U8) (i : Usize) (h : i.val + 8 ≤ input.val.length) :
    from_bytes.load8_at input i ⦃ (result : U64) =>
      ofU64 result = (ofByteList input.val).extract (8 * i.val) (8 * i.val + 64) ⦄ := by
  sorry






attribute [-progress] load8_at_val_spec load8_at_bitList_spec


@[progress]
theorem u64_shr_bitList_spec (x : U64) (k : I32) (hk0 : 0 ≤ k.val) (hk : k.val < 64) :
    (x >>> k) ⦃ (z : UScalar UScalarTy.U64) => ofU64 z ≈ₗ (ofU64 x).drop k.toNat ⦄ := by
  sorry

theorem u64_and_mask_bitList_spec (x mask : U64) (n : Nat)
    (hn : n ≤ 64) (hmask : mask.val = 2 ^ n - 1) :
    lift (x &&& mask) ⦃ (z : UScalar UScalarTy.U64) => ofU64 z ≈ₗ (ofU64 x).take n ⦄ := by
  sorry

@[progress]
theorem u64_and_mask51_bitList_spec (x mask : U64)
    (hmask : mask.val = 2251799813685247) :
    lift (x &&& mask) ⦃ (z : U64) => ofU64 z ≈ₗ (ofU64 x).take 51 ⦄ := sorry

@[progress]
theorem load8_at_bitList_progress_spec (input : Slice U8) (i : Usize)
    (h : i.val + 8 ≤ input.val.length) :
    from_bytes.load8_at input i ⦃ result =>
      ofU64 result ≈ₗ
        (ofByteList input.val).extract (8 * i.val) (8 * i.val + 64) ⦄ := by
  sorry



theorem field51_eq_of_bitList (result : FieldElement51) (bytes : Array U8 32#usize)
    (hequiv : ∀ i : Fin 5,
      ofU64 result[i]! ≈ₗ (ofByteArray bytes).extract (51 * i.val) (51 * i.val + 51)) :
    Field51_as_Nat result = U8x32_as_Nat bytes % 2 ^ 255 := by
  sorry

theorem limb_bound_of_equiv (result : FieldElement51) (bytes : Array U8 32#usize)
    (hequiv : ∀ i : Fin 5,
      ofU64 result[i]! ≈ₗ (ofByteArray bytes).extract (51 * i.val) (51 * i.val + 51)) :
    ∀ i : Fin 5, result[i]!.val < 2 ^ 51 := by
  sorry



@[progress]
theorem from_bytes_bitList_spec (bytes : Array U8 32#usize) :
    from_bytes bytes ⦃ (result : FieldElement51) =>
      ∀ i : Fin 5,
        ofU64 result[i]! ≈ₗ (ofByteArray bytes).extract (51 * i.val) (51 * i.val + 51) ⦄ := by
  sorry


@[progress]
theorem from_bytes_spec (bytes : Array U8 32#usize) :
    from_bytes bytes ⦃ (result : FieldElement51) =>
      Field51_as_Nat result ≡ (U8x32_as_Nat bytes % 2^255) [MOD p] ∧
      (∀ i < 5, result[i]!.val < 2^51) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
