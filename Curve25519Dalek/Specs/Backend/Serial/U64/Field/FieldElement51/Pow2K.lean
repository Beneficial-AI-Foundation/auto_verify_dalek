




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux

set_option linter.hashCommand false
#setup_aeneas_simps


























































































































open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.pow2k

@[progress]
theorem m_spec (x y : U64) :
    m x y ⦃ (result : U128) => result.val = x.val * y.val ⦄ := by
  sorry
@[progress]
theorem LOW_51_BIT_MASK_spec :
    LOW_51_BIT_MASK ⦃ (result : U64) => result.val = 2^51 - 1 ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51.pow2k

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51






lemma c0_lt_pow2_115 (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a0 * a0 + 2 * (a1 * (19 * a4) + a2 * (19 * a3)) < 2 ^ 115 := by
  sorry

lemma c1_lt_pow2_115 (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a3 * (19 * a3) + 2 * (a0 * a1 + a2 * (19 * a4)) < 2 ^ 115 := by
  sorry

lemma c2_lt_pow2_115 (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a1 * a1 + 2 * (a0 * a2 + a4 * (19 * a3)) < 2 ^ 115 := by
  sorry

lemma c3_lt_pow2_115 (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a4 * (19 * a4) + 2 * (a0 * a3 + a1 * a2) < 2 ^ 115 := by
  sorry

lemma c4_lt_pow2_115 (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a2 * a2 + 2 * (a0 * a4 + a1 * a3) < 2 ^ 115 := by
  sorry

private lemma carry_chain_lt_pow2_115 (formula carry : ℕ) (K : ℕ)
    (hf : formula < K * 2 ^ 108) (hc : carry < 2 ^ 64) (hK : K ≤ 127) :
    formula + carry < 2 ^ 115 := by
  have : K * 2 ^ 108 + 2 ^ 64 ≤ 128 * 2 ^ 108 := by omega
  have : (128 : ℕ) * 2 ^ 108 = 2 ^ 115 := by decide
  omega


private lemma c1_lt_tight (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a3 * (19 * a3) + 2 * (a0 * a1 + a2 * (19 * a4)) < 59 * 2 ^ 108 := by
  have : a3 * (19 * a3) < 19 * 2 ^ 108 := by nlinarith
  have : a0 * a1 < 2 ^ 108 := by nlinarith
  have : a2 * (19 * a4) < 19 * 2 ^ 108 := by nlinarith
  omega


private lemma c2_lt_tight (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a1 * a1 + 2 * (a0 * a2 + a4 * (19 * a3)) < 41 * 2 ^ 108 := by
  have : a1 * a1 < 2 ^ 108 := by nlinarith
  have : a0 * a2 < 2 ^ 108 := by nlinarith
  have : a4 * (19 * a3) < 19 * 2 ^ 108 := by nlinarith
  omega


private lemma c3_lt_tight (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a4 * (19 * a4) + 2 * (a0 * a3 + a1 * a2) < 23 * 2 ^ 108 := by
  have : a4 * (19 * a4) < 19 * 2 ^ 108 := by nlinarith
  have : a0 * a3 < 2 ^ 108 := by nlinarith
  have : a1 * a2 < 2 ^ 108 := by nlinarith
  omega


private lemma c4_lt_tight (a0 a1 a2 a3 a4 : ℕ)
    (h0 : a0 < 2 ^ 54) (h1 : a1 < 2 ^ 54) (h2 : a2 < 2 ^ 54) (h3 : a3 < 2 ^ 54) (h4 : a4 < 2 ^ 54) :
    a2 * a2 + 2 * (a0 * a4 + a1 * a3) < 5 * 2 ^ 108 := by
  have : a2 * a2 < 2 ^ 108 := by nlinarith
  have : a0 * a4 < 2 ^ 108 := by nlinarith
  have : a1 * a3 < 2 ^ 108 := by nlinarith
  omega


lemma decompose (a0 a1 a2 a3 a4 : ℕ) :
    (a0 + 2^51 * a1 + 2^102 * a2 + 2^153 * a3 + 2^204 * a4)^2
    ≡ a0 * a0 + 2 * (a1 * (19 * a4) + a2 * (19 * a3)) +
      2^51 * (a3 * (19 * a3) + 2 * (a0 * a1 + a2 * (19 * a4))) +
      2^102 * (a1 * a1 + 2 * (a0 * a2 + a4 * (19 * a3))) +
      2^153 * (a4 * (19 * a4) + 2 * (a0 * a3 + a1 * a2)) +
      2^204 * (a2 * a2 + 2 * (a0 * a4 + a1 * a3)) [MOD p] := by
  sorry

private lemma carry_chain_eq (c0 c1 c2 c3 c4 a0 a1 a2 a3 a4 carry c1' c2' c3' c4' : ℕ)
    (ha0 : a0 = c0 % 2 ^ 51) (ha1 : a1 = c1' % 2 ^ 51) (ha2 : a2 = c2' % 2 ^ 51)
    (ha3 : a3 = c3' % 2 ^ 51) (ha4 : a4 = c4' % 2 ^ 51)
    (hc1' : c1' = c1 + c0 / 2 ^ 51) (hc2' : c2' = c2 + c1' / 2 ^ 51)
    (hc3' : c3' = c3 + c2' / 2 ^ 51) (hc4' : c4' = c4 + c3' / 2 ^ 51)
    (hcarry : carry = c4' / 2 ^ 51) :
    c0 + 2^51*c1 + 2^102*c2 + 2^153*c3 + 2^204*c4 =
    a0 + 2^51*a1 + 2^102*a2 + 2^153*a3 + 2^204*a4 + 2^255*carry := by omega

set_option maxHeartbeats 1400000 in

@[progress]
theorem pow2k_loop_spec (k : U32) (a : Array U64 5#usize)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 54) :
    pow2k_loop k a ⦃ (result : Std.Array U64 5#usize) =>
      Field51_as_Nat result ≡ (Field51_as_Nat a)^(2^k.val) [MOD p] ∧
      (if k.val = 0 then result = a else ∀ i < 5, result[i]!.val < 2 ^ 52) ⦄ := by
  sorry
@[progress]
theorem pow2k_spec (self : Array U64 5#usize) (k : U32) (_ : 0 < k.val)
    (_ : ∀ i < 5, self[i]!.val < 2 ^ 54) :
    pow2k self k ⦃ (result : FieldElement51) =>
      Field51_as_Nat result ≡ (Field51_as_Nat self)^(2^k.val) [MOD p] ∧
      (∀ i < 5, result[i]!.val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
