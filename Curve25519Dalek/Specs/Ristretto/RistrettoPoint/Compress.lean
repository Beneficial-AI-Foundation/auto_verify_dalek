




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square
import Curve25519Dalek.Specs.Field.FieldElement51.InvSqrt
import Curve25519Dalek.Specs.Field.FieldElement51.IsNegative
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalAssign
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Neg
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.SQRT_M1
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.INVSQRT_A_MINUS_D















open Aeneas Aeneas.Std Result Aeneas.Std.WP Edwards
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.math curve25519_dalek.ristretto
namespace curve25519_dalek.ristretto.RistrettoPoint





















private lemma bridge_mul {a b c : FieldElement51}
    (h : Field51_as_Nat a ≡ Field51_as_Nat b * Field51_as_Nat c [MOD p]) :
    a.toField = b.toField * c.toField := by
  unfold FieldElement51.toField
  simpa only [Nat.cast_mul] using lift_mod_eq _ _ h

private lemma bridge_sq {a b : FieldElement51}
    (h : Field51_as_Nat a ≡ Field51_as_Nat b ^ 2 [MOD p]) :
    a.toField = b.toField ^ 2 := by
  unfold FieldElement51.toField
  simpa only [Nat.cast_pow] using lift_mod_eq _ _ h

private lemma bridge_sub {a b c : FieldElement51}
    (h : (Field51_as_Nat a + Field51_as_Nat c) % p = Field51_as_Nat b % p) :
    a.toField = b.toField - c.toField := by
  unfold FieldElement51.toField; have := lift_mod_eq _ _ h
  push_cast at this; linear_combination this

private lemma bridge_neg {a b : FieldElement51}
    (h : Field51_as_Nat a + Field51_as_Nat b ≡ 0 [MOD p]) :
    b.toField = -a.toField := by
  unfold FieldElement51.toField; have := lift_mod_eq _ _ h
  push_cast at this; linear_combination this

private lemma bridge_add {a b c : FieldElement51}
    (h : ∀ i < 5, (a[i]!).val = (b[i]!).val + (c[i]!).val) :
    a.toField = b.toField + c.toField := by
  unfold FieldElement51.toField Field51_as_Nat
  have key : ∑ i ∈ Finset.range 5, 2 ^ (51 * i) * (a[i]!).val =
    ∑ i ∈ Finset.range 5, 2 ^ (51 * i) * (b[i]!).val +
    ∑ i ∈ Finset.range 5, 2 ^ (51 * i) * (c[i]!).val := by
    rw [← Finset.sum_add_distrib]; apply Finset.sum_congr rfl
    intro i hi; rw [Finset.mem_range] at hi; rw [h i hi]; ring
  exact (congrArg Nat.cast key).trans (Nat.cast_add _ _)

private lemma bridge_cond_nat {a b c : FieldElement51} {flag : subtle.Choice}
    (h : ∀ i < 5, a[i]! = if flag.val = 1#u8 then b[i]! else c[i]!) :
    Field51_as_Nat a = if flag.val = 1#u8 then Field51_as_Nat b else Field51_as_Nat c := by
  unfold Field51_as_Nat; split <;> rename_i hc
  · apply Finset.sum_congr rfl; intro i hi; rw [Finset.mem_range] at hi
    have := h i hi; rw [if_pos hc] at this; rw [this]
  · apply Finset.sum_congr rfl; intro i hi; rw [Finset.mem_range] at hi
    have := h i hi; rw [if_neg hc] at this; rw [this]

private lemma bridge_cond {a b c : FieldElement51} {flag : subtle.Choice}
    (h : ∀ i < 5, a[i]! = if flag.val = 1#u8 then b[i]! else c[i]!) :
    a.toField = if flag.val = 1#u8 then b.toField else c.toField := by
  unfold FieldElement51.toField; rw [bridge_cond_nat h]; split <;> rfl

private lemma flag_eq_true_iff_is_negative_of_val {flag : subtle.Choice} {n : Nat} {x : ZMod p}
    (hflag : flag.val = 1#u8 ↔ n % 2 = 1) (hx : n = x.val) :
    flag.val = 1#u8 ↔ is_negative x = true := by
  refine ⟨?_, ?_ ⟩
  · intro hf
    unfold is_negative
    rw [beq_iff_eq, ← hx]; exact hflag.mp hf
  · intro hneg
    exact hflag.mpr (by
      unfold is_negative at hneg; rw [beq_iff_eq] at hneg; rwa [← hx] at hneg)

private lemma flag_eq_true_iff_is_negative_of_neg_val
    {flag : subtle.Choice} {n : Nat} {x : ZMod p}
    (hflag : flag.val = 1#u8 ↔ n % 2 = 1) (hx : n = (-x).val) (hx_ne : x ≠ 0) :
    flag.val = 1#u8 ↔ is_negative x = false := by
  have hxv_ne : x.val ≠ 0 := by rwa [ne_eq, ZMod.val_eq_zero]
  have hxlt : x.val < p := x.val_lt
  have hxpos : 0 < x.val := Nat.pos_of_ne_zero hxv_ne
  have hp_odd : p % 2 = 1 := by decide
  have hneg_val : (-x).val = p - x.val := by
    rw [ZMod.neg_val]; exact if_neg hx_ne
  refine ⟨?_, ?_⟩
  · intro hf
    unfold is_negative
    rw [beq_eq_false_iff_ne]
    have hneg : (-x).val % 2 = 1 := by
      have : n % 2 = 1 := hflag.mp hf; rwa [hx] at this
    rw [hneg_val] at hneg
    exact fun h => by omega
  · intro hneg
    apply hflag.mpr
    unfold is_negative at hneg
    rw [beq_eq_false_iff_ne] at hneg
    rw [hx, hneg_val]
    omega

private lemma cond_neg_scale_of_flag_match (Z y x : ZMod p) (flag : subtle.Choice)
    (hflag : flag.val = 1#u8 ↔ is_negative x = true) :
    (if flag.val = 1#u8 then -(Z * y) else Z * y) =
      Z * (if is_negative x = true then -y else y) := by
  cases hix : is_negative x with
  | false =>
      have hf : flag.val ≠ 1#u8 := by
        intro hf
        have : is_negative x = true := hflag.mp hf
        rw [hix] at this
        cases this
      rw [if_neg hf, if_neg (by decide : ¬ false = true)]
  | true =>
      have hf : flag.val = 1#u8 := hflag.mpr hix
      rw [if_pos hf, if_pos (by decide : true = true)]
      ring

private lemma cond_neg_scale_of_neg_flag_match (Z y x : ZMod p) (flag : subtle.Choice)
    (hflag : flag.val = 1#u8 ↔ is_negative x = false) :
    (if flag.val = 1#u8 then -(Z * -y) else Z * -y) =
      Z * (if is_negative x = true then -y else y) := by
  cases hix : is_negative x with
  | false =>
      have hf : flag.val = 1#u8 := hflag.mpr hix
      rw [if_pos hf, if_neg (by decide : ¬ false = true)]
      ring
  | true =>
      have hf : flag.val ≠ 1#u8 := by
        intro hf
        have : is_negative x = false := hflag.mp hf
        rw [hix] at this
        cases this
      rw [if_neg hf, if_pos (by decide : true = true)]

private lemma lift_fe_sq (fe : FieldElement51) (h : Field51_as_Nat fe ^ 2 % p = p - 1) :
    fe.toField ^ 2 = -1 := by
  unfold FieldElement51.toField
  have h := lift_mod_eq (Field51_as_Nat fe ^ 2) (p - 1) (by rwa [Nat.mod_eq_of_lt (show p - 1 < p from by decide)])
  push_cast at h; rwa [p_sub_one_cast] at h

private lemma lift_rm_sq (rm : FieldElement51)
    (h : (Field51_as_Nat rm) ^ 2 * (a - d) % p = 1) :
    rm.toField ^ 2 * (a_val - (↑d : ZMod p)) = 1 := by
  unfold FieldElement51.toField a_val
  rw [show a = (-1 : ℤ) from rfl] at h
  have : (((↑(Field51_as_Nat rm) : ℤ) ^ 2 * (-1 - ↑d) : ℤ) : ZMod p) = 1 := by
    rw [← ZMod.intCast_mod _ p, h, Int.cast_one]
  push_cast at this; exact this

set_option maxHeartbeats 800000 in





@[progress]
theorem compress_spec (self : RistrettoPoint) (h : self.IsValid) :
    compress self ⦃ (result : CompressedRistretto) =>
      result.IsValid ∧
      math.compress_pure self.toPoint = U8x32_as_Nat result ⦄ := by
  sorry
end curve25519_dalek.ristretto.RistrettoPoint
