




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ZERO
import Curve25519Dalek.Specs.Scalar.Scalar.AsBytes
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Montgomery.MontgomeryPoint.AsAffine
import Curve25519Dalek.Specs.Montgomery.ProjectivePoint.DifferentialAddAndDouble
















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery

namespace curve25519_dalek.Shared1MontgomeryPoint.Insts.CoreOpsArithMulShared0ScalarMontgomeryPoint































@[progress]
theorem mul_loop_spec
    (affine_u : backend.serial.u64.field.FieldElement51)
    (x0 x1 : montgomery.ProjectivePoint)
    (scalar_bytes : Array U8 32#usize)
    (prev_bit : Bool)
    (i : Isize)
    (idx0W : Field51_as_Nat x0.W = 0)
    (idx1W : Field51_as_Nat x1.W = 1)
    (idx0U : Field51_as_Nat x0.U = 1)
    :
    mul_loop affine_u x0 x1 scalar_bytes prev_bit i ⦃ res =>
    (res.2.2 =true →
      let q := (i.val / 8).toNat
      let r := (i.val % 8).toNat
      let m := ∑ i ∈ Finset.range q, 2^(8 * i) * (scalar_bytes[i]!).val
        +  2^(8 * q) * ((scalar_bytes[q]!).val % 2^(r+1))
        + 2^(8 * q+r) * prev_bit.toNat
      let u := x1.U.toField
      let u_out := res.2.1.U.toField
      let w_out := res.2.1.W.toField
      let u_ord := u_out/w_out
      res.2.1.U.IsValid ∧
      res.2.1.W.IsValid ∧
      res.1.U.IsValid ∧
      res.1.W.IsValid ∧
      w_out ≠ 0 ∧
      MontgomeryPoint.u_affine_toPoint u_ord = m • (MontgomeryPoint.u_affine_toPoint u)) ∧
    (res.2.2 = false →
      let q := (i.val / 8).toNat
      let r := (i.val % 8).toNat
      let m := ∑ i ∈ Finset.range q, 2^(8 * i) * (scalar_bytes[i]!).val
      + 2^(8 * q) * ((scalar_bytes[q]!).val % 2^(r+1))
      + 2^(8 * q+r) * prev_bit.toNat
      let u := x1.U.toField
      let u_out := res.1.U.toField
      let w_out := res.1.W.toField
      let u_ord := u_out/w_out
      res.2.1.U.IsValid ∧
      res.2.1.W.IsValid ∧
      res.1.U.IsValid ∧
      res.1.W.IsValid ∧
      w_out ≠ 0 ∧
      MontgomeryPoint.u_affine_toPoint u_ord = m • (MontgomeryPoint.u_affine_toPoint u)) ⦄
    := by
  sorry


















lemma aux_eq_mul (scalar : scalar.Scalar) : U8x32_as_Nat scalar.bytes =
(∑ x ∈ Finset.range ((254 :ℤ )/ 8).toNat, 2 ^ (8 * x) * (scalar.bytes[x]!).val +
        2 ^ (8 * ((254 :ℤ ) / 8).toNat) * ((scalar.bytes[((254 :ℤ )/ 8).toNat]!).val % 2 ^ (((254 :ℤ ) % 8).toNat+1) ))
        + 2^ 255 * ((scalar.bytes[31]!).val/ 2^7)
        := by
  sorry
lemma aux_lt_mul (i : ℕ) (scalar : scalar.Scalar) :
∑ x ∈ Finset.range i, 2 ^ (8 * x) * (scalar.bytes[x]!).val <  2^ (8*i)
        := by
  sorry
lemma aux_lt254_mul (scalar : scalar.Scalar) :
∑ x ∈ Finset.range ((254 :ℤ )/ 8).toNat, 2 ^ (8 * x) * (scalar.bytes[x]!).val +
        2 ^ (8 * ((254 :ℤ ) / 8).toNat) * ((scalar.bytes[((254 :ℤ ) / 8).toNat]!).val % 2 ^ (((254 :ℤ ) % 8).toNat+1) )
        <  2^ 255
        := by
  sorry
lemma aux_eq_mod_mul (scalar : scalar.Scalar) : (U8x32_as_Nat scalar.bytes) % 2^ 255 =
  (∑ x ∈ Finset.range ((254 :ℤ )/ 8).toNat, 2 ^ (8 * x) * (scalar.bytes[x]!).val +
        2 ^ (8 * ((254 :ℤ ) / 8).toNat) * ((scalar.bytes[((254 :ℤ ) / 8).toNat]!).val % 2 ^ (((254 :ℤ ) % 8).toNat+1) )):= by
  sorry












lemma mul_spec_toField_eq
    (x : backend.serial.u64.field.FieldElement51)
    (P : montgomery.MontgomeryPoint)
    (hmod_x : Field51_as_Nat x ≡ (U8x32_as_Nat P) % 2 ^ 255 [MOD p]) :
    x.toField = ((U8x32_as_Nat P % 2 ^ 255 : ℕ) : CurveField) := by
  sorry










lemma mul_spec_mkPoint_from_affine
    (res : Array U8 32#usize)
    (P : montgomery.MontgomeryPoint)
    (scalar : scalar.Scalar)
    (x : backend.serial.u64.field.FieldElement51)
    (u_div_w : CurveField)
    (hmod_x : Field51_as_Nat x ≡ (U8x32_as_Nat P) % 2 ^ 255 [MOD p])
    (res_bound : U8x32_as_Nat res < 2 ^ 255)
    (res_field : U8x32_as_Field res = u_div_w)
    (loop_inv : MontgomeryPoint.u_affine_toPoint u_div_w =
        ((U8x32_as_Nat scalar.bytes) % 2 ^ 255) • MontgomeryPoint.u_affine_toPoint x.toField) :
    MontgomeryPoint.mkPoint res =
        ((U8x32_as_Nat scalar.bytes) % 2 ^ 255) • MontgomeryPoint.mkPoint P := by
  sorry



















@[progress, externally_verified]
theorem mul_spec (P : montgomery.MontgomeryPoint) (scalar : scalar.Scalar) :
    mul P scalar ⦃ res =>
      let m:= (U8x32_as_Nat scalar.bytes) % 2^255
      MontgomeryPoint.mkPoint res = m • (MontgomeryPoint.mkPoint P) ⦄ := by
  sorry
end curve25519_dalek.Shared1MontgomeryPoint.Insts.CoreOpsArithMulShared0ScalarMontgomeryPoint

namespace curve25519_dalek.Shared1Scalar.Insts.CoreOpsArithMulShared0MontgomeryPointMontgomeryPoint































@[progress]
theorem mul_spec (scalar : scalar.Scalar) (P : montgomery.MontgomeryPoint) :
    mul scalar P ⦃ res =>
    let m:= (U8x32_as_Nat scalar.bytes) % 2^255
    MontgomeryPoint.mkPoint res = m • (MontgomeryPoint.mkPoint P) ⦄
    := by
  sorry
end curve25519_dalek.Shared1Scalar.Insts.CoreOpsArithMulShared0MontgomeryPointMontgomeryPoint

namespace curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint

































@[progress]
theorem mul_spec (P : MontgomeryPoint) (rhs : scalar.Scalar) :
    mul P rhs ⦃ res =>
    let m:= (U8x32_as_Nat rhs.bytes) % 2^255
    MontgomeryPoint.mkPoint res = m • (MontgomeryPoint.mkPoint P) ⦄
 := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint

namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulMontgomeryPointMontgomeryPoint






























@[progress]
theorem mul_spec (scalar : Scalar) (P : montgomery.MontgomeryPoint) :
    mul scalar P ⦃ res =>
    let m:= (U8x32_as_Nat scalar.bytes) % 2^255
    MontgomeryPoint.mkPoint res = m • (MontgomeryPoint.mkPoint P) ⦄
 := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulMontgomeryPointMontgomeryPoint
