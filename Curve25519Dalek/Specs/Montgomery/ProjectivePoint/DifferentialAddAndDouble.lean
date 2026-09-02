




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square
import Curve25519Dalek.Specs.Montgomery.MontgomeryPoint.ElligatorEncode
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.APLUS2_OVER_FOUR












open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek
open backend.serial.u64.field.FieldElement51
open Montgomery
open backend.serial.u64.constants
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.montgomery
open curve25519_dalek.field.FieldElement51

namespace curve25519_dalek.montgomery



@[mk_iff]
structure ProjectivePoint.IsValid (P : montgomery.ProjectivePoint) : Prop where

  U_bounds : ∀ i < 5, P.U[i]!.val < 2 ^ 53
  W_bounds : ∀ i < 5, P.W[i]!.val < 2 ^ 53

  W_ne_zero : P.W.toField ≠ 0

  on_curve :
    let U := P.U.toField; let W := P.W.toField; let u := U/W
    IsSquare (u ^ 3 + Curve25519.A * u ^ 2 + u)

lemma not_eq_T_point (P : montgomery.ProjectivePoint)
    (P_affine : backend.serial.u64.field.FieldElement51)
    (hP_valid : P.IsValid)
    (P_a : P_affine.toField = P.U.toField / P.W.toField)
    (non_eq_T : P_affine.toField ≠ 0) :
    P.U.toField ≠  0 := by
  sorry









def valid_ladder_state
    (P Q : montgomery.ProjectivePoint)
    (affine_PmQ : backend.serial.u64.field.FieldElement51) : Prop :=
  ∃ (P_affine Q_affine : backend.serial.u64.field.FieldElement51),
    P_affine.toField ≠ 0 ∧ Q_affine.toField ≠ 0 ∧
    P_affine.toField ≠ Q_affine.toField ∧
    P_affine.toField = P.U.toField / P.W.toField ∧
    Q_affine.toField = Q.U.toField / Q.W.toField ∧
    (∀ i < 5, affine_PmQ[i]!.val < 2 ^ 52) ∧
    affine_PmQ.toField ≠ 0 ∧
    (∀ (P_affine Q_affine : Point),
    get_u P_affine = P.U.toField / P.W.toField ∧
    get_u Q_affine = Q.U.toField / Q.W.toField →
    get_u (P_affine - Q_affine) = affine_PmQ.toField)


































set_option maxHeartbeats 10000000 in

@[progress]
theorem differential_add_and_double_spec
    (P Q : montgomery.ProjectivePoint)
    (affine_PmQ : backend.serial.u64.field.FieldElement51)
    (hP_valid : P.IsValid)
    (hQ_valid : Q.IsValid)
    (h_ladder_state : valid_ladder_state P Q affine_PmQ) :
    differential_add_and_double P Q affine_PmQ ⦃ res =>
      res.1.IsValid ∧ res.2.IsValid ∧
      (∀  (P_affine Q_affine : Montgomery.Point),
        (Montgomery.get_u P_affine = Field51_as_Nat P.U / Field51_as_Nat P.W ∧
         Montgomery.get_u Q_affine = Field51_as_Nat Q.U / Field51_as_Nat Q.W ∧
         Montgomery.get_u (P_affine - Q_affine) = Field51_as_Nat affine_PmQ) →
        (Field51_as_Nat res.1.U / Field51_as_Nat res.1.W = Montgomery.get_u (2 • P_affine)) ∧
        (Field51_as_Nat res.2.U / Field51_as_Nat res.2.W = Montgomery.get_u (P_affine + Q_affine))) ∧
      (∃  (P_affine Q_affine : Montgomery.Point),
        (Montgomery.get_u P_affine = Field51_as_Nat P.U / Field51_as_Nat P.W ∧
         Montgomery.get_u Q_affine = Field51_as_Nat Q.U / Field51_as_Nat Q.W ∧
         Montgomery.get_u (P_affine - Q_affine) = Field51_as_Nat affine_PmQ) )
      ⦄ := by
  sorry
end curve25519_dalek.montgomery
