




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.EDWARDS_D2
import Curve25519Dalek.Aux











open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.backend.serial.u64.field.FieldElement51
  curve25519_dalek.backend.serial.u64.constants
open curve25519_dalek.backend.serial.curve_models.ProjectiveNielsPoint
open curve25519_dalek.montgomery
namespace curve25519_dalek.edwards.EdwardsPoint































@[externally_verified, progress]
theorem as_projective_niels_spec (e : EdwardsPoint)
    (he : e.IsValid) :
    as_projective_niels e ⦃ (pn : backend.serial.curve_models.ProjectiveNielsPoint) =>
      let X := Field51_as_Nat e.X
      let Y := Field51_as_Nat e.Y
      let Z := Field51_as_Nat e.Z
      let T := Field51_as_Nat e.T
      let A := Field51_as_Nat pn.Y_plus_X
      let B := Field51_as_Nat pn.Y_minus_X
      let Z' := Field51_as_Nat pn.Z
      let C := Field51_as_Nat pn.T2d
      A % p = (Y + X) % p ∧
      (B + X) % p = Y % p ∧
      Z' % p = Z % p ∧
      C % p = (T * (2 * d)) % p ∧
      (∀ i < 5, (pn.Y_plus_X[i]!).val < 2 ^ 54 ∧
      ∀ i < 5, (pn.Y_minus_X[i]!).val < 2 ^ 52 ∧
      ∀ i < 5, (pn.Z[i]!).val < 2 ^ 53 ∧
      ∀ i < 5, (pn.T2d[i]!).val < 2 ^ 52) ∧
      pn.IsValid ∧
      e.toPoint = pn.toPoint
       ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
