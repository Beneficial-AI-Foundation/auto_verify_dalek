




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Neg




















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.Shared0ProjectiveNielsPoint.Insts.CoreOpsArithNegProjectiveNielsPoint
open curve25519_dalek.backend.serial.curve_models

namespace curve25519_dalek.Shared0ProjectiveNielsPoint.Insts.CoreOpsArithNegProjectiveNielsPoint


































theorem neg_spec (self : ProjectiveNielsPoint) (self_bound : ∀ i < 5, self.T2d[i]!.val < 2 ^ 54) :
    neg self ⦃ (result : ProjectiveNielsPoint) =>
      result.Y_plus_X = self.Y_minus_X ∧
      result.Y_minus_X = self.Y_plus_X ∧
      result.Z = self.Z ∧
      (Field51_as_Nat self.T2d + Field51_as_Nat result.T2d) % p = 0 ⦄ := by
  sorry
end curve25519_dalek.Shared0ProjectiveNielsPoint.Insts.CoreOpsArithNegProjectiveNielsPoint
