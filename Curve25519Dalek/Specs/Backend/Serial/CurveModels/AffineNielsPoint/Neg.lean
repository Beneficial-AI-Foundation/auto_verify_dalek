




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Neg


















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.curve_models

namespace curve25519_dalek.Shared0AffineNielsPoint.Insts.CoreOpsArithNegAffineNielsPoint

































@[progress]
theorem neg_spec
    (self : backend.serial.curve_models.AffineNielsPoint)
    (self_bound : ∀ i < 5, self.xy2d[i]!.val < 2 ^ 54) :
    neg self ⦃ (result : AffineNielsPoint) =>
    result.y_plus_x = self.y_minus_x ∧
    result.y_minus_x = self.y_plus_x ∧
    (Field51_as_Nat self.xy2d + Field51_as_Nat result.xy2d) % p = 0 ⦄ := by
  sorry
end curve25519_dalek.Shared0AffineNielsPoint.Insts.CoreOpsArithNegAffineNielsPoint
