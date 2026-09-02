




import Curve25519Dalek.Funs
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.AsProjectiveNiels
import Curve25519Dalek.Specs.Backend.Serial.CurveModels.CompletedPoint.Add
import Curve25519Dalek.Specs.Backend.Serial.CurveModels.CompletedPoint.AsExtended











open Aeneas Aeneas.Std Result Aeneas.Std.WP


namespace curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAEdwardsPointEdwardsPoint






















@[progress]
theorem add_spec
    (self other : edwards.EdwardsPoint)
    (h_self_valid : self.IsValid)
    (h_other_valid : other.IsValid) :
    add self other ⦃ (result : edwards.EdwardsPoint) =>
      result.IsValid ∧
      result.toPoint = self.toPoint + other.toPoint ⦄ := by
  sorry
end curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAEdwardsPointEdwardsPoint



namespace curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithAddEdwardsPointEdwardsPoint




















@[progress]
theorem add_spec (self other : EdwardsPoint) (h_self_valid : self.IsValid) (h_other_valid : other.IsValid) :
    add self other ⦃ result =>
    result.IsValid ∧
    result.toPoint = self.toPoint + other.toPoint ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithAddEdwardsPointEdwardsPoint
