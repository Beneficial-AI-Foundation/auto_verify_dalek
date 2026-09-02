




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Neg
import Curve25519Dalek.Math.Montgomery.Curve











open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.edwards.EdwardsPoint
open curve25519_dalek.backend.serial.u64.field
namespace curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithNegEdwardsPoint




















@[progress]
theorem neg_spec
    (self : edwards.EdwardsPoint)
    (h_self_valid : self.IsValid) :
    neg self ⦃ (result : edwards.EdwardsPoint) =>
      result.IsValid ∧
      result.toPoint = -self.toPoint ⦄ := by
  sorry
end curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithNegEdwardsPoint
