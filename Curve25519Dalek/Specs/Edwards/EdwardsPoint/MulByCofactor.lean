




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.MulByPow2
import Curve25519Dalek.Math.Edwards.Representation











open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.EdwardsPoint

















@[progress]
theorem mul_by_cofactor_spec (self : EdwardsPoint) (hself : self.IsValid) :
    mul_by_cofactor self ⦃ result =>
    result.IsValid ∧
    result.toPoint = h • self.toPoint ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
