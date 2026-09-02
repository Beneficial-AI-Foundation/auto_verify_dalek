




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.ExternallyVerified














open Aeneas.Std Result
namespace curve25519_dalek.edwards.EdwardsPoint

















@[externally_verified]
theorem mul_by_pow_2_spec (self : EdwardsPoint) (k : U32) (hself : self.IsValid) (hk : k.val > 0) :
    ∃ result : EdwardsPoint, mul_by_pow_2 self k = ok result ∧
    result.IsValid ∧
    result.toPoint = (2 ^ k.val) • self.toPoint := by
  sorry

end curve25519_dalek.edwards.EdwardsPoint
