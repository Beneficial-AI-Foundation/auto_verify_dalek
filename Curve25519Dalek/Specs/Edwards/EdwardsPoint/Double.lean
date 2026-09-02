




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.ExternallyVerified













open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.EdwardsPoint




















@[externally_verified, progress]
theorem double_spec (e : EdwardsPoint) (he_valid : e.IsValid) :
    double e ⦃ result =>
    result.IsValid ∧ result.toPoint = e.toPoint + e.toPoint ⦄ := by
    sorry

end curve25519_dalek.edwards.EdwardsPoint
