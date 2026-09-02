




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified















open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.affine.AffinePoint






















@[externally_verified, progress]
theorem compress_spec (self : AffinePoint)
    (h : Field51_as_Nat self.y < 2 ^ 255) :
    compress self ⦃ result =>
    True
     ⦄ := by
  sorry
end curve25519_dalek.edwards.affine.AffinePoint
