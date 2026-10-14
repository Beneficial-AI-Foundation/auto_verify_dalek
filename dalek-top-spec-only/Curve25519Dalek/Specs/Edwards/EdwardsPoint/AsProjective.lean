import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.edwards.EdwardsPoint

/-- `as_projective` simply drops the `T` coordinate: the projective point has the same
`X`, `Y`, `Z` limbs (hence the same `Field51_as_Nat` values and limb bounds). -/
@[progress]
theorem as_projective_spec (e : EdwardsPoint) :
    as_projective e ⦃ q =>
      q.X = e.X ∧ q.Y = e.Y ∧ q.Z = e.Z ∧
      Field51_as_Nat q.X = Field51_as_Nat e.X ∧
      Field51_as_Nat q.Y = Field51_as_Nat e.Y ∧
      Field51_as_Nat q.Z = Field51_as_Nat e.Z ⦄ := by
  unfold as_projective
  simp

end curve25519_dalek.edwards.EdwardsPoint
