




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.EdwardsPoint

















@[progress]
theorem as_projective_spec (e : EdwardsPoint) :
    edwards.EdwardsPoint.as_projective e ⦃ q =>
    q.X = e.X ∧ q.Y = e.Y ∧ q.Z = e.Z ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
