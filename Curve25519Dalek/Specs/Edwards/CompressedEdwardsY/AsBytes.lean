




import Curve25519Dalek.Funs










open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek

namespace curve25519_dalek.edwards.CompressedEdwardsY







@[progress]
theorem as_bytes_spec
    (self : edwards.CompressedEdwardsY) :
    as_bytes self ⦃ result =>
    result = self ⦄ := by
  sorry
end curve25519_dalek.edwards.CompressedEdwardsY
