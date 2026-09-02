




import Curve25519Dalek.Funs













open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar


















@[progress]
theorem to_bytes_spec (s : Scalar) :
    to_bytes s ⦃ a =>
    a = s.bytes ∧ mk a = s ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
