




import Curve25519Dalek.Funs










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar


















@[progress]
theorem as_bytes_spec (s : Scalar) :
    as_bytes s ⦃ b =>
    b = s.bytes ∧ mk b = s ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
