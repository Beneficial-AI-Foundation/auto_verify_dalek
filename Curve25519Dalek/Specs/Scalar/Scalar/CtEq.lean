




import Curve25519Dalek.Funs










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar.Insts.SubtleConstantTimeEq


















@[progress]
theorem ct_eq_spec (self other : scalar.Scalar) :
    ct_eq self other ⦃ (c : subtle.Choice) =>
      c = Choice.one ↔ self.bytes = other.bytes ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.SubtleConstantTimeEq
