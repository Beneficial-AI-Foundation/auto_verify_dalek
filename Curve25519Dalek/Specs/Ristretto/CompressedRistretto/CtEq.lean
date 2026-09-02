




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Ristretto.CompressedRistretto.AsBytes












open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.ristretto.CompressedRistretto.Insts.SubtleConstantTimeEq



















@[progress]
theorem ct_eq_spec
    (self other : CompressedRistretto) :
    ct_eq self other ⦃ (result : subtle.Choice) =>
      result = Choice.one ↔ self = other ⦄ := by
  sorry
end curve25519_dalek.ristretto.CompressedRistretto.Insts.SubtleConstantTimeEq
