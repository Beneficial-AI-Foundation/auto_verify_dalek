




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Edwards.CompressedEdwardsY.AsBytes












open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.CompressedEdwardsY.Insts.SubtleConstantTimeEq



















@[progress]
theorem ct_eq_spec
    (self other : CompressedEdwardsY) :
    ct_eq self other ⦃ (result : subtle.Choice) =>
      result = Choice.one ↔ self = other ⦄ := by
  sorry
end curve25519_dalek.edwards.CompressedEdwardsY.Insts.SubtleConstantTimeEq
