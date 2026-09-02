




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Ristretto.CompressedRistretto.FromSlice




















open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.CompressedEdwardsY























@[progress]
theorem from_slice_spec
    (bytes : Slice U8) :
    from_slice bytes ⦃ (result : core.result.Result CompressedEdwardsY core.array.TryFromSliceError) =>
      (bytes.length = 32 → ∃ cey : CompressedEdwardsY, result = .Ok cey ∧ cey.val = bytes.val) ∧
      (bytes.length ≠ 32 → result = .Err ()) ⦄ := by
  sorry
end curve25519_dalek.edwards.CompressedEdwardsY
