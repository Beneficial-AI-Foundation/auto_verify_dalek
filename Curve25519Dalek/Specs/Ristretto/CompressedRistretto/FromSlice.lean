




import Curve25519Dalek.Funs















open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.ristretto.CompressedRistretto



















@[progress]
theorem core.array.TryFromArrayCopySlice.try_from_spec
    {T : Type} (N : Usize) (copyInst : core.marker.Copy T) (s : Slice T)
    (hClone : List.mapM copyInst.cloneInst.clone s.val = ok s.val) :
    core.array.TryFromArrayCopySlice.try_from N copyInst s ⦃ (result : core.result.Result (Array T N) core.array.TryFromSliceError) =>
      (s.length = N → ∃ a : Array T N, result = .Ok a ∧ a.val = s.val) ∧
      (s.length ≠ N → result = .Err ()) ⦄ := by
  sorry





@[progress]
theorem from_slice_spec
    (bytes : Slice U8) :
    from_slice bytes ⦃ (result : core.result.Result CompressedRistretto core.array.TryFromSliceError) =>
      (bytes.length = 32 → ∃ cr : CompressedRistretto, result = .Ok cr ∧ cr.val = bytes.val) ∧
      (bytes.length ≠ 32 → result = .Err ()) ⦄ := by
  sorry
end curve25519_dalek.ristretto.CompressedRistretto
