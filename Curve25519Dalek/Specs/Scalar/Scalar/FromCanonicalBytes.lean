




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Scalar.Scalar.IsCanonical









theorem curve25519_dalek.subtle.Choice.ne_zero_iff_eq_one (a : subtle.Choice)
    (h : a ≠ Choice.zero) : a = Choice.one := by
  sorry
open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.scalar.Scalar
























@[progress]
theorem from_canonical_bytes_spec (b : Array U8 32#usize) :
    from_canonical_bytes b ⦃ s =>
    (U8x32_as_Nat b < L → s.is_some = Choice.one ∧ s.value.bytes = b) ∧
    (L ≤ U8x32_as_Nat b → s.is_some = Choice.zero) ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
