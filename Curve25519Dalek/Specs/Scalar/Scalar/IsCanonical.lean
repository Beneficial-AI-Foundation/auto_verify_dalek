




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Scalar.Scalar.Reduce
import Curve25519Dalek.Specs.Scalar.Scalar.CtEq










open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.scalar.Scalar

















@[progress]
theorem is_canonical_spec (s : Scalar) :
    is_canonical s ⦃ (c : subtle.Choice) =>
      (c = Choice.one ↔ U8x32_as_Nat s.bytes < L) ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
