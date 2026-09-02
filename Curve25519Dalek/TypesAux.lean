




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux








open Aeneas.Std Result
namespace curve25519_dalek.scalar.Scalar


theorem Scalar_ext (a b : Scalar) : a.bytes = b.bytes → a = b := by
  sorry

lemma U8x32_as_Nat_eq_zero_iff_ZERO (s : Scalar) : U8x32_as_Nat s.bytes = 0 ↔ s = ZERO := by
  sorry
end curve25519_dalek.scalar.Scalar
