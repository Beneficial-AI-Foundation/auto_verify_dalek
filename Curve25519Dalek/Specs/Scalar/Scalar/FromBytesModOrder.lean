




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Scalar.Scalar.Reduce









open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.scalar.Scalar


















@[progress]
theorem from_bytes_mod_order_spec (b : Array U8 32#usize) :
    from_bytes_mod_order b ⦃ s =>
    U8x32_as_Nat s.bytes ≡ U8x32_as_Nat b [MOD L] ∧ U8x32_as_Nat s.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
