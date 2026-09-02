




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytesWide
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack








open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar
















@[progress]
theorem from_bytes_mod_order_wide_spec (input : Array U8 64#usize) :
    from_bytes_mod_order_wide input ⦃ (result : Scalar) =>
      U8x32_as_Nat result.bytes ≡ U8x64_as_Nat input [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
