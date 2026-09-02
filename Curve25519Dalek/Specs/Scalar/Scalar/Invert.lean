




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.TypesAux
import Curve25519Dalek.Specs.Scalar.Scalar.Unpack
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Invert
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack










open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.scalar.Scalar


















@[progress]
theorem invert_spec (self : Scalar) (h : U8x32_as_Nat self.bytes % L ≠ 0) :
    invert self ⦃ (result : Scalar) =>
      U8x32_as_Nat self.bytes * U8x32_as_Nat result.bytes ≡ 1 [MOD L] ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
