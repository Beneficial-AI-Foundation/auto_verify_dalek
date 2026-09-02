




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ToBytes








open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.backend.serial.u64.scalar
  curve25519_dalek.backend.serial.u64.scalar
namespace curve25519_dalek.scalar.Scalar52
















@[progress]
theorem pack_spec (self : Scalar52) (h : ∀ i < 5, self[i]!.val < 2 ^ 52)
    (h' : Scalar52_as_Nat self < L) :
    pack self ⦃ (result : Scalar) =>
      U8x32_as_Nat result.bytes ≡ Scalar52_as_Nat self [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar52
