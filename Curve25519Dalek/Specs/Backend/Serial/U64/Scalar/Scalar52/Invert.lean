




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.AsMontgomery
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryInvert
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryMul
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromMontgomery
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Zero
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.RR

set_option exponentiation.threshold 260








open Aeneas Aeneas.Std Aeneas.Std.WP Result curve25519_dalek.backend.serial.u64.scalar
  curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.scalar.Scalar52






















@[progress]
theorem invert_spec (self : Scalar52) (h : Scalar52_as_Nat self % L ≠ 0)
    (hu : ∀ i < 5, self[i]!.val < 2 ^ 62) :
    invert self ⦃ (result : Scalar52) =>
      (Scalar52_as_Nat self * Scalar52_as_Nat result) ≡ 1 [MOD L] ∧
      (∀ i < 5, result[i]!.val < 2 ^ 52) ∧ Scalar52_as_Nat result < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar52
