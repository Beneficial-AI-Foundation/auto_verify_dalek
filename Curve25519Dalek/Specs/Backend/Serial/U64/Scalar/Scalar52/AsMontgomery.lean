




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryMul
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.RR

set_option exponentiation.threshold 260










open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52












theorem RR_lt : ∀ i < 5, constants.RR[i]!.val < 2 ^ 62 := by
  sorry




@[progress]
theorem as_montgomery_spec (u : Scalar52) (h : ∀ i < 5, u[i]!.val < 2 ^ 62) :
    as_montgomery u ⦃ m =>
    Scalar52_as_Nat m ≡ (Scalar52_as_Nat u * R) [MOD L] ∧
    (∀ i < 5, m[i]!.val < 2 ^ 62) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
