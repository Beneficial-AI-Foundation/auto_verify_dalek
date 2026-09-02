




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MulInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce











open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

set_option exponentiation.threshold 262
























@[progress]
theorem montgomery_mul_spec (m m' : Scalar52)
    (hm : ∀ i < 5, m[i]!.val < 2 ^ 62) (hm' : ∀ i < 5, m'[i]!.val < 2 ^ 62) :
    montgomery_mul m m' ⦃ w =>
    (Scalar52_as_Nat m * Scalar52_as_Nat m') ≡ (Scalar52_as_Nat w * R) [MOD L] ∧
    (∀ i < 5, w[i]!.val < 2 ^ 62) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
