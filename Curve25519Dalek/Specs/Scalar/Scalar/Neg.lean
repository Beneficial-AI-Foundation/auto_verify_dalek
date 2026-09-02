




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MulInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Zero
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.R

set_option exponentiation.threshold 260





























open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithNegScalar































private lemma R_limb_bounds : ∀ i < 5, backend.serial.u64.constants.R[i]!.val < 2 ^ 62 := by
  unfold backend.serial.u64.constants.R; decide

private lemma ZERO_limb_bounds :
    ∀ i < 5, backend.serial.u64.scalar.Scalar52.ZERO[i]!.val < 2 ^ 52 := by
  unfold backend.serial.u64.scalar.Scalar52.ZERO; decide









@[progress]
theorem neg_spec (self : scalar.Scalar)
    (h_self : U8x32_as_Nat self.bytes < L) :
    neg self ⦃ result =>
      U8x32_as_Nat result.bytes + U8x32_as_Nat self.bytes ≡ 0 [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithNegScalar







namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithNegScalar
















@[progress]
theorem neg_spec (self : scalar.Scalar)
    (h_self : U8x32_as_Nat self.bytes < L) :
    neg self ⦃ result =>
      U8x32_as_Nat result.bytes + U8x32_as_Nat self.bytes ≡ 0 [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithNegScalar
