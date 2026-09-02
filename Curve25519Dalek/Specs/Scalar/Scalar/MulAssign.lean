




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack
























open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignSharedAScalar































@[progress]
theorem mul_assign_spec (self _rhs : Scalar) :
    mul_assign self _rhs ⦃ (result : Scalar) =>
      U8x32_as_Nat result.bytes ≡ U8x32_as_Nat self.bytes * U8x32_as_Nat _rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignSharedAScalar







namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignScalar
















@[progress]
theorem mul_assign_spec (self rhs : Scalar) :
    mul_assign self rhs ⦃ (result : Scalar) =>
      U8x32_as_Nat result.bytes ≡ U8x32_as_Nat self.bytes * U8x32_as_Nat rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignScalar
