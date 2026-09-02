




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack
























open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedAScalarScalar
































@[progress]
theorem mul_spec (self _rhs : scalar.Scalar) :
    mul self _rhs ⦃ (result : scalar.Scalar) =>
      U8x32_as_Nat result.bytes ≡ U8x32_as_Nat self.bytes * U8x32_as_Nat _rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedAScalarScalar








namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulSharedBScalarScalar

















@[progress]
theorem mul_spec (self rhs : scalar.Scalar) :
    mul self rhs ⦃ result =>
      U8x32_as_Nat result.bytes ≡
        U8x32_as_Nat self.bytes * U8x32_as_Nat rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulSharedBScalarScalar








namespace curve25519_dalek.SharedAScalar.Insts.CoreOpsArithMulScalarScalar

















@[progress]
theorem mul_spec (self rhs : scalar.Scalar) :
    mul self rhs ⦃ result =>
      U8x32_as_Nat result.bytes ≡
        U8x32_as_Nat self.bytes * U8x32_as_Nat rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.SharedAScalar.Insts.CoreOpsArithMulScalarScalar








namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulScalarScalar

















@[progress]
theorem mul_spec (self rhs : scalar.Scalar) :
    mul self rhs ⦃ result =>
      U8x32_as_Nat result.bytes ≡
        U8x32_as_Nat self.bytes * U8x32_as_Nat rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulScalarScalar
