




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.ExternallyVerified
















open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithMulSharedAScalarEdwardsPoint




















@[progress, externally_verified]
theorem mul_spec (e : edwards.EdwardsPoint) (s : scalar.Scalar)
    (h_s_canonical : U8x32_as_Nat s.bytes < 2 ^ 255)
    (h_e_valid : e.IsValid) :
    mul e s ⦃ result =>
    result.IsValid ∧
    result.toPoint = (U8x32_as_Nat s.bytes) • e.toPoint ⦄ := by
  sorry

end curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithMulSharedAScalarEdwardsPoint

namespace curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedAEdwardsPointEdwardsPoint






















@[progress]
theorem mul_spec (s : scalar.Scalar) (e : edwards.EdwardsPoint)
    (h_s_canonical : U8x32_as_Nat s.bytes < 2 ^ 255)
    (h_e_valid : e.IsValid) :
    mul s e ⦃ result =>
    result.IsValid ∧
    result.toPoint = (U8x32_as_Nat s.bytes) • e.toPoint ⦄ := by
  sorry
end curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedAEdwardsPointEdwardsPoint

namespace curve25519_dalek.SharedAEdwardsPoint.Insts.CoreOpsArithMulScalarEdwardsPoint






















@[progress]
theorem mul_spec (e : edwards.EdwardsPoint) (s : scalar.Scalar)
    (h_s_canonical : U8x32_as_Nat s.bytes < 2 ^ 255)
    (h_e_valid : e.IsValid) :
      mul e s ⦃ result =>
      result.IsValid ∧
      result.toPoint = ((U8x32_as_Nat s.bytes)) • e.toPoint ⦄ := by
  sorry
end curve25519_dalek.SharedAEdwardsPoint.Insts.CoreOpsArithMulScalarEdwardsPoint

namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulEdwardsPointEdwardsPoint






















@[progress]
theorem mul_spec (s : scalar.Scalar) (e : edwards.EdwardsPoint)
    (h_s_canonical : U8x32_as_Nat s.bytes < 2 ^ 255)
    (h_e_valid : e.IsValid) :
    mul s e ⦃ result =>
      result.IsValid ∧
      result.toPoint = ((U8x32_as_Nat s.bytes)) • e.toPoint ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulEdwardsPointEdwardsPoint
