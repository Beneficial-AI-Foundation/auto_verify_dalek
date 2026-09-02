




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.Mul
















open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.ristretto
namespace curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithMulSharedAScalarRistrettoPoint





















@[progress]
theorem mul_spec (self : RistrettoPoint) (scalar : scalar.Scalar)
    (hscalar : U8x32_as_Nat scalar.bytes < 2 ^ 255) (hself : self.IsValid) :
    mul self scalar ⦃ (result : RistrettoPoint) =>
      result.IsValid ∧
      result.toPoint = (U8x32_as_Nat scalar.bytes) • self.toPoint ⦄ := by
  sorry































end curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithMulSharedAScalarRistrettoPoint

namespace curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedARistrettoPointRistrettoPoint





















@[progress]
theorem mul_spec (self : scalar.Scalar) (point : RistrettoPoint)
    (hself : U8x32_as_Nat self.bytes < 2 ^ 255) (hpoint : point.IsValid) :
    mul self point ⦃ (result : RistrettoPoint) =>
      result.IsValid ∧ result.toPoint = (U8x32_as_Nat self.bytes) • point.toPoint ⦄ := by
  sorry
end curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedARistrettoPointRistrettoPoint
