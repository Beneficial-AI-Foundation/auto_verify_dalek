




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Montgomery.MontgomeryPoint.Mul
















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery
namespace curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulAssignShared0Scalar






















@[progress]
theorem mul_assign_spec (P : MontgomeryPoint) (scalar : scalar.Scalar) :
    mul_assign P scalar ⦃ res =>
    let m:= (U8x32_as_Nat scalar.bytes) % 2^255
    MontgomeryPoint.mkPoint res = m • (MontgomeryPoint.mkPoint P) ⦄
     := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulAssignShared0Scalar
