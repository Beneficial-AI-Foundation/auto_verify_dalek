




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack























open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithSubSharedAScalarScalar
































@[progress]
theorem sub_spec (self rhs : scalar.Scalar)
    (h_self : U8x32_as_Nat self.bytes < L)
    (h_rhs : U8x32_as_Nat rhs.bytes < L) :
    sub self rhs ⦃ result =>
      U8x32_as_Nat result.bytes + U8x32_as_Nat rhs.bytes ≡
        U8x32_as_Nat self.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithSubSharedAScalarScalar







namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithSubSharedBScalarScalar

















@[progress]
theorem sub_spec (self rhs : scalar.Scalar)
    (h_self : U8x32_as_Nat self.bytes < L)
    (h_rhs : U8x32_as_Nat rhs.bytes < L) :
    sub self rhs ⦃ result =>
      U8x32_as_Nat result.bytes + U8x32_as_Nat rhs.bytes ≡
        U8x32_as_Nat self.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithSubSharedBScalarScalar
