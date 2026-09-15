/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Montgomery.ProjectivePoint.DifferentialAddAndDouble

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery

namespace curve25519_dalek.Shared1MontgomeryPoint.Insts.CoreOpsArithMulShared0ScalarMontgomeryPoint

end curve25519_dalek.Shared1MontgomeryPoint.Insts.CoreOpsArithMulShared0ScalarMontgomeryPoint

namespace curve25519_dalek.Shared1Scalar.Insts.CoreOpsArithMulShared0MontgomeryPointMontgomeryPoint

end curve25519_dalek.Shared1Scalar.Insts.CoreOpsArithMulShared0MontgomeryPointMontgomeryPoint

namespace curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint

@[progress]
theorem mul_spec (P : MontgomeryPoint) (rhs : scalar.Scalar) :
    mul P rhs ⦃ res =>
    let m:= (U8x32_as_Nat rhs.bytes) % 2^255
    MontgomeryPoint.mkPoint res = m • (MontgomeryPoint.mkPoint P) ⦄
 := by
  sorry

end curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint

namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulMontgomeryPointMontgomeryPoint

end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulMontgomeryPointMontgomeryPoint
