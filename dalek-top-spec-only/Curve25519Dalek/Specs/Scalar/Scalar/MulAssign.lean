/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MulInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Sub
import Mathlib.Algebra.Polynomial.Eval.Algebra
import Mathlib.Algebra.Polynomial.Eval.Coeff
import Mathlib.Algebra.Polynomial.Eval.Defs
import Mathlib.Algebra.Polynomial.Eval.Degree
import Mathlib.Data.Nat.ModEq
import Mathlib.Data.Int.ModEq
import Mathlib.Data.ZMod.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ToBytes

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignSharedAScalar

end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignSharedAScalar

namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignScalar

@[progress]
theorem mul_assign_spec (self rhs : Scalar) :
    mul_assign self rhs ⦃ (result : Scalar) =>
      U8x32_as_Nat result.bytes ≡ U8x32_as_Nat self.bytes * U8x32_as_Nat rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry

end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignScalar
