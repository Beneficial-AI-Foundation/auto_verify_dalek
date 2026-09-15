/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.SquareInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MulInternal
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Sub
import Mathlib.Algebra.Polynomial.Eval.Algebra
import Mathlib.Algebra.Polynomial.Eval.Coeff
import Mathlib.Algebra.Polynomial.Eval.Defs
import Mathlib.Algebra.Polynomial.Eval.Degree
import Mathlib.Data.Nat.ModEq
import Mathlib.Data.Int.ModEq
import Mathlib.Data.ZMod.Basic

open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

set_option exponentiation.threshold 262

@[progress]
theorem square_spec (self : Scalar52)
    (hself : ∀ i < 5, self[i]!.val < 2 ^ 62) :
    square self ⦃ ( result : Scalar52 ) =>
      Scalar52_as_Nat result ≡ Scalar52_as_Nat self * Scalar52_as_Nat self [MOD L] ∧
      ∀ i < 5, result[i]!.val < 2 ^ 52 ⦄ := by
  sorry

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
