




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.SquareInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce

import Mathlib.Algebra.Polynomial.Eval.Algebra
import Mathlib.Algebra.Polynomial.Eval.Coeff
import Mathlib.Algebra.Polynomial.Eval.Defs
import Mathlib.Algebra.Polynomial.Eval.Degree











open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52





















@[progress]
theorem montgomery_square_spec (m : Scalar52) (hm : ∀ i < 5, m[i]!.val < 2 ^ 62) :
    montgomery_square m ⦃ w =>
    (Scalar52_as_Nat m * Scalar52_as_Nat m) % L = (Scalar52_as_Nat w * R) % L ∧
    (∀ i < 5, w[i]!.val < 2 ^ 62) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
