/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Montgomery.MontgomeryPoint.Mul
import Curve25519Dalek.Specs.Scalar.ClampInteger

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery
namespace curve25519_dalek.montgomery.MontgomeryPoint

@[progress]
theorem mul_clamped_spec (P : MontgomeryPoint) (bytes : Array U8 32#usize) :
    mul_clamped P bytes ⦃ res =>
      (∃ clamped_scalar,
      h ∣ U8x32_as_Nat clamped_scalar ∧
      U8x32_as_Nat clamped_scalar < 2 ^ 255 ∧
      2 ^ 254 ≤ U8x32_as_Nat clamped_scalar ∧
      let m:= (U8x32_as_Nat clamped_scalar)
      MontgomeryPoint.mkPoint res = m • (MontgomeryPoint.mkPoint P)) ⦄ := by
  sorry

end curve25519_dalek.montgomery.MontgomeryPoint
