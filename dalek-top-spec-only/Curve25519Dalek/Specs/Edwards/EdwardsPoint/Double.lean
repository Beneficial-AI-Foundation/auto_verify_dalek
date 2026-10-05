/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.ExternallyVerified

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.EdwardsPoint

/-- As upstream, validity includes the curve equation, `Z ≠ 0`, `XY = TZ`,
and coordinate limbs below `2^53`, for both the input and the output. -/
@[externally_verified, progress]
theorem double_spec (e : EdwardsPoint) (he_valid : e.IsValid) :
    double e ⦃ result =>
    result.IsValid ∧ result.toPoint = e.toPoint + e.toPoint ⦄ := by
  sorry

end curve25519_dalek.edwards.EdwardsPoint
