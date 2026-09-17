/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.montgomery.MontgomeryPoint

@[progress]
theorem to_bytes_spec (mp : montgomery.MontgomeryPoint) :
    montgomery.MontgomeryPoint.to_bytes mp ⦃ result =>
    result = mp ⦄ := by
  sorry

end curve25519_dalek.montgomery.MontgomeryPoint
