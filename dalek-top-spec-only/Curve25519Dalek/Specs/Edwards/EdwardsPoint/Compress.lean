/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified

import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes

open Aeneas Aeneas.Std Result Aeneas.Std.WP

open curve25519_dalek.backend.serial.u64.field.FieldElement51

namespace curve25519_dalek.edwards.EdwardsPoint

@[externally_verified, progress]
theorem compress_spec (self : EdwardsPoint) (hX : ∀ i < 5, self.X[i]!.val < 2 ^ 54)
      (hY : ∀ i < 5, self.Y[i]!.val < 2 ^ 54) (hZ : ∀ i < 5, self.Z[i]!.val < 2 ^ 54)

      :
    compress self ⦃ result => True ⦄ := by
  sorry

end curve25519_dalek.edwards.EdwardsPoint
