/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Tactics
import Curve25519Dalek.Specs.Field.FieldElement51.IsZero
import Mathlib.Data.Nat.ModEq

open Aeneas Aeneas.Std Result Aeneas.Std.WP Edwards
open curve25519_dalek.backend.serial.u64.field.FieldElement51
namespace curve25519_dalek.edwards.EdwardsPoint

@[progress, externally_verified]
theorem is_torsion_free_spec (self : EdwardsPoint) (hself : self.IsValid) :
    is_torsion_free self ⦃ result =>
    (result ↔ L • self.toPoint = 0) ⦄ := by
  sorry

end curve25519_dalek.edwards.EdwardsPoint
