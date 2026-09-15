/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreCmpPartialEqFieldElement51

end curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreCmpPartialEqFieldElement51

namespace curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpPartialEqAffineNielsPoint

@[progress]
theorem eq_spec
    (self other : backend.serial.curve_models.AffineNielsPoint) :
    eq self other ⦃ b =>
    (b = true ↔
      self.y_plus_x.to_bytes = other.y_plus_x.to_bytes ∧
      self.y_minus_x.to_bytes = other.y_minus_x.to_bytes ∧
      self.xy2d.to_bytes = other.xy2d.to_bytes) ⦄ := by
  sorry

end curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpPartialEqAffineNielsPoint
