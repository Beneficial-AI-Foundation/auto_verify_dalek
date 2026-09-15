/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Mathlib.Data.Nat.ModEq

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field
namespace curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint

@[progress]
theorem eq_spec (self other : AffinePoint) (h_self_valid : self.IsValid) (h_other_valid : other.IsValid) :
    eq self other ⦃ result =>
    result = true ↔ self.toPoint = other.toPoint ⦄ := by
  sorry

end curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint
