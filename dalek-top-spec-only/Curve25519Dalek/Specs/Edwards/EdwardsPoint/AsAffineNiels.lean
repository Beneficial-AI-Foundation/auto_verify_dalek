/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Data.Nat.ModEq

open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.backend.serial.u64.field.FieldElement51
  curve25519_dalek.backend.serial.u64.constants
open curve25519_dalek.backend.serial.curve_models.AffineNielsPoint
open curve25519_dalek.montgomery
namespace curve25519_dalek.edwards.EdwardsPoint

@[progress]
theorem as_affine_niels_spec
  (self : EdwardsPoint)
  (hself : self.IsValid) :
  as_affine_niels self ⦃ an =>
  let X := Field51_as_Nat self.X
  let Y := Field51_as_Nat self.Y
  let Z := Field51_as_Nat self.Z
  let ypx := Field51_as_Nat an.y_plus_x
  let ymx := Field51_as_Nat an.y_minus_x
  let xy2d_val := Field51_as_Nat an.xy2d
  (ypx * Z) % p = (Y + X) % p ∧
  (ymx * Z + X) % p = Y % p ∧
  (xy2d_val * Z * Z) % p = (X * Y * (2 * d)) % p ∧
  (∀ i < 5, an.y_plus_x[i]!.val < 2 ^ 54) ∧
  (∀ i < 5, an.y_minus_x[i]!.val < 2 ^ 52) ∧
  (∀ i < 5, an.xy2d[i]!.val < 2 ^ 52) ⦄
:= by
  sorry

end curve25519_dalek.edwards.EdwardsPoint
