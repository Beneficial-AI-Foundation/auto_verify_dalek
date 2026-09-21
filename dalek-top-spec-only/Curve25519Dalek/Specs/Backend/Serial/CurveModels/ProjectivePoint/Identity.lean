/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ZERO

open Aeneas.Std Result Aeneas.Std.WP curve25519_dalek
open backend.serial.u64.field.FieldElement51
open backend.serial.curve_models
namespace curve25519_dalek.IdentityCurveModelsProjectivePoint

@[progress]
theorem identity_spec :
    spec identity (fun (q : ProjectivePoint) =>
      Field51_as_Nat q.X = 0 ∧
      Field51_as_Nat q.Y = 1 ∧
      Field51_as_Nat q.Z = 1) := by
  unfold identity
  apply spec_bind ZERO_spec
  intro fe hfe
  apply spec_bind ONE_spec
  intro fe1 hfe1
  simp [spec_ok, hfe, hfe1]

end curve25519_dalek.IdentityCurveModelsProjectivePoint
