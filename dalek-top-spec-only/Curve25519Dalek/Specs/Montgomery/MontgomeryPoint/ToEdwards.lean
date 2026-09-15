/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Data.Nat.ModEq
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Math.Montgomery.Representation

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.montgomery.MontgomeryPoint
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.backend.serial.u64.field.FieldElement51

@[progress]
theorem to_edwards_spec (mp : MontgomeryPoint) (sign : U8) :
      to_edwards mp sign ⦃ result =>
        (∀ ep, result = some ep →
          ∃ Z_inv,
            field.FieldElement51.invert ep.Z = ok Z_inv ∧
            let u := U8x32_as_Nat mp % 2^255
            let y := Field51_as_Nat ep.Y * Field51_as_Nat Z_inv % p
            (y * ((u + 1) % p)) % p = ((u + p - 1) % p) % p ∧ ep.IsValid )
      ⦄ := by
  sorry

end curve25519_dalek.montgomery.MontgomeryPoint
