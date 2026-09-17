/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Data.Nat.ModEq
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.SQRT_M1
import Curve25519Dalek.Specs.Field.FieldElement51.IsZero

open Aeneas Aeneas.Std Result Edwards Aeneas.Std.WP
open curve25519_dalek.ristretto
namespace curve25519_dalek.ristretto.CompressedRistretto

@[progress]
theorem decompress_spec (comp : CompressedRistretto) :
    decompress comp ⦃ result =>
    (¬comp.IsValid → result = none) ∧
    (comp.IsValid →
        ∃ rist,
        result = some rist ∧
        RistrettoPoint.IsValid rist ∧
        decompress_pure comp = some rist.toPoint) ⦄ := by
  sorry

end curve25519_dalek.ristretto.CompressedRistretto
