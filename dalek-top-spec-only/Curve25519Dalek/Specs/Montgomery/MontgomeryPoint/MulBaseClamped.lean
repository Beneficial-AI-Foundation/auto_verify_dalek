/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Edwards.Basepoint
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Data.Nat.ModEq
import Curve25519Dalek.Tactics
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Scalar.ClampInteger

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64
open Montgomery
namespace curve25519_dalek.montgomery.MontgomeryPoint

@[progress]
theorem mul_base_clamped_spec (bytes : Array U8 32#usize) :
    mul_base_clamped bytes ⦃ result =>
    (∃ clamped_scalar_nat,
    h ∣ clamped_scalar_nat ∧
    clamped_scalar_nat < 2 ^ 255 ∧
    2 ^ 254 ≤ clamped_scalar_nat ∧
     MontgomeryPoint.mkPoint result = clamped_scalar_nat • (fromEdwards _root_.Edwards.basepoint)) ⦄    := by
  sorry

end curve25519_dalek.montgomery.MontgomeryPoint
