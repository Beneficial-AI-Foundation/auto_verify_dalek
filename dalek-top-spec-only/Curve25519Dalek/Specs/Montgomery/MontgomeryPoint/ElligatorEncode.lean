/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.FunsExternal
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Tactic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.backend.serial.u64.constants
open curve25519_dalek.field.FieldElement51
namespace curve25519_dalek.montgomery

@[progress]
theorem elligator_encode_spec
    (r_0 : backend.serial.u64.field.FieldElement51)
    (h_bounds : ∀ i, i < 5 → (r_0[i]!).val ≤ 2 ^ 52 - 1) :
    elligator_encode r_0 ⦃ res =>

    let r     : ZMod p := (Field51_as_Nat r_0 : ZMod p)
    let d_1   : ZMod p := 1 + 2 * r ^ 2
    let d     : ZMod p := -Curve25519.A * d_1⁻¹
    let eps   : ZMod p := d * (d ^ 2 + Curve25519.A * d + 1)
    let point  := res.1
    let eps_is_sq := res.2

    (eps_is_sq.val = 1#u8 ↔ IsSquare eps) ∧

    (eps_is_sq.val = 1#u8 →
      (U8x32_as_Nat point : ZMod p) = d) ∧
    (eps_is_sq.val = 0#u8 →
      (U8x32_as_Nat point : ZMod p) = -d - Curve25519.A) ∧

    (eps_is_sq.val = 1#u8 →
      let u : ZMod p := (U8x32_as_Nat point : ZMod p)
      u * (u ^ 2 + Curve25519.A * u + 1) = eps) ∧

    (eps_is_sq.val = 0#u8 →
      let u : ZMod p := (U8x32_as_Nat point : ZMod p)
      IsSquare (-(u * (u ^ 2 + Curve25519.A * u + 1)))) ⦄ := by
  sorry

end curve25519_dalek.montgomery
