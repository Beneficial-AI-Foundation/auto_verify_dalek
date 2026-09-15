/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Curve

import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Tactic
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.SQRT_M1
import Curve25519Dalek.Specs.Field.FieldElement51.IsZero

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.math
namespace curve25519_dalek.field.FieldElement51

def SQRT_M1_val := backend.serial.u64.constants.SQRT_M1_raw

private abbrev sqrt_ratio_i_cases
    (u v r2 : backend.serial.u64.field.FieldElement51)
    (c : subtle.Choice) : Prop :=
  (Field51_as_Nat u % p = 0 →
      c.val = 1#u8 ∧ Field51_as_Nat r2 % p = 0 ∧
        (∀ i < 5, r2[i]!.val ≤ 2 ^ 53 - 1)) ∧
    (Field51_as_Nat u % p ≠ 0 ∧ Field51_as_Nat v % p = 0 →
      c.val = 0#u8 ∧ Field51_as_Nat r2 % p = 0 ∧
        (∀ i < 5, r2[i]!.val ≤ 2 ^ 53 - 1)) ∧
    (Field51_as_Nat u % p ≠ 0 ∧ Field51_as_Nat v % p ≠ 0 ∧
        (∃ x : Nat, (x ^ 2 * (Field51_as_Nat v % p)) % p = Field51_as_Nat u % p) →
      c.val = 1#u8 ∧
        ((Field51_as_Nat r2 % p) ^ 2 * (Field51_as_Nat v % p)) % p =
          Field51_as_Nat u % p ∧
        (∀ i < 5, r2[i]!.val ≤ 2 ^ 53 - 1)) ∧
    ((Field51_as_Nat u % p ≠ 0 ∧ Field51_as_Nat v % p ≠ 0 ∧
        ¬∃ x : Nat, (x ^ 2 * (Field51_as_Nat v % p)) % p = Field51_as_Nat u % p) →
      c.val = 0#u8 ∧
        ((Field51_as_Nat r2 % p) ^ 2 * (Field51_as_Nat v % p)) % p =
          ((Field51_as_Nat SQRT_M1_val % p) * (Field51_as_Nat u % p)) % p ∧
        (∀ i < 5, r2[i]!.val ≤ 2 ^ 53 - 1)) ∧
    (Field51_as_Nat r2 % p % 2 = 0)

section sqrt_ratio_i_branch_solvers

variable
  {u v fe v3 fe2 fe4 r fe5 check fe6 fe7 r_prime r1 r_neg r2 :
    backend.serial.u64.field.FieldElement51}
  {r_is_negative : subtle.Choice}

end sqrt_ratio_i_branch_solvers

end curve25519_dalek.field.FieldElement51
