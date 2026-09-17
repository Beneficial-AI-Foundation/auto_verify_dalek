/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Data.Nat.ModEq
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Montgomery.MontgomeryPoint.ElligatorEncode
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi

open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek
open backend.serial.u64.field.FieldElement51
open Montgomery
open backend.serial.u64.constants
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.montgomery
open curve25519_dalek.field.FieldElement51

namespace curve25519_dalek.montgomery

@[mk_iff]
structure ProjectivePoint.IsValid (P : montgomery.ProjectivePoint) : Prop where

  U_bounds : ∀ i < 5, P.U[i]!.val < 2 ^ 53
  W_bounds : ∀ i < 5, P.W[i]!.val < 2 ^ 53

  W_ne_zero : P.W.toField ≠ 0

  on_curve :
    let U := P.U.toField; let W := P.W.toField; let u := U/W
    IsSquare (u ^ 3 + Curve25519.A * u ^ 2 + u)

def valid_ladder_state
    (P Q : montgomery.ProjectivePoint)
    (affine_PmQ : backend.serial.u64.field.FieldElement51) : Prop :=
  ∃ (P_affine Q_affine : backend.serial.u64.field.FieldElement51),
    P_affine.toField ≠ 0 ∧ Q_affine.toField ≠ 0 ∧
    P_affine.toField ≠ Q_affine.toField ∧
    P_affine.toField = P.U.toField / P.W.toField ∧
    Q_affine.toField = Q.U.toField / Q.W.toField ∧
    (∀ i < 5, affine_PmQ[i]!.val < 2 ^ 52) ∧
    affine_PmQ.toField ≠ 0 ∧
    (∀ (P_affine Q_affine : Point),
    get_u P_affine = P.U.toField / P.W.toField ∧
    get_u Q_affine = Q.U.toField / Q.W.toField →
    get_u (P_affine - Q_affine) = affine_PmQ.toField)

end curve25519_dalek.montgomery
