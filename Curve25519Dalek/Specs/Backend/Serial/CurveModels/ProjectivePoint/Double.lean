




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square2
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.AddAssign
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Math.Edwards.Representation
import Mathlib.Data.ZMod.Basic

set_option linter.hashCommand false
#setup_aeneas_simps












open Aeneas Aeneas.Std Result Aeneas.Std.WP

open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51

namespace curve25519_dalek.backend.serial.curve_models.ProjectivePoint




































@[progress]
theorem double_spec_aux (q : ProjectivePoint)
    (h_qX_bounds : ∀ i < 5, (q.X[i]!).val < 2 ^ 53)
    (h_qY_bounds : ∀ i < 5, (q.Y[i]!).val < 2 ^ 53)
    (h_qZ_bounds : ∀ i < 5, (q.Z[i]!).val < 2 ^ 54) :
    double q ⦃ c =>
    let X := Field51_as_Nat q.X
    let Y := Field51_as_Nat q.Y
    let Z := Field51_as_Nat q.Z
    let X' := Field51_as_Nat c.X
    let Y' := Field51_as_Nat c.Y
    let Z' := Field51_as_Nat c.Z
    let T' := Field51_as_Nat c.T
    X' % p = (2 * X * Y) % p ∧
    Y' % p = (Y^2 + X^2) % p ∧
    (Z' + X^2) % p = Y^2 % p ∧
    (T' + Z') % p = (2 * Z^2) % p ∧
    (∀ i < 5, c.X[i]!.val < 2 ^ 52) ∧
    (∀ i < 5, c.Y[i]!.val < 2 ^ 53) ∧
    (∀ i < 5, c.Z[i]!.val < 2 ^ 52) ∧
    (∀ i < 5, c.T[i]!.val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.curve_models.ProjectivePoint

namespace curve25519_dalek.backend.serial.curve_models.ProjectivePoint

open Edwards
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.backend.serial.u64.field

private lemma double_lift_to_field_eqs (c : CompletedPoint) (q : ProjectivePoint)
    (hX_arith : Field51_as_Nat c.X % p = (2 * Field51_as_Nat q.X * Field51_as_Nat q.Y) % p)
    (hY_arith : Field51_as_Nat c.Y % p = (Field51_as_Nat q.Y ^ 2 + Field51_as_Nat q.X ^ 2) % p)
    (hZ_arith : (Field51_as_Nat c.Z + Field51_as_Nat q.X ^ 2) % p = Field51_as_Nat q.Y ^ 2 % p)
    (hT_arith : (Field51_as_Nat c.T + Field51_as_Nat c.Z) % p = (2 * Field51_as_Nat q.Z ^ 2) % p) :
    c.X.toField = 2 * q.X.toField * q.Y.toField ∧
    c.Y.toField = q.Y.toField ^ 2 + q.X.toField ^ 2 ∧
    c.Z.toField = q.Y.toField ^ 2 - q.X.toField ^ 2 ∧
    c.T.toField = 2 * q.Z.toField ^ 2 - c.Z.toField := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · unfold FieldElement51.toField
    have h := lift_mod_eq _ _ hX_arith; push_cast at h; exact h
  · unfold FieldElement51.toField
    have h := lift_mod_eq _ _ hY_arith; push_cast at h; exact h
  · unfold FieldElement51.toField
    have h := lift_mod_eq _ _ hZ_arith; push_cast at h; exact eq_sub_of_add_eq h
  · unfold FieldElement51.toField at *
    have h := lift_mod_eq _ _ hT_arith; push_cast at h; exact eq_sub_of_add_eq h

attribute [local irreducible] p in





theorem double_spec
    (q : ProjectivePoint) (hq_valid : q.IsValid) :
    ∃ c, ProjectivePoint.double q = ok c ∧
    c.IsValid ∧ c.toPoint = q.toPoint + q.toPoint := by
  sorry
end curve25519_dalek.backend.serial.curve_models.ProjectivePoint
