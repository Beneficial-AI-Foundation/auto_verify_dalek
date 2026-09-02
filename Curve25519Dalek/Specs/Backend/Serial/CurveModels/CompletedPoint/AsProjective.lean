




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Math.Edwards.Representation














open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.curve_models.CompletedPoint





















@[progress]
theorem as_projective_spec_aux (q : CompletedPoint)
  (h_qX_bounds : ∀ i, i < 5 → (q.X[i]!).val < 2 ^ 54)
  (h_qY_bounds : ∀ i, i < 5 → (q.Y[i]!).val < 2 ^ 54)
  (h_qZ_bounds : ∀ i, i < 5 → (q.Z[i]!).val < 2 ^ 54)
  (h_qT_bounds : ∀ i, i < 5 → (q.T[i]!).val < 2 ^ 54) :
as_projective q ⦃ proj =>
let X := Field51_as_Nat q.X
let Y := Field51_as_Nat q.Y
let Z := Field51_as_Nat q.Z
let T := Field51_as_Nat q.T
let X' := Field51_as_Nat proj.X
let Y' := Field51_as_Nat proj.Y
let Z' := Field51_as_Nat proj.Z
X' % p = (X * T) % p ∧
Y' % p = (Y * Z) % p ∧
Z' % p = (Z * T) % p ∧

(∀ i < 5, proj.X[i]!.val < 2 ^ 52) ∧
(∀ i < 5, proj.Y[i]!.val < 2 ^ 52) ∧
(∀ i < 5, proj.Z[i]!.val < 2 ^ 52) ⦄
:= by
  sorry
end curve25519_dalek.backend.serial.curve_models.CompletedPoint






namespace curve25519_dalek.backend.serial.curve_models.CompletedPoint

open Edwards
open curve25519_dalek.backend.serial.u64.field.FieldElement51












private lemma as_projective_lift_to_field_eqs
    (proj : ProjectivePoint)
    (q : CompletedPoint)
    (hX_arith : Field51_as_Nat proj.X % p = (Field51_as_Nat q.X * Field51_as_Nat q.T) % p)
    (hY_arith : Field51_as_Nat proj.Y % p = (Field51_as_Nat q.Y * Field51_as_Nat q.Z) % p)
    (hZ_arith : Field51_as_Nat proj.Z % p = (Field51_as_Nat q.Z * Field51_as_Nat q.T) % p) :
    proj.X.toField = q.X.toField * q.T.toField ∧
    proj.Y.toField = q.Y.toField * q.Z.toField ∧
    proj.Z.toField = q.Z.toField * q.T.toField := by
  constructor
  · unfold toField
    have h := lift_mod_eq _ _ hX_arith
    push_cast at h
    exact h
  constructor
  · unfold toField
    have h := lift_mod_eq _ _ hY_arith
    push_cast at h
    exact h
  · unfold toField
    have h := lift_mod_eq _ _ hZ_arith
    push_cast at h
    exact h







private lemma as_projective_on_curve
    (pX pY pZ qX qY qZ qT : Edwards.CurveField)
    (hX_F : pX = qX * qT)
    (hY_F : pY = qY * qZ)
    (hZ_F : pZ = qZ * qT)
    (h_curve : Ed25519.a * qX ^ 2 * qT ^ 2 + qY ^ 2 * qZ ^ 2 =
               qZ ^ 2 * qT ^ 2 + Ed25519.d * qX ^ 2 * qY ^ 2) :
    Ed25519.a * pX ^ 2 * pZ ^ 2 + pY ^ 2 * pZ ^ 2 =
    pZ ^ 4 + Ed25519.d * pX ^ 2 * pY ^ 2 := by
  simp only [hX_F, hY_F, hZ_F]
  simp only [Ed25519] at h_curve ⊢
  linear_combination (qZ ^ 2 * qT ^ 2) * h_curve





private lemma as_projective_isValid_and_toPoint
    (proj : ProjectivePoint)
    (q : CompletedPoint) (hq_valid : q.IsValid)
    (hX_F : proj.X.toField = q.X.toField * q.T.toField)
    (hY_F : proj.Y.toField = q.Y.toField * q.Z.toField)
    (hZ_F : proj.Z.toField = q.Z.toField * q.T.toField)
    (hpX_bounds : ∀ i < 5, proj.X[i]!.val < 2 ^ 52)
    (hpY_bounds : ∀ i < 5, proj.Y[i]!.val < 2 ^ 52)
    (hpZ_bounds : ∀ i < 5, proj.Z[i]!.val < 2 ^ 52) :
    proj.IsValid ∧ proj.toPoint = q.toPoint := by

  have hpZ_ne : proj.Z.toField ≠ 0 := by
    rw [hZ_F]
    apply mul_ne_zero hq_valid.Z_ne_zero hq_valid.T_ne_zero

  have h_on_curve : Ed25519.a * proj.X.toField ^ 2 * proj.Z.toField ^ 2 +
      proj.Y.toField ^ 2 * proj.Z.toField ^ 2 =
      proj.Z.toField ^ 4 + Ed25519.d * proj.X.toField ^ 2 * proj.Y.toField ^ 2 :=
    as_projective_on_curve proj.X.toField proj.Y.toField proj.Z.toField
      q.X.toField q.Y.toField q.Z.toField q.T.toField
      hX_F hY_F hZ_F hq_valid.on_curve

  have h_proj_valid : proj.IsValid := {
    X_bounds := hpX_bounds
    Y_bounds := hpY_bounds
    Z_bounds := hpZ_bounds
    Z_ne_zero := hpZ_ne
    on_curve := h_on_curve
  }
  constructor
  · exact h_proj_valid
  ·
    have ⟨h_px, h_py⟩ := ProjectivePoint.toPoint_of_isValid h_proj_valid
    have ⟨h_qx, h_qy⟩ := CompletedPoint.toPoint_of_isValid hq_valid
    ext
    ·
      rw [h_px, hX_F, hZ_F, h_qx]
      field_simp [hq_valid.Z_ne_zero, hq_valid.T_ne_zero]
    ·
      rw [h_py, hY_F, hZ_F, h_qy]
      field_simp [hq_valid.Z_ne_zero, hq_valid.T_ne_zero]








theorem as_projective_spec
    (q : CompletedPoint) (hq_valid : q.IsValid) :
    ∃ proj, as_projective q = ok proj ∧
    proj.IsValid ∧ proj.toPoint = q.toPoint := by
  sorry
end curve25519_dalek.backend.serial.curve_models.CompletedPoint
