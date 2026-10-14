/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.AsProjective
import Curve25519Dalek.Specs.Backend.Serial.CurveModels.ProjectivePoint.Double
import Curve25519Dalek.Specs.Backend.Serial.CurveModels.CompletedPoint.AsExtended

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.EdwardsPoint

open Edwards in
theorem double_field (X Y Z Xc Yc Zc Tc X' Y' Z' T' : CurveField) (hZ : Z ≠ 0)
    (hcurve : Ed25519.a * X^2 * Z^2 + Y^2 * Z^2 = Z^4 + Ed25519.d * X^2 * Y^2)
    (hXc : Xc + Y^2 + X^2 = (X + Y)^2) (hYc : Yc = Y^2 + X^2) (hZc : Zc + X^2 = Y^2)
    (hTc : Tc + Zc = 2 * Z^2)
    (hX' : X' = Xc * Tc) (hY' : Y' = Yc * Zc) (hZ' : Z' = Zc * Tc) (hT' : T' = Xc * Yc) :
    Z' ≠ 0 ∧ X' * Y' = T' * Z' ∧
    Ed25519.a * X'^2 * Z'^2 + Y'^2 * Z'^2 = Z'^4 + Ed25519.d * X'^2 * Y'^2 ∧
    X' / Z' = ((X/Z) * (Y/Z) + (Y/Z) * (X/Z)) /
      (1 + Ed25519.d * (X/Z) * (X/Z) * (Y/Z) * (Y/Z)) ∧
    Y' / Z' = ((Y/Z) * (Y/Z) - Ed25519.a * (X/Z) * (X/Z)) /
      (1 - Ed25519.d * (X/Z) * (X/Z) * (Y/Z) * (Y/Z)) := by
  have ha : Ed25519.a = -1 := rfl
  rw [ha] at hcurve ⊢
  have hXc' : Xc = 2 * X * Y := by linear_combination hXc
  have hZc' : Zc = Y^2 - X^2 := by linear_combination hZc
  have hTc' : Tc = 2 * Z^2 - Y^2 + X^2 := by linear_combination hTc - hZc
  subst hXc' hZc' hTc' hYc hX' hY' hZ' hT'
  obtain ⟨s, hs⟩ := neg_one_is_square
  have hZc0 : Y^2 - X^2 ≠ 0 := by
    intro h0
    have hX0 : X ≠ 0 := by
      rintro rfl
      apply hZ
      have : Z^4 = 0 := by linear_combination -hcurve + Z^2 * h0
      exact pow_eq_zero_iff (by norm_num) |>.mp this
    apply d_not_square
    refine ⟨s * Z^2 / X^2, ?_⟩
    rw [div_mul_div_comm, eq_div_iff (mul_ne_zero (pow_ne_zero 2 hX0) (pow_ne_zero 2 hX0))]
    linear_combination -hcurve + (Z^2 - Ed25519.d * X^2) * h0 + Z^4 * hs
  have hTc0 : 2 * Z^2 - Y^2 + X^2 ≠ 0 := by
    intro h0
    have hXY : X * Y ≠ 0 := by
      intro hxy
      apply hZ
      have : Z^4 = 0 := by linear_combination hcurve + Z^2 * h0 + Ed25519.d * X * Y * hxy
      exact pow_eq_zero_iff (by norm_num) |>.mp this
    apply d_not_square
    refine ⟨Z^2 / (X * Y), ?_⟩
    rw [div_mul_div_comm, eq_div_iff (mul_ne_zero hXY hXY)]
    linear_combination -hcurve - Z^2 * h0
  refine ⟨mul_ne_zero hZc0 hTc0, by ring, ?_, ?_, ?_⟩
  · linear_combination (4 * (Y^2 + X^2)^2 * (Y^2 - X^2)^2 * (2 * Z^2 - Y^2 + X^2)^2) * hcurve
  · have h1 : 1 + Ed25519.d * (X/Z) * (X/Z) * (Y/Z) * (Y/Z) = (Y^2 - X^2) / Z^2 := by
      field_simp
      linear_combination -hcurve
    rw [h1]
    field_simp
    ring
  · have h1 : 1 - Ed25519.d * (X/Z) * (X/Z) * (Y/Z) * (Y/Z) = (2 * Z^2 - Y^2 + X^2) / Z^2 := by
      field_simp
      linear_combination hcurve
    rw [h1]
    field_simp
    ring

/-- As upstream, validity includes the curve equation, `Z ≠ 0`, `XY = TZ`,
and coordinate limbs below `2^53`, for both the input and the output. -/
@[externally_verified, progress]
theorem double_spec (e : EdwardsPoint) (he_valid : e.IsValid) :
    double e ⦃ result =>
    result.IsValid ∧ result.toPoint = e.toPoint + e.toPoint ⦄ := by
  have hXb := he_valid.X_bounds
  have hYb := he_valid.Y_bounds
  have hZb := he_valid.Z_bounds
  unfold double
  progress with as_projective_spec as ⟨pp, hX, hY, hZ, _, _, _⟩
  rw [← hX] at hXb
  rw [← hY] at hYb
  rw [← hZ] at hZb
  have hZb' : ∀ i < 5, pp.Z[i]!.val < 2 ^ 54 := fun i hi => by have := hZb i hi; omega
  progress with backend.serial.curve_models.ProjectivePoint.double_spec as
    ⟨cp, hcX, hcY, hcZ, hcT, h1, h2, h3, h4⟩
  have hcX' : ∀ i < 5, cp.X[i]!.val < 2 ^ 54 := fun i hi => by have := hcX i hi; omega
  have hcY' : ∀ i < 5, cp.Y[i]!.val < 2 ^ 54 := fun i hi => by have := hcY i hi; omega
  have hcZ' : ∀ i < 5, cp.Z[i]!.val < 2 ^ 54 := fun i hi => by have := hcZ i hi; omega
  have hcT' : ∀ i < 5, cp.T[i]!.val < 2 ^ 54 := fun i hi => by have := hcT i hi; omega
  progress with backend.serial.curve_models.CompletedPoint.as_extended_spec as
    ⟨r, hrX, hrY, hrZ, hrT, h5, h6, h7, h8⟩
  have c1 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h1
  have c2 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h2
  have c3 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h3
  have c4 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h4
  have c5 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h5
  have c6 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h6
  have c7 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h7
  have c8 := (ZMod.natCast_eq_natCast_iff' _ _ p).mpr h8
  push_cast at c1 c2 c3 c4 c5 c6 c7 c8
  simp only [hX, hY, hZ] at c1 c2 c3 c4 c5 c6 c7 c8
  obtain ⟨hZne, hrel, hcurve, hx, hy⟩ := double_field e.X.toField e.Y.toField e.Z.toField
    cp.X.toField cp.Y.toField cp.Z.toField cp.T.toField
    r.X.toField r.Y.toField r.Z.toField r.T.toField
    he_valid.Z_ne_zero he_valid.on_curve c1 c2 c3 c4 c5 c6 c7 c8
  have hr : r.IsValid :=
    ⟨fun i hi => by have := hrX i hi; omega, fun i hi => by have := hrY i hi; omega,
     fun i hi => by have := hrZ i hi; omega, fun i hi => by have := hrT i hi; omega,
     hZne, hrel, hcurve⟩
  refine ⟨hr, ?_⟩
  rw [EdwardsPoint.toPoint, dif_pos hr, EdwardsPoint.toPoint, dif_pos he_valid]
  exact Edwards.Point.ext hx hy

end curve25519_dalek.edwards.EdwardsPoint
