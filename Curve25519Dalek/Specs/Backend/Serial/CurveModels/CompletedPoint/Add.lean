




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.AddAssign




























open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.backend.serial.curve_models
open curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAProjectiveNielsPointCompletedPoint
namespace curve25519_dalek.backend.serial.curve_models.CompletedPoint
































theorem add_assign_spec' (a b : Array U64 5#usize)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 54)
    (hb : ∀ i < 5, b[i]!.val < 2 ^ 52) :
    ∃ result, backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51.add_assign a b = ok result ∧
    (∀ i < 5, (result[i]!).val = (a[i]!).val + (b[i]!).val) ∧
    (∀ i < 5, result[i]!.val < 2 ^ 55) := by
  sorry
theorem add_spec' {a b : Array U64 5#usize}
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 54) (hb : ∀ i < 5, b[i]!.val < 2 ^ 52) :
    ∃ result, Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51.add a b = ok result ∧
    (∀ i < 5, result[i]!.val = a[i]!.val + b[i]!.val) ∧
    (∀ i < 5, result[i]!.val < 2^55) := by
  sorry

theorem add_assign_spec_52_52 (a b : Array U64 5#usize)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 52)
    (hb : ∀ i < 5, b[i]!.val < 2 ^ 52) :
    ∃ result, backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51.add_assign a b = ok result ∧
    (∀ i < 5, (result[i]!).val = (a[i]!).val + (b[i]!).val) ∧
    (∀ i < 5, result[i]!.val < 2 ^ 53) := by
  sorry

theorem add_assign_spec_53_52 (a b : Array U64 5#usize)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 53)
    (hb : ∀ i < 5, b[i]!.val < 2 ^ 52) :
    ∃ result, backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51.add_assign a b = ok result ∧
    (∀ i < 5, (result[i]!).val = (a[i]!).val + (b[i]!).val) ∧
    (∀ i < 5, result[i]!.val < 2 ^ 54) := by
  sorry

theorem add_spec_52_52 {a b : Array U64 5#usize}
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 52) (hb : ∀ i < 5, b[i]!.val < 2 ^ 52) :
    ∃ result, Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51.add a b = ok result ∧
    (∀ i < 5, result[i]!.val = a[i]!.val + b[i]!.val) ∧
    (∀ i < 5, result[i]!.val < 2^53) := by
  sorry

theorem add_spec_53_52 {a b : Array U64 5#usize}
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 53) (hb : ∀ i < 5, b[i]!.val < 2 ^ 52) :
    ∃ result, Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51.add a b = ok result ∧
    (∀ i < 5, result[i]!.val = a[i]!.val + b[i]!.val) ∧
    (∀ i < 5, result[i]!.val < 2^54) := by
  sorry

private lemma zz2_tight_bounds {ZZ ZZ2 : Array U64 5#usize}
    (h_ZZ_bounds : ∀ i < 5, ZZ[i]!.val < 2 ^ 52)
    (h_ZZ2 : ∀ i < 5, ZZ2[i]!.val = ZZ[i]!.val + ZZ[i]!.val) :
    ∀ i < 5, ZZ2[i]!.val < 2 ^ 53 := by
  intro i hi
  calc ZZ2[i]!.val = ZZ[i]!.val + ZZ[i]!.val := h_ZZ2 i hi
      _ < 2 ^ 52 + 2 ^ 52 := by have := h_ZZ_bounds i hi; omega
      _ = 2 ^ 53 := by norm_num


private lemma add_X_mod_arith (fe PP MM Y_plus_X Y_minus_X selfX selfY otherYpX otherYmX : ℕ)
    (h_YpX_eq : Y_plus_X = selfY + selfX)
    (h_YmX : (Y_minus_X + selfX) % p = selfY % p)
    (h_PP : PP ≡ Y_plus_X * otherYpX [MOD p])
    (h_MM : MM ≡ Y_minus_X * otherYmX [MOD p])
    (h_fe : (fe + MM) % p = PP % p) :
    (fe + selfY * otherYmX) % p = ((selfY + selfX) * otherYpX + selfX * otherYmX) % p := by
  rw [← Nat.ModEq, ← h_YpX_eq]
  rw [← Nat.ModEq] at h_fe
  have := Nat.ModEq.mul_right otherYmX h_YmX
  have := Nat.ModEq.symm (Nat.ModEq.add_left fe this)
  rw [add_mul, ← add_assoc] at this
  apply Nat.ModEq.trans this
  apply Nat.ModEq.add_right
  apply Nat.ModEq.symm
  apply Nat.ModEq.trans (Nat.ModEq.symm h_PP)
  apply Nat.ModEq.trans (Nat.ModEq.symm h_fe)
  apply Nat.ModEq.add_left
  exact h_MM


private lemma add_Y_mod_arith (fe1 PP MM Y_plus_X Y_minus_X selfX selfY otherYpX otherYmX : ℕ)
    (h_fe1_eq : fe1 = PP + MM)
    (h_YpX_eq : Y_plus_X = selfY + selfX)
    (h_YmX : (Y_minus_X + selfX) % p = selfY % p)
    (h_PP : PP ≡ Y_plus_X * otherYpX [MOD p])
    (h_MM : MM ≡ Y_minus_X * otherYmX [MOD p]) :
    (fe1 + selfX * otherYmX) % p = ((selfY + selfX) * otherYpX + selfY * otherYmX) % p := by
  rw [← Nat.ModEq, h_fe1_eq]
  have := Nat.ModEq.add h_PP h_MM
  have := Nat.ModEq.add_right (selfX * otherYmX) this
  apply Nat.ModEq.trans this
  rw [← h_YpX_eq, add_assoc]
  apply Nat.ModEq.add_left
  rw [← add_mul]
  apply Nat.ModEq.mul_right
  exact h_YmX


private lemma add_Z_mod_arith (fe2 ZZ2 ZZ TT2d selfZ otherZ selfT otherT2d : ℕ)
    (h_fe2_eq : fe2 = ZZ2 + TT2d)
    (h_ZZ2_eq : ZZ2 = ZZ + ZZ)
    (h_ZZ : ZZ ≡ selfZ * otherZ [MOD p])
    (h_TT2d : TT2d ≡ selfT * otherT2d [MOD p]) :
    fe2 % p = (2 * selfZ * otherZ + selfT * otherT2d) % p := by
  rw [← Nat.ModEq, h_fe2_eq, h_ZZ2_eq]
  simp only [(by scalar_tac : ∀ a, a + a = 2 * a)]
  have := Nat.ModEq.mul_left 2 h_ZZ
  have := Nat.ModEq.add_right TT2d this
  apply Nat.ModEq.trans this
  rw [mul_assoc]
  apply Nat.ModEq.add_left
  exact h_TT2d


private lemma add_T_mod_arith (fe3 ZZ2 ZZ TT2d selfZ otherZ selfT otherT2d : ℕ)
    (h_ZZ2_eq : ZZ2 = ZZ + ZZ)
    (h_ZZ : ZZ ≡ selfZ * otherZ [MOD p])
    (h_TT2d : TT2d ≡ selfT * otherT2d [MOD p])
    (h_fe3 : (fe3 + TT2d) % p = ZZ2 % p) :
    (fe3 + selfT * otherT2d) % p = (2 * selfZ * otherZ) % p := by
  rw [← Nat.ModEq]
  rw [← Nat.ModEq] at h_fe3
  have := Nat.ModEq.add_left fe3 h_TT2d
  have := Nat.ModEq.trans (Nat.ModEq.symm this) h_fe3
  apply Nat.ModEq.trans this
  rw [h_ZZ2_eq]
  simp only [(by omega : ∀ a, a + a = 2 * a)]
  have := Nat.ModEq.mul_left 2 h_ZZ
  rw [mul_assoc]
  exact this












theorem add_spec_aux_54_52_53_52
    (self : edwards.EdwardsPoint)
    (other : backend.serial.curve_models.ProjectiveNielsPoint)
    (h_selfX_bounds : ∀ i, i < 5 → (self.X[i]!).val < 2 ^ 53)
    (h_selfY_bounds : ∀ i, i < 5 → (self.Y[i]!).val < 2 ^ 53)
    (h_selfZ_bounds : ∀ i, i < 5 → (self.Z[i]!).val < 2 ^ 53)
    (h_selfT_bounds : ∀ i, i < 5 → (self.T[i]!).val < 2 ^ 53)
    (h_otherYpX_bounds : ∀ i, i < 5 → (other.Y_plus_X[i]!).val < 2 ^ 54)
    (h_otherYmX_bounds : ∀ i, i < 5 → (other.Y_minus_X[i]!).val < 2 ^ 52)
    (h_otherZ_bounds : ∀ i, i < 5 → (other.Z[i]!).val < 2 ^ 53)
    (h_otherT2d_bounds : ∀ i, i < 5 → (other.T2d[i]!).val < 2 ^ 52) :
    add self other ⦃ c =>
    let X := Field51_as_Nat self.X
    let Y := Field51_as_Nat self.Y
    let Z := Field51_as_Nat self.Z
    let T := Field51_as_Nat self.T
    let YpX := Field51_as_Nat other.Y_plus_X
    let YmX := Field51_as_Nat other.Y_minus_X
    let Z₀ := Field51_as_Nat other.Z
    let T2d := Field51_as_Nat other.T2d
    let X' := Field51_as_Nat c.X
    let Y' := Field51_as_Nat c.Y
    let Z' := Field51_as_Nat c.Z
    let T' := Field51_as_Nat c.T
    (X' + Y * YmX) % p = ((Y + X) * YpX + X * YmX) % p ∧
    (Y' + X * YmX) % p = ((Y + X) * YpX + Y  * YmX) % p ∧
    Z' % p = ((2 * Z * Z₀) + (T * T2d)) % p ∧
    (T' + T * T2d) % p = (2 * Z * Z₀ ) % p ∧

    (∀ i < 5, c.X[i]!.val < 2 ^ 54) ∧
    (∀ i < 5, c.Y[i]!.val < 2 ^ 54) ∧
    (∀ i < 5, c.Z[i]!.val < 2 ^ 54) ∧
    (∀ i < 5, c.T[i]!.val < 2 ^ 54) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.curve_models.CompletedPoint







namespace curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAProjectiveNielsPointCompletedPoint

open Edwards
open curve25519_dalek.backend.serial.curve_models
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.edwards








theorem add_spec_bounds
    (self : curve25519_dalek.edwards.EdwardsPoint) (hself : self.IsValid)
    (other : ProjectiveNielsPoint) (hother : other.IsValid) :
    ∃ c, add self other = ok c ∧
    let X := Field51_as_Nat self.X
    let Y := Field51_as_Nat self.Y
    let Z := Field51_as_Nat self.Z
    let T := Field51_as_Nat self.T
    let YpX := Field51_as_Nat other.Y_plus_X
    let YmX := Field51_as_Nat other.Y_minus_X
    let Z₀ := Field51_as_Nat other.Z
    let T2d := Field51_as_Nat other.T2d
    let X' := Field51_as_Nat c.X
    let Y' := Field51_as_Nat c.Y
    let Z' := Field51_as_Nat c.Z
    let T' := Field51_as_Nat c.T
    (X' + Y * YmX) % p = ((Y + X) * YpX + X * YmX) % p ∧
    (Y' + X * YmX) % p = ((Y + X) * YpX + Y * YmX) % p ∧
    Z' % p = ((2 * Z * Z₀) + (T * T2d)) % p ∧
    (T' + T * T2d) % p = (2 * Z * Z₀) % p ∧

    (∀ i < 5, c.X[i]!.val < 2 ^ 54) ∧
    (∀ i < 5, c.Y[i]!.val < 2 ^ 54) ∧
    (∀ i < 5, c.Z[i]!.val < 2 ^ 54) ∧
    (∀ i < 5, c.T[i]!.val < 2 ^ 54) := by
  sorry









private lemma niels_T2d_affine_expr (YpX YmX Z T2d x y : CurveField)
    (hZ_ne : Z ≠ 0)
    (hx : x = (YpX - YmX) / (2 * Z))
    (hy : y = (YpX + YmX) / (2 * Z))
    (h_rel : 2 * Z * T2d = Ed25519.d * (YpX ^ 2 - YmX ^ 2)) :
    T2d = 2 * Ed25519.d * Z * x * y := by
  have h2 : (2 : CurveField) ≠ 0 := by decide
  have h2Z_ne : 2 * Z ≠ 0 := mul_ne_zero h2 hZ_ne
  rw [show YpX ^ 2 - YmX ^ 2 = (YpX - YmX) * (YpX + YmX) from by ring] at h_rel
  have h_factor : (YpX - YmX) * (YpX + YmX) = 4 * Z ^ 2 * x * y := by
    simp only [hx, hy]; field_simp [h2Z_ne]; ring
  rw [h_factor] at h_rel
  have h_cancel : T2d * (2 * Z) = 2 * Ed25519.d * Z * x * y * (2 * Z) := by
    linear_combination h_rel
  field_simp [hZ_ne, h2] at h_cancel
  calc T2d = 2 * Z * Ed25519.d * x * y := h_cancel
    _ = 2 * Ed25519.d * Z * x * y := by ring



private lemma edwards_T_affine_expr (X Y Z T x y : CurveField)
    (hZ_ne : Z ≠ 0)
    (hx : x = X / Z) (hy : y = Y / Z)
    (h_T : X * Y = T * Z) :
    T = x * y * Z := by
  simp only [hx, hy]; field_simp [hZ_ne]; linear_combination -h_T



private lemma completed_on_curve_of_factored_add
    (X' Y' Z' T' x1 y1 x2 y2 Z1 Z2 : CurveField)
    (P1 : Point Ed25519) (hP1x : P1.x = x1) (hP1y : P1.y = y1)
    (P2 : Point Ed25519) (hP2x : P2.x = x2) (hP2y : P2.y = y2)
    (hZ1_ne : Z1 ≠ 0) (hZ2_ne : Z2 ≠ 0)
    (hX' : X' = 2 * Z1 * Z2 * (x1 * y2 + y1 * x2))
    (hY' : Y' = 2 * Z1 * Z2 * (y1 * y2 + x1 * x2))
    (hZ' : Z' = 2 * Z1 * Z2 * (1 + Ed25519.d * x1 * x2 * y1 * y2))
    (hT' : T' = 2 * Z1 * Z2 * (1 - Ed25519.d * x1 * x2 * y1 * y2))
    (hZ'_ne : Z' ≠ 0) (hT'_ne : T' ≠ 0) :
    Ed25519.a * X' ^ 2 * T' ^ 2 + Y' ^ 2 * Z' ^ 2 =
    Z' ^ 2 * T' ^ 2 + Ed25519.d * X' ^ 2 * Y' ^ 2 := by
  have h2 : (2 : CurveField) ≠ 0 := by decide
  have h_sum_on_curve := (P1 + P2).on_curve
  have h_sum_x : (P1 + P2).x = (x1 * y2 + y1 * x2) / (1 + Ed25519.d * x1 * x2 * y1 * y2) := by
    rw [add_x, hP1x, hP1y, hP2x, hP2y]
  have h_sum_y : (P1 + P2).y = (y1 * y2 + x1 * x2) / (1 - Ed25519.d * x1 * x2 * y1 * y2) := by
    rw [add_y, hP1x, hP1y, hP2x, hP2y]
    simp only [Ed25519]
    ring_nf
  have h_cx_eq : X' / Z' = (P1 + P2).x := by
    rw [hX', hZ', h_sum_x]; field_simp [h2, hZ1_ne, hZ2_ne]
  have h_cy_eq : Y' / T' = (P1 + P2).y := by
    rw [hY', hT', h_sum_y]; field_simp [h2, hZ1_ne, hZ2_ne]
  have hcZ2 : Z' ^ 2 ≠ 0 := pow_ne_zero 2 hZ'_ne
  have hcT2 : T' ^ 2 ≠ 0 := pow_ne_zero 2 hT'_ne
  simp only [Ed25519] at h_sum_on_curve ⊢
  have h_key : (Ed25519.a * (P1 + P2).x ^ 2 + (P1 + P2).y ^ 2) =
      (1 + Ed25519.d * (P1 + P2).x ^ 2 * (P1 + P2).y ^ 2) := by
    simp only [Ed25519]; exact h_sum_on_curve
  calc Ed25519.a * X' ^ 2 * T' ^ 2 + Y' ^ 2 * Z' ^ 2
      = (Ed25519.a * (X' / Z') ^ 2 + (Y' / T') ^ 2) *
          Z' ^ 2 * T' ^ 2 := by field_simp [hcZ2, hcT2]
    _ = (Ed25519.a * (P1 + P2).x ^ 2 + (P1 + P2).y ^ 2) * Z' ^ 2 * T' ^ 2 := by
          rw [h_cx_eq, h_cy_eq]
    _ = (1 + Ed25519.d * (P1 + P2).x ^ 2 * (P1 + P2).y ^ 2) * Z' ^ 2 * T' ^ 2 := by
          rw [h_key]
    _ = Z' ^ 2 * T' ^ 2 + Ed25519.d * X' ^ 2 * Y' ^ 2 := by
          rw [← h_cx_eq, ← h_cy_eq]
          simp only [div_pow]
          field_simp [hcZ2, hcT2]




private lemma edwards_affine_on_curve_of_projective
    (X Y Z : CurveField) (hZ_ne : Z ≠ 0)
    (h_curve : Ed25519.a * X ^ 2 * Z ^ 2 + Y ^ 2 * Z ^ 2 = Z ^ 4 + Ed25519.d * X ^ 2 * Y ^ 2) :
    Ed25519.a * (X / Z)^2 + (Y / Z)^2 = 1 + Ed25519.d * (X / Z) ^ 2 * (Y / Z) ^ 2 := by
  have hZ2 : Z^2 ≠ 0 := pow_ne_zero 2 hZ_ne
  have hZ4 : Z^4 ≠ 0 := pow_ne_zero 4 hZ_ne
  simp only [Ed25519] at h_curve ⊢
  simp only [div_pow]
  field_simp [hZ2, hZ4]
  linear_combination h_curve




private lemma niels_affine_on_curve_of_projective
    (YpX YmX Z : CurveField) (hZ_ne : Z ≠ 0)
    (h_curve : 4 * Ed25519.a * (YpX - YmX) ^ 2 * Z ^ 2 + 4 * (YpX + YmX) ^ 2 * Z ^ 2 =
      16 * Z ^ 4 + Ed25519.d * (YpX - YmX) ^ 2 * (YpX + YmX) ^ 2) :
    Ed25519.a * ((YpX - YmX) / (2 * Z))^2 + ((YpX + YmX) / (2 * Z))^2 =
      1 + Ed25519.d * ((YpX - YmX) / (2 * Z))^2 * ((YpX + YmX) / (2 * Z))^2 := by
  have h2 : (2 : CurveField) ≠ 0 := by decide
  have h2Z_ne : 2 * Z ≠ 0 := mul_ne_zero h2 hZ_ne
  have h2Z2 : (2 * Z)^2 ≠ 0 := pow_ne_zero 2 h2Z_ne
  have h2Z4 : (2 * Z)^4 ≠ 0 := pow_ne_zero 4 h2Z_ne
  simp only [Ed25519] at h_curve ⊢
  simp only [div_pow]
  field_simp [h2Z2, h2Z4]
  ring_nf; ring_nf at h_curve
  linear_combination h_curve



private lemma add_T1_T2d_product (T1 T2d x1 y1 x2 y2 Z1 Z2 : CurveField)
    (h_T1 : T1 = x1 * y1 * Z1)
    (h_T2d : T2d = 2 * Ed25519.d * Z2 * x2 * y2) :
    T1 * T2d = 2 * Ed25519.d * x1 * x2 * y1 * y2 * Z1 * Z2 := by
  rw [h_T1, h_T2d]; ring


private lemma add_Z_coord_factored (cZ T1 T2d Z1 Z2 x1 x2 y1 y2 : CurveField)
    (hZ_F : cZ = 2 * Z1 * Z2 + T1 * T2d)
    (h_T1_T2d : T1 * T2d = 2 * Ed25519.d * x1 * x2 * y1 * y2 * Z1 * Z2) :
    cZ = 2 * Z1 * Z2 * (1 + Ed25519.d * x1 * x2 * y1 * y2) := by
  rw [hZ_F, h_T1_T2d]; ring


private lemma add_T_coord_factored (cT T1 T2d Z1 Z2 x1 x2 y1 y2 : CurveField)
    (hT_F : cT = 2 * Z1 * Z2 - T1 * T2d)
    (h_T1_T2d : T1 * T2d = 2 * Ed25519.d * x1 * x2 * y1 * y2 * Z1 * Z2) :
    cT = 2 * Z1 * Z2 * (1 - Ed25519.d * x1 * x2 * y1 * y2) := by
  rw [hT_F, h_T1_T2d]; ring




private lemma niels_coords_as_affine (YpX YmX Z x y : CurveField)
    (hZ_ne : Z ≠ 0)
    (hx : x = (YpX - YmX) / (2 * Z)) (hy : y = (YpX + YmX) / (2 * Z)) :
    YpX = Z * (x + y) ∧ YmX = Z * (y - x) := by
  have h2 : (2 : CurveField) ≠ 0 := by decide
  have h2Z_ne : 2 * Z ≠ 0 := mul_ne_zero h2 hZ_ne
  constructor
  · simp only [hx, hy]; field_simp [h2Z_ne]; ring
  · simp only [hx, hy]; field_simp [h2Z_ne]; ring



private lemma edwards_coords_as_affine (X Y Z x y : CurveField)
    (hZ_ne : Z ≠ 0) (hx : x = X / Z) (hy : y = Y / Z) :
    X = Z * x ∧ Y = Z * y := by
  constructor
  · simp only [hx]; field_simp [hZ_ne]
  · simp only [hy]; field_simp [hZ_ne]



private lemma add_X_coord_factored
    (cX YpX YmX X1 Y1 Z1 Z2 x1 y1 x2 y2 : CurveField)
    (hX_F' : cX = (Y1 + X1) * YpX - (Y1 - X1) * YmX)
    (hYpX : YpX = Z2 * (x2 + y2)) (hYmX : YmX = Z2 * (y2 - x2))
    (hX1 : X1 = Z1 * x1) (hY1 : Y1 = Z1 * y1) :
    cX = 2 * Z1 * Z2 * (x1 * y2 + y1 * x2) := by
  rw [hX_F', hYpX, hYmX, hX1, hY1]; ring



private lemma add_Y_coord_factored
    (cY YpX YmX X1 Y1 Z1 Z2 x1 y1 x2 y2 : CurveField)
    (hY_F' : cY = (Y1 + X1) * YpX + (Y1 - X1) * YmX)
    (hYpX : YpX = Z2 * (x2 + y2)) (hYmX : YmX = Z2 * (y2 - x2))
    (hX1 : X1 = Z1 * x1) (hY1 : Y1 = Z1 * y1) :
    cY = 2 * Z1 * Z2 * (y1 * y2 + x1 * x2) := by
  rw [hY_F', hYpX, hYmX, hX1, hY1]; ring



private lemma add_completed_toPoint_eq_sum
    (self : EdwardsPoint) (_hself : self.IsValid)
    (c : CompletedPoint) (hc : c.IsValid)
    (Q : Point Ed25519)
    (x1 y1 x2 y2 Z1 Z2 : CurveField)
    (hZ1_ne : Z1 ≠ 0) (hZ2_ne : Z2 ≠ 0)
    (h_self_x : self.toPoint.x = x1) (h_self_y : self.toPoint.y = y1)
    (h_other_x : Q.x = x2) (h_other_y : Q.y = y2)
    (hX_factored : c.X.toField = 2 * Z1 * Z2 * (x1 * y2 + y1 * x2))
    (hY_factored : c.Y.toField = 2 * Z1 * Z2 * (y1 * y2 + x1 * x2))
    (hZ_factored : c.Z.toField = 2 * Z1 * Z2 * (1 + Ed25519.d * x1 * x2 * y1 * y2))
    (hT_factored : c.T.toField = 2 * Z1 * Z2 * (1 - Ed25519.d * x1 * x2 * y1 * y2))
    (_h_denom_plus : 1 + Ed25519.d * x1 * x2 * y1 * y2 ≠ 0)
    (_h_denom_minus : 1 - Ed25519.d * x1 * x2 * y1 * y2 ≠ 0) :
    c.toPoint = self.toPoint + Q := by
  have h2 : (2 : CurveField) ≠ 0 := by decide
  have ⟨h_cx, h_cy⟩ := CompletedPoint.toPoint_of_isValid hc
  ext
  · rw [h_cx, hX_factored, hZ_factored, add_x, h_self_x, h_self_y, h_other_x, h_other_y]
    field_simp [h2, hZ1_ne, hZ2_ne]
  · rw [h_cy, hY_factored, hT_factored, add_y, h_self_x, h_self_y, h_other_x, h_other_y]
    simp only [Ed25519]
    field_simp [h2, hZ1_ne, hZ2_ne]
    ring_nf






private lemma add_spec_algebraic
    (self : EdwardsPoint) (hself : self.IsValid)
    (other : ProjectiveNielsPoint)
    (hother_Z_ne_zero : other.Z.toField ≠ 0)
    (hother_on_curve :
      4 * Ed25519.a * (other.Y_plus_X.toField - other.Y_minus_X.toField) ^ 2 *
        other.Z.toField ^ 2 +
      4 * (other.Y_plus_X.toField + other.Y_minus_X.toField) ^ 2 * other.Z.toField ^ 2 =
      16 * other.Z.toField ^ 4 +
      Ed25519.d * (other.Y_plus_X.toField - other.Y_minus_X.toField) ^ 2 *
        (other.Y_plus_X.toField + other.Y_minus_X.toField) ^ 2)
    (hother_T2d_relation :
      2 * other.Z.toField * other.T2d.toField =
      Ed25519.d * (other.Y_plus_X.toField ^ 2 - other.Y_minus_X.toField ^ 2))
    (c : CompletedPoint)
    (hX_F : c.X.toField + self.Y.toField * other.Y_minus_X.toField =
        (self.Y.toField + self.X.toField) * other.Y_plus_X.toField +
        self.X.toField * other.Y_minus_X.toField)
    (hY_F : c.Y.toField + self.X.toField * other.Y_minus_X.toField =
        (self.Y.toField + self.X.toField) * other.Y_plus_X.toField +
        self.Y.toField * other.Y_minus_X.toField)
    (hZ_F : c.Z.toField = 2 * self.Z.toField * other.Z.toField +
        self.T.toField * other.T2d.toField)
    (hT_F : c.T.toField + self.T.toField * other.T2d.toField =
        2 * self.Z.toField * other.Z.toField)
    (hcX_valid : c.X.IsValid) (hcY_valid : c.Y.IsValid)
    (hcZ_valid : c.Z.IsValid) (hcT_valid : c.T.IsValid)
    (Q : Point Ed25519)
    (hQx : Q.x = (other.Y_plus_X.toField - other.Y_minus_X.toField) / (2 * other.Z.toField))
    (hQy : Q.y = (other.Y_plus_X.toField + other.Y_minus_X.toField) / (2 * other.Z.toField)) :
    c.IsValid ∧ c.toPoint = self.toPoint + Q := by

  have hX_F' : c.X.toField = (self.Y.toField + self.X.toField) * other.Y_plus_X.toField -
      (self.Y.toField - self.X.toField) * other.Y_minus_X.toField := by
    have := hX_F; linear_combination this
  have hY_F' : c.Y.toField = (self.Y.toField + self.X.toField) * other.Y_plus_X.toField +
      (self.Y.toField - self.X.toField) * other.Y_minus_X.toField := by
    have := hY_F; linear_combination this
  have hT_F' : c.T.toField = 2 * self.Z.toField * other.Z.toField -
      self.T.toField * other.T2d.toField := by
    have := hT_F; linear_combination this

  set X1 := self.X.toField with hX1_def
  set Y1 := self.Y.toField with hY1_def
  set Z1 := self.Z.toField with hZ1_def
  set T1 := self.T.toField with hT1_def
  have hZ1_ne : Z1 ≠ 0 := hself.Z_ne_zero

  set YpX := other.Y_plus_X.toField with hYpX_def
  set YmX := other.Y_minus_X.toField with hYmX_def
  set Z2 := other.Z.toField with hZ2_def
  set T2d := other.T2d.toField with hT2d_def
  have hZ2_ne : Z2 ≠ 0 := hother_Z_ne_zero
  have h2 : (2 : CurveField) ≠ 0 := by decide

  set x1 := X1 / Z1 with hx1_def
  set y1 := Y1 / Z1 with hy1_def
  set x2 := (YpX - YmX) / (2 * Z2) with hx2_def
  set y2 := (YpX + YmX) / (2 * Z2) with hy2_def

  have h_P1_on_curve := edwards_affine_on_curve_of_projective X1 Y1 Z1 hZ1_ne hself.on_curve
  let P1 : Point Ed25519 := ⟨x1, y1, h_P1_on_curve⟩
  have h_P2_on_curve := niels_affine_on_curve_of_projective YpX YmX Z2 hZ2_ne hother_on_curve
  let P2 : Point Ed25519 := ⟨x2, y2, h_P2_on_curve⟩

  have h_denoms := Ed25519.denomsNeZero P1 P2
  have h_denom_plus : 1 + Ed25519.d * x1 * x2 * y1 * y2 ≠ 0 := by
    have h := h_denoms.1; simp only [P1, P2] at h; convert h using 1
  have h_denom_minus : 1 - Ed25519.d * x1 * x2 * y1 * y2 ≠ 0 := by
    have h := h_denoms.2; simp only [P1, P2] at h; convert h using 1

  have h_T2d_expr := niels_T2d_affine_expr YpX YmX Z2 T2d x2 y2 hZ2_ne hx2_def hy2_def
    hother_T2d_relation
  have h_T1_expr := edwards_T_affine_expr X1 Y1 Z1 T1 x1 y1 hZ1_ne hx1_def hy1_def
    hself.T_relation

  have h_T1_T2d := add_T1_T2d_product T1 T2d x1 y1 x2 y2 Z1 Z2 h_T1_expr h_T2d_expr

  have hZ_factored := add_Z_coord_factored c.Z.toField T1 T2d Z1 Z2 x1 x2 y1 y2 hZ_F h_T1_T2d
  have hT_factored := add_T_coord_factored c.T.toField T1 T2d Z1 Z2 x1 x2 y1 y2 hT_F' h_T1_T2d

  have hcZ_ne : c.Z.toField ≠ 0 := by
    rw [hZ_factored]
    exact mul_ne_zero (mul_ne_zero (mul_ne_zero h2 hZ1_ne) hZ2_ne) h_denom_plus
  have hcT_ne : c.T.toField ≠ 0 := by
    rw [hT_factored]
    exact mul_ne_zero (mul_ne_zero (mul_ne_zero h2 hZ1_ne) hZ2_ne) h_denom_minus

  have ⟨hYpX', hYmX'⟩ := niels_coords_as_affine YpX YmX Z2 x2 y2 hZ2_ne hx2_def hy2_def
  have ⟨hX1', hY1'⟩ := edwards_coords_as_affine X1 Y1 Z1 x1 y1 hZ1_ne hx1_def hy1_def

  have hX_factored := add_X_coord_factored c.X.toField YpX YmX X1 Y1 Z1 Z2 x1 y1 x2 y2
    hX_F' hYpX' hYmX' hX1' hY1'
  have hY_factored := add_Y_coord_factored c.Y.toField YpX YmX X1 Y1 Z1 Z2 x1 y1 x2 y2
    hY_F' hYpX' hYmX' hX1' hY1'

  have h_c_on_curve := completed_on_curve_of_factored_add
    c.X.toField c.Y.toField c.Z.toField c.T.toField x1 y1 x2 y2 Z1 Z2
    P1 rfl rfl P2 rfl rfl
    hZ1_ne hZ2_ne
    hX_factored hY_factored hZ_factored hT_factored
    hcZ_ne hcT_ne

  have h_c_valid : c.IsValid := {
    X_valid := hcX_valid
    Y_valid := hcY_valid
    Z_valid := hcZ_valid
    T_valid := hcT_valid
    Z_ne_zero := hcZ_ne
    T_ne_zero := hcT_ne
    on_curve := h_c_on_curve
  }
  refine ⟨h_c_valid, ?_⟩

  have ⟨h_selfx, h_selfy⟩ := EdwardsPoint.toPoint_of_isValid hself
  have h_self_x : self.toPoint.x = x1 := by simp only [h_selfx, hx1_def, hX1_def, hZ1_def]
  have h_self_y : self.toPoint.y = y1 := by simp only [h_selfy, hy1_def, hY1_def, hZ1_def]
  have h_other_x : Q.x = x2 := by simp only [hQx, hx2_def, hYpX_def, hYmX_def, hZ2_def]
  have h_other_y : Q.y = y2 := by simp only [hQy, hy2_def, hYpX_def, hYmX_def, hZ2_def]
  exact add_completed_toPoint_eq_sum self hself c h_c_valid Q x1 y1 x2 y2 Z1 Z2
    hZ1_ne hZ2_ne h_self_x h_self_y h_other_x h_other_y
    hX_factored hY_factored hZ_factored hT_factored h_denom_plus h_denom_minus









@[progress]
theorem add_spec
    (self : curve25519_dalek.edwards.EdwardsPoint) (hself : self.IsValid)
    (other : ProjectiveNielsPoint) (hother : other.IsValid) :
    add self other ⦃ c =>
    c.IsValid ∧ c.toPoint = self.toPoint + other.toPoint ⦄ := by
  sorry
end curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAProjectiveNielsPointCompletedPoint
