




import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Funs
import Curve25519Dalek.Types
import Mathlib.Algebra.Field.ZMod
import Mathlib.Tactic.MkIffOfInductiveProp



















namespace curve25519_dalek.math

open Edwards ZMod
open Aeneas.Std Result

section EdwardsDecompression











noncomputable def decompress_edwards_pure (bytes : Array U8 32#usize) : Option (Point Ed25519) :=
  let s := U8x32_as_Nat bytes


  let y_int := s % (2^255)
  let sign_bit := s / (2^255)

  if y_int >= p then
    none
  else
    let y : ZMod p := y_int


    let u := y^2 - 1
    let v := d * y^2 + 1
    let x2 := u * v⁻¹

    if h : IsSquare x2 then
      let x_root := abs_edwards (Classical.choose h)

      let x := if (is_negative x_root) != (sign_bit == 1) then -x_root else x_root

      some { x := x, y := y, on_curve := by
              have hx_sq : x^2 = x2 := by
                simp only [x]
                suffices x_root ^ 2 = x2 by split_ifs <;> simpa
                have spec := Classical.choose_spec h
                rw [spec]
                dsimp [x_root]
                rw [abs_edwards_sq (Classical.choose h), pow_two]
              have hv_ne0 : v ≠ 0 := by
                intro hv
                dsimp only [v] at hv
                have h_neg : (d : ZMod p) * y^2 = -1 := eq_neg_of_add_eq_zero_left hv

                have rhs_sq : IsSquare (-1 : ZMod p) := by
                  use sqrt_m1; rw [←pow_two, sqrt_m1]; rw [← sub_eq_zero]







                  sorry

                have lhs_not_sq : ¬ IsSquare ((d : ZMod p) * y^2) := by
                  intro h_is_sq
                  have h_d_not_sq : ¬ IsSquare (d : ZMod p) := by
                    apply (legendreSym.eq_neg_one_iff' p).mp
                    norm_num [d, p]

                  apply h_d_not_sq
                  by_cases hy : y = 0
                  · simp only [hy, pow_two, mul_zero] at h_neg;
                    try grind
                  · rcases h_is_sq with ⟨k, hk⟩
                    use k * y⁻¹; ring_nf; field_simp [hy]; rw [← pow_two] at hk; exact hk

                rw [h_neg] at lhs_not_sq
                try grind

              simp only [hx_sq]
              dsimp [Ed25519, x2, u, v]
              simp only [neg_mul, one_mul]
              simp only [v] at hv_ne0
              rw [mul_comm] at hv_ne0
              field_simp [hv_ne0]
              ring
              }
    else
      none

end EdwardsDecompression

end curve25519_dalek.math





namespace curve25519_dalek.edwards.affine

open curve25519_dalek.backend.serial.u64.field
open Edwards





@[mk_iff]
structure AffinePoint.IsValid (a : AffinePoint) : Prop where

  x_valid : a.x.IsValid
  y_valid : a.y.IsValid

  on_curve :
    let x := a.x.toField
    let y := a.y.toField
    Ed25519.a * x^2 + y^2 = 1 + Ed25519.d * x^2 * y^2

instance AffinePoint.instDecidableIsValid (a : AffinePoint) : Decidable a.IsValid :=
  decidable_of_iff _ (isValid_iff a).symm


def AffinePoint.toPoint (a : AffinePoint) : Point Ed25519 :=
  if h : a.IsValid then
    { x := a.x.toField
      y := a.y.toField
      on_curve := h.on_curve }
  else 0

end curve25519_dalek.edwards.affine



namespace curve25519_dalek.edwards
open curve25519_dalek.backend.serial.u64.field Edwards




@[mk_iff]
structure EdwardsPoint.IsValid (e : EdwardsPoint) : Prop where

  X_bounds : ∀ i < 5, e.X[i]!.val < 2 ^ 53
  Y_bounds : ∀ i < 5, e.Y[i]!.val < 2 ^ 53
  Z_bounds : ∀ i < 5, e.Z[i]!.val < 2 ^ 53
  T_bounds : ∀ i < 5, e.T[i]!.val < 2 ^ 53

  Z_ne_zero : e.Z.toField ≠ 0

  T_relation : e.X.toField * e.Y.toField = e.T.toField * e.Z.toField

  on_curve :
    let X := e.X.toField; let Y := e.Y.toField; let Z := e.Z.toField
    Ed25519.a * X^2 * Z^2 + Y^2 * Z^2 = Z^4 + Ed25519.d * X^2 * Y^2

instance EdwardsPoint.instDecidableIsValid (e : EdwardsPoint) : Decidable e.IsValid :=
  decidable_of_iff _ (isValid_iff e).symm



def EdwardsPoint.toPoint' (e : EdwardsPoint) (h : e.IsValid) : Point Ed25519 :=
  let X := e.X.toField
  let Y := e.Y.toField
  let Z := e.Z.toField
  { x := X / Z
    y := Y / Z
    on_curve := by
      have hz : Z ≠ 0 := h.Z_ne_zero
      have hz2 : Z^2 ≠ 0 := pow_ne_zero 2 hz
      have hz4 : Z^4 ≠ 0 := pow_ne_zero 4 hz
      have hcurve : Ed25519.a * X^2 * Z^2 + Y^2 * Z^2 = Z^4 + Ed25519.d * X^2 * Y^2 := h.on_curve
      simp only [Ed25519] at hcurve ⊢
      simp only [div_pow]
      field_simp [hz2, hz4]
      linear_combination hcurve }



def EdwardsPoint.toPoint (e : EdwardsPoint) : Point Ed25519 :=
  if h : e.IsValid then e.toPoint' h else 0


theorem EdwardsPoint.toPoint_of_isValid {e : EdwardsPoint} (h : e.IsValid) :
    (e.toPoint).x = e.X.toField / e.Z.toField ∧
    (e.toPoint).y = e.Y.toField / e.Z.toField := by
  unfold toPoint
  rw [dif_pos h]
  simp only [toPoint']
  trivial

end curve25519_dalek.edwards





namespace curve25519_dalek.edwards
open curve25519_dalek.math Edwards





def CompressedEdwardsY.IsValid (c : CompressedEdwardsY) : Prop :=
  (decompress_edwards_pure c).isSome





noncomputable def CompressedEdwardsY.toPoint (c : CompressedEdwardsY) : Point Ed25519 :=
  match decompress_edwards_pure c with
  | some P => P
  | none => 0

end curve25519_dalek.edwards



namespace curve25519_dalek.backend.serial.curve_models
open Edwards

open curve25519_dalek.backend.serial.u64.field in








@[mk_iff]
structure ProjectivePoint.IsValid (pp : ProjectivePoint) : Prop where

  X_bounds : ∀ i < 5, pp.X[i]!.val < 2 ^ 52
  Y_bounds : ∀ i < 5, pp.Y[i]!.val < 2 ^ 52
  Z_bounds : ∀ i < 5, pp.Z[i]!.val < 2 ^ 52

  Z_ne_zero : pp.Z.toField ≠ 0

  on_curve :
    let X := pp.X.toField; let Y := pp.Y.toField; let Z := pp.Z.toField
    Ed25519.a * X^2 * Z^2 + Y^2 * Z^2 = Z^4 + Ed25519.d * X^2 * Y^2

instance ProjectivePoint.instDecidableIsValid (pp : ProjectivePoint) : Decidable pp.IsValid :=
  decidable_of_iff _ (isValid_iff pp).symm



noncomputable def ProjectivePoint.toPoint (pp : ProjectivePoint) : Point Ed25519 :=
  if h : pp.IsValid then
    let X := pp.X.toField
    let Y := pp.Y.toField
    let Z := pp.Z.toField
    { x := X / Z
      y := Y / Z
      on_curve := by
        have hz : Z ≠ 0 := h.Z_ne_zero
        have hz2 : Z^2 ≠ 0 := pow_ne_zero 2 hz
        have hz4 : Z^4 ≠ 0 := pow_ne_zero 4 hz
        have hcurve : Ed25519.a * X^2 * Z^2 + Y^2 * Z^2 = Z^4 + Ed25519.d * X^2 * Y^2 := h.on_curve
        simp only [Ed25519] at hcurve ⊢
        simp only [div_pow]
        field_simp [hz2, hz4]
        linear_combination hcurve }
  else 0


theorem ProjectivePoint.toPoint_of_isValid {pp : ProjectivePoint} (h : pp.IsValid) :
    (pp.toPoint).x = pp.X.toField / pp.Z.toField ∧
    (pp.toPoint).y = pp.Y.toField / pp.Z.toField := by
  unfold toPoint; rw [dif_pos h]; constructor <;> rfl



open curve25519_dalek.backend.serial.u64.field in






@[mk_iff]
structure CompletedPoint.IsValid (cp : CompletedPoint) : Prop where

  X_valid : cp.X.IsValid
  Y_valid : cp.Y.IsValid
  Z_valid : cp.Z.IsValid
  T_valid : cp.T.IsValid

  Z_ne_zero : cp.Z.toField ≠ 0

  T_ne_zero : cp.T.toField ≠ 0

  on_curve :
    let X := cp.X.toField; let Y := cp.Y.toField
    let Z := cp.Z.toField; let T := cp.T.toField
    Ed25519.a * X^2 * T^2 + Y^2 * Z^2 = Z^2 * T^2 + Ed25519.d * X^2 * Y^2

open curve25519_dalek.backend.serial.u64.field in
instance CompletedPoint.instDecidableIsValid (cp : CompletedPoint) : Decidable cp.IsValid :=
  decidable_of_iff _ (isValid_iff cp).symm



noncomputable def CompletedPoint.toPoint (cp : CompletedPoint) : Point Ed25519 :=
  if h : cp.IsValid then
    let X := cp.X.toField
    let Y := cp.Y.toField
    let Z := cp.Z.toField
    let T := cp.T.toField
    { x := X / Z
      y := Y / T
      on_curve := by
        have hz : Z ≠ 0 := h.Z_ne_zero
        have ht : T ≠ 0 := h.T_ne_zero
        have hz2 : Z^2 ≠ 0 := pow_ne_zero 2 hz
        have ht2 : T^2 ≠ 0 := pow_ne_zero 2 ht
        have hcurve : Ed25519.a * X^2 * T^2 + Y^2 * Z^2 = Z^2 * T^2 + Ed25519.d * X^2 * Y^2 := h.on_curve
        simp only [Ed25519] at hcurve ⊢
        simp only [div_pow]
        field_simp [hz2, ht2]
        linear_combination hcurve }
  else 0


theorem CompletedPoint.toPoint_of_isValid {cp : CompletedPoint} (h : cp.IsValid) :
    (cp.toPoint).x = cp.X.toField / cp.Z.toField ∧
    (cp.toPoint).y = cp.Y.toField / cp.T.toField := by
  unfold toPoint; rw [dif_pos h]; constructor <;> rfl





































@[mk_iff]
structure ProjectiveNielsPoint.IsValid (pn : ProjectiveNielsPoint) : Prop where

  Y_plus_X_bounds : ∀ i < 5, pn.Y_plus_X[i]!.val < 2 ^ 54
  Y_minus_X_bounds : ∀ i < 5, pn.Y_minus_X[i]!.val < 2 ^ 52
  Z_bounds : ∀ i < 5, pn.Z[i]!.val < 2 ^ 53
  T2d_bounds : ∀ i < 5, pn.T2d[i]!.val < 2 ^ 52

  Z_ne_zero : pn.Z.toField ≠ 0

  on_curve :
    let YpX := pn.Y_plus_X.toField; let YmX := pn.Y_minus_X.toField; let Z := pn.Z.toField
    4 * Ed25519.a * (YpX - YmX)^2 * Z^2 + 4 * (YpX + YmX)^2 * Z^2 =
      16 * Z^4 + Ed25519.d * (YpX - YmX)^2 * (YpX + YmX)^2

  T2d_relation :
    let YpX := pn.Y_plus_X.toField; let YmX := pn.Y_minus_X.toField
    let Z := pn.Z.toField; let T2d := pn.T2d.toField
    2 * Z * T2d = Ed25519.d * (YpX^2 - YmX^2)


instance ProjectiveNielsPoint.instDecidableIsValid (pn : ProjectiveNielsPoint) : Decidable pn.IsValid :=
  decidable_of_iff _ (isValid_iff pn).symm







noncomputable def ProjectiveNielsPoint.toPoint' (pn : ProjectiveNielsPoint) (h : pn.IsValid) :
    Point Ed25519 :=
  let YpX := pn.Y_plus_X.toField
  let YmX := pn.Y_minus_X.toField
  let Z := pn.Z.toField
  { x := (YpX - YmX) / (2 * Z)
    y := (YpX + YmX) / (2 * Z)
    on_curve := by
      have hz : Z ≠ 0 := h.Z_ne_zero
      have h2 : (2 : CurveField) ≠ 0 := by decide
      have h2z : 2 * Z ≠ 0 := mul_ne_zero h2 hz
      have h2z2 : (2 * Z)^2 ≠ 0 := pow_ne_zero 2 h2z
      have h2z4 : (2 * Z)^4 ≠ 0 := pow_ne_zero 4 h2z
      have hcurve := h.on_curve
      simp only [Ed25519] at hcurve ⊢
      simp only [div_pow]
      field_simp [h2z2, h2z4]
      ring_nf
      ring_nf at hcurve
      linear_combination hcurve }































noncomputable def ProjectiveNielsPoint.toPoint (pn : ProjectiveNielsPoint) : Point Ed25519 :=
  if h : pn.IsValid then pn.toPoint' h else 0





theorem ProjectiveNielsPoint.toPoint_of_isValid {pn : ProjectiveNielsPoint} (h : pn.IsValid) :
    (pn.toPoint).x = (pn.Y_plus_X.toField - pn.Y_minus_X.toField) / (2 * pn.Z.toField) ∧
    (pn.toPoint).y = (pn.Y_plus_X.toField + pn.Y_minus_X.toField) / (2 * pn.Z.toField) := by
  unfold toPoint
  rw [dif_pos h]
  simp only [toPoint']
  trivial















noncomputable instance : Coe ProjectivePoint (Point Ed25519) where
  coe p := p.toPoint


noncomputable instance : Coe CompletedPoint (Point Ed25519) where
  coe p := p.toPoint

@[simp]
theorem ProjectivePoint.toPoint_eq_coe (p : ProjectivePoint) :
  p.toPoint = ↑p := rfl

@[simp]
theorem CompletedPoint.toPoint_eq_coe (p : CompletedPoint) :
  p.toPoint = ↑p := rfl

end curve25519_dalek.backend.serial.curve_models
