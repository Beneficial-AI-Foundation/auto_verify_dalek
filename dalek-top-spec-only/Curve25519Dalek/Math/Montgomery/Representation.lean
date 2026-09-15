/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Types

namespace curve25519_dalek.backend.serial.curve_models

end curve25519_dalek.backend.serial.curve_models

namespace curve25519_dalek.montgomery

open curve25519_dalek curve25519_dalek.math
open Edwards

end curve25519_dalek.montgomery

namespace Montgomery

open curve25519_dalek.montgomery
open curve25519_dalek.math

section MontgomeryPoint

def v_squared (u : CurveField) : CurveField := u ^ 3 + Curve25519.A * u ^ 2 + u

noncomputable def MontgomeryPoint.u_affine_toPoint (u : CurveField) : Point:=
    match h_call: curve25519_dalek.math.sqrt_checked (v_squared u) with
    | (v, was_square) =>
    if h_invalid : !was_square || (u ==0) then
      T_point
    else
      .some (x := u) (y := v) (h := by
        replace h_invalid := Bool.eq_false_iff.mpr h_invalid
        rw [Bool.or_eq_false_iff] at h_invalid
        obtain ⟨h_sq_not,  h_y_eq_false⟩ := h_invalid
        simp only [Bool.not_eq_eq_eq_not, Bool.not_false] at h_sq_not
        have curve_eq : v ^ 2 = u ^ 3 + Curve25519.A * u ^ 2 + u := by
          apply sqrt_checked_spec (v_squared u)
          · exact h_call
          · exact h_sq_not
        apply (nonsingular_iff u v).mpr
        rw[WeierstrassCurve.Affine.equation_iff]
        simp only [MontgomeryCurveCurve25519]
        simp only[curve_eq ]
        ring
     )

noncomputable def MontgomeryPoint.mkPoint (m : MontgomeryPoint) : Point:=
    MontgomeryPoint.u_affine_toPoint  (((U8x32_as_Nat m) % 2 ^255):ℕ )

end MontgomeryPoint

section fromEdwards
open curve25519_dalek.montgomery
open curve25519_dalek.edwards

lemma d_eq : (Edwards.Ed25519.d : CurveField)= -121665/ 121666 := by
  have hd: Edwards.Ed25519.d = d := by decide
  rw[hd]
  have : (121666 : CurveField)≠ 0 := by decide
  field_simp[this]
  decide

lemma a_plus_d : (Edwards.Ed25519.a : CurveField) + Edwards.Ed25519.d = - 243331/121666 := by
  have ha: Edwards.Ed25519.a = -1 := by rfl
  rw[ha, d_eq]
  have : (121666 : CurveField)≠ 0 := by decide
  field_simp[this]
  decide

lemma a_sub_d : (Edwards.Ed25519.a : CurveField) - Edwards.Ed25519.d = - 1/121666 := by
  have ha: Edwards.Ed25519.a = -1 := by rfl
  rw[ha, d_eq]
  have : (121666 : CurveField)≠ 0 := by decide
  field_simp[this]
  decide

lemma adA : 2 * ((Edwards.Ed25519.a : CurveField) + Edwards.Ed25519.d) /(Edwards.Ed25519.a - Edwards.Ed25519.d) = Curve25519.A := by
  rw[a_plus_d, a_sub_d]
  have : (121666 : CurveField)≠ 0 := by decide
  field_simp[this]
  decide

lemma adB : (4 / ((Edwards.Ed25519.a : CurveField) - Edwards.Ed25519.d)) = - 486664 := by
  rw[ a_sub_d]
  have : (121666 : CurveField)≠ 0 := by decide
  field_simp[this]
  decide

lemma B_d_relation : IsSquare (4 / ((Edwards.Ed25519.a : CurveField) - Edwards.Ed25519.d)) := by
  rw[adB]
  apply ((@legendreSym.eq_one_iff p _ (-486664)) (by decide)).mp
  norm_num [p]

noncomputable def Curve25519.roots_B : CurveField :=
  Classical.choose B_d_relation

lemma pow2_roots_B : Curve25519.roots_B ^ 2 = 4 / ((Edwards.Ed25519.a : CurveField) - Edwards.Ed25519.d) := by
  classical
  unfold Curve25519.roots_B
  have :=B_d_relation
  unfold IsSquare at this
  simpa [pow_two] using (Classical.choose_spec this).symm

lemma montgomery_edwards_inverse {y : CurveField} (hy1 : y ≠ 1) :    let u := (1 + y) / (1 - y)
    y = (u - 1) / (u + 1) := by
  intro u
  have num_eq : u - 1 = (1 + y - (1 - y)) / (1 - y) := by
    field_simp [hy1]
    grind
  have num_simplified : u - 1 = (2 * y) / (1 - y) := by
    rw [num_eq]
    ring_nf
  have den_eq : u + 1 = (1 + y + (1 - y)) / (1 - y) := by
    field_simp [hy1]
    grind
  have den_simplified : u + 1 = 2 / (1 - y) := by
    rw [den_eq]
    ring_nf
  calc y = y := rfl
    _ = (2 * y) / 2 := by  field_simp
    _ = (2 * y) / (1 - y) * (1 - y) / 2 := by field_simp [hy1]; grind
    _ = (u - 1) / (u + 1) := by
        rw [← num_simplified]
        field_simp [hy1]
        have h_u_plus_1 : u + 1 ≠ 0 := by
          rw [den_simplified]
          field_simp [hy1]
          ring_nf
          simp only [ne_eq, mul_eq_zero, inv_eq_zero, not_or]
          grind
        field_simp [h_u_plus_1]
        grind

theorem on_curves_M (e : Edwards.Point Edwards.Ed25519)
 (hy : e.y ≠ 1)
 (hx : e.x ≠ 0) :
  let u :=(1 + e.y) / (1 - e.y)
  let v := (1 + e.y) / ((1 - e.y) * e.x)
  let A := 2 * ((Edwards.Ed25519.a : CurveField) + Edwards.Ed25519.d) /(Edwards.Ed25519.a - Edwards.Ed25519.d)
  let B := 4 / ((Edwards.Ed25519.a : CurveField) - Edwards.Ed25519.d)
  B* v^2 = u ^ 3 + A * u ^ 2 + u  := by
  have eq:= e.on_curve
  have huy:= montgomery_edwards_inverse hy
  simp only at eq
  set u :=(1 + e.y) / (1 - e.y) with hu
  set v := (1 + e.y) / ((1 - e.y) * e.x) with hv
  have h1 : (1 - e.y) ≠ 0 := by grind
  have h2 : (1 + e.y) ≠ 0 := by
    intro h2
    have : e.y=-1 := by grind
    simp only [this, even_two, Even.neg_pow, one_pow, mul_one] at eq
    have : Edwards.Ed25519.a * e.x ^ 2  =  Edwards.Ed25519.d * e.x ^ 2 := by grind
    have : (Edwards.Ed25519.a  - Edwards.Ed25519.d) * e.x^2 =0 := by grind
    simp only [mul_eq_zero, ne_eq, OfNat.ofNat_ne_zero, not_false_eq_true, pow_eq_zero_iff, hx, or_false] at this
    revert this
    decide
  have hxv: e.x = u / v := by
    rw [hu, hv]
    field_simp [h1, h2, hx]
  simp only at huy
  rw[huy, hxv] at eq
  have nonv: v ≠ 0 := by
    rw[hv]
    intro h
    apply h2
    grind
  have nonu: u ≠ 0 := by
    rw[hu]
    intro h
    apply h2
    grind
  have nonu1: u +1 ≠ 0 := by
    rw[hu]
    intro h
    field_simp at h
    ring_nf at h
    grind
  field_simp at eq
  have ha: Edwards.Ed25519.a = -1 := by rfl
  have hd: Edwards.Ed25519.d = d := by rfl
  have :
  v ^ 2 * (u + 1) ^ 2 -  v ^ 2 * (u - 1) ^ 2 =  Edwards.Ed25519.a * u ^ 2 * (u + 1) ^ 2  - u ^ 2 * (u - 1) ^ 2 * Edwards.Ed25519.d:= by grind
  have : v ^ 2 * ((u + 1) ^ 2 -  (u - 1) ^ 2) =  Edwards.Ed25519.a * u ^ 2 * (u + 1) ^ 2  - u ^ 2 * (u - 1) ^ 2 * Edwards.Ed25519.d:= by grind
  have : 4 * u * v ^ 2  =  Edwards.Ed25519.a * u ^ 2 * (u + 1) ^ 2  - u ^ 2 * (u - 1) ^ 2 * Edwards.Ed25519.d := by grind
  have : 4 * u * v ^ 2  =  u^2 *(Edwards.Ed25519.a *  (u + 1) ^ 2  - (u - 1) ^ 2 * Edwards.Ed25519.d) := by grind
  have : 4  * v ^ 2  =  u *(Edwards.Ed25519.a *  (u + 1) ^ 2  - (u - 1) ^ 2 * Edwards.Ed25519.d) := by grind
  rw[ha, hd] at this
  rw[ha, hd]
  have dplus: (-1: CurveField) -d  ≠ 0 := by decide
  have : 4  * v ^ 2  =  - u * ( (d+1)*u ^ 2  - 2*(d-1)* u + d +1) := by
    rw[this]
    ring_nf
  field_simp
  rw[this]
  ring_nf

theorem on_MontgomeryCurves (e : Edwards.Point Edwards.Ed25519)
 (hy : e.y ≠ 1)
 (hx : e.x ≠ 0) :
  let u :=(1 + e.y) / (1 - e.y)
  let v := Curve25519.roots_B  * (1 + e.y) / ((1 - e.y) * e.x)
  v^2 = u ^ 3 + Curve25519.A * u ^ 2 + u  := by
  have := on_curves_M e hy hx
  simp_all only [ne_eq, adA]
  rw[← this, ← pow2_roots_B]
  grind

theorem nonsingular_on_curves_M (e : Edwards.Point Edwards.Ed25519) (hy : e.y ≠ 1)
 (hx : e.x ≠ 0) :
  let u := (1 + e.y) / (1 - e.y)
  let v := Curve25519.roots_B * (1 + e.y) / ((1 - e.y) * e.x)
  MontgomeryCurveCurve25519.Nonsingular u v  := by
  rw[Montgomery.nonsingular_iff, WeierstrassCurve.Affine.equation_iff, MontgomeryCurveCurve25519]
  have := on_MontgomeryCurves e hy hx
  simp_all only [ne_eq, zero_mul, add_zero, one_mul]

noncomputable def fromEdwards : Edwards.Point Edwards.Ed25519 → Point
  | e =>
    if hy: e.y = 1 then
     0
     else
     if hx: e.x =0 ∧ e.y = -1 then
      T_point
     else
      let u:= (1 + e.y) / (1 - e.y)
      let v := Curve25519.roots_B  * (1 + e.y) / ((1 - e.y) * e.x)
      .some (x := u) (y := v) (h:= by
      apply nonsingular_on_curves_M e hy
      have : e.x ≠  0 ∨  e.y ≠  -1 := by
       grind
      rcases this
      · simp_all only [false_and, not_false_eq_true, ne_eq]
      · intro h
        have := e.on_curve
        simp only [h, ne_eq, OfNat.ofNat_ne_zero, not_false_eq_true, zero_pow, mul_zero, zero_add, zero_mul, add_zero,
          sq_eq_one_iff, hy, false_or] at this
        simp_all only [and_self, not_true_eq_false]
       )

end fromEdwards

section toEdwards
open curve25519_dalek.math

end toEdwards

end Montgomery
