/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point

namespace Montgomery

open ZMod
open WeierstrassCurve.Affine.Point

abbrev CurveField : Type := ZMod p

instance : Fact (Nat.Prime p) := ⟨PrimeCert.prime_25519''⟩

instance : NeZero (2 : CurveField) := ⟨by decide⟩

open scoped Classical in
noncomputable instance : DecidableEq CurveField := inferInstance

def Curve25519.A := (486662 : CurveField)

def MontgomeryCurveCurve25519 : WeierstrassCurve.Affine CurveField :=
  { a₁ := 0
    a₂ := Curve25519.A
    a₃ := 0
    a₄ := 1
    a₆ := 0 }

abbrev Point :=  MontgomeryCurveCurve25519.Point

def T_point : Point := .some (x := 0) (y := 0) (h := by
  constructor
  · norm_num [MontgomeryCurveCurve25519]
  · left
    norm_num [MontgomeryCurveCurve25519, Curve25519.A])

theorem non_singular {u v : CurveField}
    (h : v ^ 2 = u ^ 3 + Curve25519.A * u ^ 2 + u) :
    v ≠ 0 ∨ 3 * u ^ 2 + 2 * Curve25519.A * u + 1 ≠ 0  := by
    by_cases hv: v =0
    · right
      simp only [hv, ne_eq, OfNat.ofNat_ne_zero, not_false_eq_true, zero_pow] at h
      have :  u ^ 3 + Curve25519.A * u ^ 2 + u = u *( u ^ 2 + Curve25519.A * u  + 1) := by ring
      rw[this] at h
      have := mul_eq_zero.mp h.symm
      rcases this with h1 | h1
      · simp[h1]
      · have : 3 * u ^ 2 + 2 * Curve25519.A * u + 1=
        3 * (u ^ 2 +  Curve25519.A * u + 1) - Curve25519.A * u -2 := by ring
        rw[this, h1]
        simp only [mul_zero, zero_sub, ne_eq]
        intro h2
        have : Curve25519.A * u = -2 := by grind
        simp only [this] at h1
        have eq1: Curve25519.A^2 * u^2 = 4 := by grind
        have : -2 + (1:CurveField)= -1 := by ring
        rw[add_assoc, this] at h1
        have :  Curve25519.A ^ 2 * u^2 + Curve25519.A ^ 2* (-1) = 0  := by grind
        rw[eq1, Curve25519.A] at this
        revert this
        decide
    · simp[hv]

lemma nonsingular_iff (x y : CurveField) : MontgomeryCurveCurve25519.Nonsingular x y ↔ MontgomeryCurveCurve25519.Equation x y := by
  simp only [MontgomeryCurveCurve25519, WeierstrassCurve.Affine.nonsingular_iff, WeierstrassCurve.Affine.equation_iff,
    zero_mul, add_zero, one_mul, ne_eq, sub_zero, and_iff_left_iff_imp]
  intro h
  rcases non_singular h
  · right
    rename_i h1
    intro a
    apply h1
    have : (2 : CurveField) * y = 0 := by
      rw [two_mul]
      grind
    exact (mul_eq_zero.mp this).resolve_left (NeZero.ne 2)
  · left
    rename_i h1
    grind

def get_u : Point → CurveField
  | .zero => 0
  | .some (x := u) .. => u

end Montgomery
