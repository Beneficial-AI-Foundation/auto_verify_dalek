/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Math.Basic

import Mathlib.Algebra.Field.ZMod
import Mathlib.NumberTheory.LegendreSymbol.Basic
import Mathlib.Tactic.NormNum.LegendreSymbol
import Mathlib.Tactic.LinearCombination
import PrimeCert.PrimeList

namespace Edwards

open ZMod

instance : NeZero (2 : CurveField) := ⟨by decide⟩

structure EdwardsCurve (F : Type) where
  a : F
  d : F

def Ed25519 : EdwardsCurve CurveField := {
  a := -1,
  d := (d : CurveField)
}

lemma d_not_square : ¬IsSquare Ed25519.d := by
  apply (legendreSym.eq_neg_one_iff' p).mp
  norm_num [d, p]

structure Point {F : Type} [Mul F] [Add F] [Pow F ℕ] [One F] (C : EdwardsCurve F) where
  x : F
  y : F
  on_curve : C.a * x^2 + y^2 = 1 + C.d * x^2 * y^2 := by grind

instance : Inhabited (Point Ed25519) := ⟨{ x := 0, y := 1}⟩

lemma neg_one_is_square : IsSquare (-1 : CurveField) := by
  apply ZMod.exists_sq_eq_neg_one_iff.mpr; decide

variable {F : Type} [Field F]

section Completeness
variable [NeZero (2 : F)]

theorem complete_addition_denominators_ne_zero
    (C : EdwardsCurve F) (ha : IsSquare C.a) (hd : ¬IsSquare C.d) (p1 p2 : Point C) :
    let lam := C.d * p1.x * p2.x * p1.y * p2.y
    (1 + lam ≠ 0) ∧ (1 - lam ≠ 0) := by

  sorry

theorem Ed25519.denomsNeZero (p1 p2 : Point Ed25519) :
    let lam := Ed25519.d * p1.x * p2.x * p1.y * p2.y
    (1 + lam ≠ 0) ∧ (1 - lam ≠ 0) :=
  complete_addition_denominators_ne_zero Ed25519 neg_one_is_square d_not_square p1 p2

def add_coords (C : EdwardsCurve F) (p1 p2 : F × F) : F × F :=
  let (x₁, y₁) := p1
  let (x₂, y₂) := p2
  let lambda_val := C.d * x₁ * x₂ * y₁ * y₂
  ( (x₁ * y₂ + y₁ * x₂) / (1 + lambda_val), (y₁ * y₂ - C.a * x₁ * x₂) / (1 - lambda_val) )

omit [NeZero (2 : F)] in

theorem add_closure (C : EdwardsCurve F) (p1 p2 : Point C)
    (h : let lam := C.d * p1.x * p2.x * p1.y * p2.y; (1 + lam ≠ 0) ∧ (1 - lam ≠ 0)) :
    let (x, y) := add_coords C (p1.x, p1.y) (p2.x, p2.y)
    C.a * x^2 + y^2 = 1 + C.d * x^2 * y^2 := by
  set x₁ := p1.x; set y₁ := p1.y
  set x₂ := p2.x; set y₂ := p2.y
  suffices C.a * (x₁ * y₂ + y₁ * x₂)^2 * (1 - x₁ * y₂ * y₁ * x₂ * C.d)^2 +
      (1 + x₁ * y₂ * y₁ * x₂ * C.d)^2 * (y₂ * y₁ - C.a * x₁ * x₂)^2 =
      (1 + x₁ * y₂ * y₁ * x₂ * C.d)^2 * (1 - x₁ * y₂ * y₁ * x₂ * C.d)^2 +
      (x₁ * y₂ + y₁ * x₂)^2 * C.d * (y₂ * y₁ - C.a * x₁ * x₂)^2 by
    have : 1 + x₁ * y₂ * y₁ * x₂ * C.d ≠ 0 := by grind
    have : 1 - x₁ * y₂ * y₁ * x₂ * C.d ≠ 0 := by grind
    unfold add_coords
    field_simp; assumption
  rw [← sub_eq_zero]

  let A := C.a * x₁^2 + y₁^2 - (1 + C.d * x₁^2 * y₁^2)
  let B := C.a * x₂^2 + y₂^2 - (1 + C.d * x₂^2 * y₂^2)
  have hA : A = 0 := by linear_combination p1.on_curve
  have hB : B = 0 := by linear_combination p2.on_curve
  let P := (C.a * x₂^2 + y₂^2) + (-C.d * x₂^2 * y₂^2) + (-C.d * x₂^2 * y₁^2 * y₂^2) +
    (-C.a * x₁^2 * x₂^2 * y₂^2 * C.d) + (x₁^2 * y₁^2 * x₂^2 * y₂^4 * C.d^2) +
    (-x₁^2 * y₁^2 * x₂^2 * y₂^2 * C.d^2) + (C.a * x₁^2 * x₂^4 * y₁^2 * y₂^2 * C.d^2)
  let Q := 1 + (-x₁^2 * y₁^2 * y₂^2 * C.d) + (-C.a * x₁^2 * x₂^2 * y₁^2 * C.d) +
    (x₁^4 * x₂^2 * y₁^4 * y₂^2 * C.d^3)
  calc _ = P * A + Q * B := by grind
    _ = P * 0 + Q * 0 := by rw [hA, hB]
    _ = 0 := by ring

end Completeness

theorem add_closure_Ed25519 (p1 p2 : Point Ed25519) :
    let (x, y) := add_coords Ed25519 (p1.x, p1.y) (p2.x, p2.y)
    Ed25519.a * x^2 + y^2 = 1 + Ed25519.d * x^2 * y^2 :=
  add_closure Ed25519 p1 p2 (Ed25519.denomsNeZero p1 p2)

instance : Add (Point Ed25519) where
  add p1 p2 :=
  let coords := add_coords Ed25519 (p1.x, p1.y) (p2.x, p2.y)
  { x := coords.1
    y := coords.2
    on_curve := add_closure_Ed25519 p1 p2 }

instance : Zero (Point Ed25519) where
  zero := { x := 0, y := 1 }

def nsmul_Ed25519 (n : ℕ) (p : Point Ed25519) : Point Ed25519 :=
  match n with
  | 0 => 0
  | n + 1 => p + (nsmul_Ed25519 n p)

instance : SMul ℕ (Point Ed25519) := ⟨nsmul_Ed25519⟩

end Edwards
