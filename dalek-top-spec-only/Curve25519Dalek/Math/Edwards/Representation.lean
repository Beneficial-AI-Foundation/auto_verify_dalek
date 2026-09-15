/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
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

  Z_ne_zero : e.Z.toField ≠ 0

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

end curve25519_dalek.edwards

namespace curve25519_dalek.edwards
open curve25519_dalek.math Edwards

end curve25519_dalek.edwards

namespace curve25519_dalek.backend.serial.curve_models
open Edwards

end curve25519_dalek.backend.serial.curve_models
