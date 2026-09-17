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
