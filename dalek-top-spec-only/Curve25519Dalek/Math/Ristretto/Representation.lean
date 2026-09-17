/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Types
import Curve25519Dalek.Funs

namespace curve25519_dalek.math

open Edwards ZMod
open Aeneas.Std Result

def invsqrt_a_minus_d : ZMod p :=
  54469307008909316920995813868745141605393597292927456921205312896311721017578

def a_val : ZMod p := -1

section PureIsogeny

lemma decompress_helper {F : Type*} [Field F] (a d s I u1 u2 v : F)
    (ha : a = -1)
    (hu1 : u1 = 1 + a * s ^ 2)
    (hu2 : u2 = 1 - a * s ^ 2)
    (hv : v = a * d * u1 ^ 2 - u2 ^ 2)
    (hI : I ^ 2 * (v * u2 ^ 2) = 1) :
    let x := 2 * s * (I * u2)
    let y := u1 * (I * (I * u2) * v)
    a * x^2 + y^2 = 1 + d * x^2 * y^2 := by
  intro x y
  have h_inv : I^2 = (v * u2^2)⁻¹ := eq_inv_of_mul_eq_one_left hI
  dsimp only [x, y]; simp only [pow_two]; ring_nf
  rw [show I^4 = (I^2)^2 by ring, show I^6 = (I^2)^3 by ring, h_inv]
  have h_denom_nz : (v * u2^2) ≠ 0 := right_ne_zero_of_mul_eq_one hI
  field_simp [h_denom_nz]; rw [div_eq_iff h_denom_nz]
  simp only [add_mul, one_mul, div_mul_cancel₀ _ h_denom_nz]
  rw [hv, hu1, hu2, ha];
  try ring

def compress_u1 (P : Point Ed25519) : ZMod p :=
  (1 + P.y) * (1 - P.y)

def compress_u2 (P : Point Ed25519) : ZMod p :=
  P.x * P.y

noncomputable def compress_invsqrt (P : Point Ed25519) : ZMod p :=
  (inv_sqrt_checked (compress_u1 P * (compress_u2 P) ^ 2)).1

noncomputable def compress_den1 (P : Point Ed25519) : ZMod p :=
  compress_invsqrt P * compress_u1 P

noncomputable def compress_den2 (P : Point Ed25519) : ZMod p :=
  compress_invsqrt P * compress_u2 P

noncomputable def compress_z_inv (P : Point Ed25519) : ZMod p :=
  compress_den1 P * compress_den2 P * (P.x * P.y)

noncomputable def compress_rotate (P : Point Ed25519) : Bool :=
  is_negative (P.x * P.y * compress_z_inv P)

noncomputable def compress_x_prime (P : Point Ed25519) : ZMod p :=
  if compress_rotate P then P.y * sqrt_m1 else P.x

noncomputable def compress_y_prime (P : Point Ed25519) : ZMod p :=
  if compress_rotate P then P.x * sqrt_m1 else P.y

noncomputable def compress_den_inv (P : Point Ed25519) : ZMod p :=
  if compress_rotate P then compress_den1 P * invsqrt_a_minus_d else compress_den2 P

noncomputable def compress_y_final (P : Point Ed25519) : ZMod p :=
  if is_negative (compress_x_prime P * compress_z_inv P)
  then -(compress_y_prime P)
  else compress_y_prime P

noncomputable def compress_s (P : Point Ed25519) : ZMod p :=
  abs_edwards (compress_den_inv P * (1 - compress_y_final P))

noncomputable def compress_pure (P : Point Ed25519) : Nat :=
  (compress_s P).val

end PureIsogeny

end curve25519_dalek.math

namespace curve25519_dalek.ristretto
open curve25519_dalek.edwards Edwards
open curve25519_dalek.math

def IsEven (P : Point Ed25519) : Prop :=
  IsSquare (1 - P.y^2)

def RistrettoPoint.IsValid (r : RistrettoPoint) : Prop :=

  EdwardsPoint.IsValid r ∧

  let Y := r.Y.toField
  let Z := r.Z.toField
  IsSquare (Z^2 - Y^2)

def RistrettoPoint.toPoint (r : RistrettoPoint) : Point Ed25519 :=
  EdwardsPoint.toPoint r

def decompress_step1 (c : CompressedRistretto) : Option (ZMod p) :=
  let s_int := U8x32_as_Nat c

  if s_int >= p || s_int % 2 != 0 then
    none
  else
    some (s_int : ZMod p)

noncomputable def decompress_step2 (s : ZMod p) : Option (Point Ed25519) :=

  let u1 := 1 + a_val * s^2
  let u2 := 1 - a_val * s^2
  let v := a_val * d * u1^2 - u2^2

  let arg := v * u2^2
  match h_call : inv_sqrt_checked arg with
  | (I, was_square) =>

    let Dx := I * u2
    let Dy := I * Dx * v

    let x := abs_edwards (2 * s * Dx)
    let y := u1 * Dy

    let t := x * y
    if h_invalid : !was_square || is_negative t || (y == 0) then
      none
    else

      some { x := x, y := y, on_curve := by

              replace h_invalid := Bool.eq_false_iff.mpr h_invalid
              rw [Bool.or_eq_false_iff, Bool.or_eq_false_iff] at h_invalid
              obtain ⟨⟨h_sq_not, h_neg_false⟩, h_y_eq_false⟩ := h_invalid
              simp only [Bool.not_eq_eq_eq_not, Bool.not_false] at h_sq_not
              have h_I_sq_mul : I^2 * (v * u2^2) = 1 := by
                apply inv_sqrt_checked_spec arg
                · exact h_call
                · exact h_sq_not
                ·
                  intro h_zero
                  rw [h_zero] at h_call
                  rw [inv_sqrt_checked_zero] at h_call; simp only [Prod.mk.injEq,
                    Bool.false_eq] at h_call
                  exact absurd h_call.2 (by rw [h_sq_not]; decide)
              let x_raw := 2 * s * Dx
              have h_curve_raw : a_val * x_raw^2 + y^2 = 1 + d * x_raw^2 * y^2 := by
                dsimp only [y, Dy, Dx, x_raw]
                apply decompress_helper a_val d s I u1 u2 v
                <;> try rw [a_val];
                <;> try rfl
                exact h_I_sq_mul
              have h_x_sq : x^2 = x_raw^2 := by
                dsimp only [x]
                exact abs_edwards_sq (2 * s * Dx)
              rw [h_x_sq]
              exact h_curve_raw
           }

noncomputable def decompress_pure (c : CompressedRistretto) : Option (Point Ed25519) :=
  (decompress_step1 c).bind decompress_step2

def CompressedRistretto.IsValid (c : CompressedRistretto) : Prop :=
  ∃ (pt : Point Ed25519),
    decompress_pure c = some pt

end curve25519_dalek.ristretto

namespace curve25519_dalek.math

open Edwards ZMod ristretto

section ElligatorMap

def elligator_r (r0 : ZMod p) : ZMod p :=
  sqrt_m1 * r0 ^ 2

def elligator_Ns (r0 : ZMod p) : ZMod p :=
  (elligator_r r0 + 1) * (1 - d ^ 2)

def elligator_D (r0 : ZMod p) : ZMod p :=
  -(1 + d * elligator_r r0) * (elligator_r r0 + d)

def elligator_ratio (r0 : ZMod p) : ZMod p :=
  elligator_Ns r0 * (elligator_D r0)⁻¹

def elligator_is_square (r0 : ZMod p) : Prop :=
  ∃ x : ZMod p, x ^ 2 * elligator_D r0 = elligator_Ns r0

instance instDecidableElligatorIsSquare (r0 : ZMod p) :
    Decidable (elligator_is_square r0) :=
  show Decidable (∃ x : ZMod p, x ^ 2 * elligator_D r0 = elligator_Ns r0) from inferInstance

noncomputable def elligator_s (r0 : ZMod p) : ZMod p :=
  if elligator_is_square r0 then
    abs_edwards (sqrt (elligator_ratio r0))
  else
    -(abs_edwards ((sqrt (sqrt_m1 * elligator_ratio r0)) * r0))

def elligator_c (r0 : ZMod p) : ZMod p :=
  if elligator_is_square r0 then -(1 : ZMod p)
  else elligator_r r0

noncomputable def elligator_Nt (r0 : ZMod p) : ZMod p :=
  elligator_c r0 * (elligator_r r0 - 1) * (d - 1) ^ 2 - elligator_D r0

noncomputable def elligator_ristretto_flavor_x (r0 : ZMod p) : ZMod p :=
  (2 * elligator_s r0 * elligator_D r0) / (elligator_Nt r0 * sqrt_ad_minus_one)

noncomputable def elligator_ristretto_flavor_y (r0 : ZMod p) : ZMod p :=
  (1 - elligator_s r0 ^ 2) / (1 + elligator_s r0 ^ 2)

noncomputable def elligator_ristretto_flavor_pure (r0 : ZMod p)
    : {P : Point Ed25519 // IsEven P} :=
  ⟨{ x := elligator_ristretto_flavor_x r0
     y := elligator_ristretto_flavor_y r0
     on_curve := by sorry },
    by
    unfold IsEven
    unfold elligator_ristretto_flavor_y
    by_cases hdenom : (1 : ZMod p) + elligator_s r0 ^ 2 = 0
    · have hzero : (1 - elligator_s r0 ^ 2) / (1 + elligator_s r0 ^ 2) = 0 := by
        rw [hdenom]; exact div_zero _
      rw [hzero]
      exact ⟨1, by ring⟩
    · exact ⟨2 * elligator_s r0 / (1 + elligator_s r0 ^ 2),
        by field_simp [hdenom]; ring⟩⟩

end ElligatorMap

end curve25519_dalek.math

namespace Edwards

open curve25519_dalek.math

end Edwards
