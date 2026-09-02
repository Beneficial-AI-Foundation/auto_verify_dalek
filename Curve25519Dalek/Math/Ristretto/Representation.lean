




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

lemma compress_s_sq (P : Point Ed25519) :
    compress_s P ^ 2 = compress_den_inv P ^ 2 * (1 - compress_y_final P) ^ 2 := by
  unfold compress_s
  rw [abs_edwards_sq]
  ring

lemma compress_z_inv_eq_one (P : Point Ed25519)
    (hI : compress_invsqrt P ^ 2 * (compress_u1 P * compress_u2 P ^ 2) = 1) :
    compress_z_inv P = 1 := by
  unfold compress_z_inv compress_den1 compress_den2
  have h_mul :
      compress_invsqrt P * compress_u1 P * (compress_invsqrt P * compress_u2 P) * (P.x * P.y) =
        compress_invsqrt P ^ 2 * (compress_u1 P * compress_u2 P ^ 2) := by
    unfold compress_u2
    ring
  simpa only [h_mul] using hI

private lemma p_sub_one_lt : p - 1 < p := by decide

private lemma iad_sq_nat :
    54469307008909316920995813868745141605393597292927456921205312896311721017578 ^ 2 *
    (57896044618658097711785492504343953926634992332820282019728792003956564819948 -
     37095705934669439343138083508754565189542113879843219016388785533085940283555) % p = 1 := by
  decide


lemma iad_sq : (invsqrt_a_minus_d : ZMod p) ^ 2 * (a_val - (↑d : ZMod p)) = 1 := by
  unfold invsqrt_a_minus_d a_val d
  have h := iad_sq_nat
  unfold p at h
  have : (((54469307008909316920995813868745141605393597292927456921205312896311721017578 : ℕ) ^ 2 *
    (57896044618658097711785492504343953926634992332820282019728792003956564819948 -
     37095705934669439343138083508754565189542113879843219016388785533085940283555) : ℤ) : ZMod p) = 1 := by
    rw [← ZMod.intCast_mod _ p]
    decide
  push_cast at this; exact this

lemma compress_den_inv_cancel (P : Point Ed25519)
    (hI : compress_invsqrt P ^ 2 * (compress_u1 P * compress_u2 P ^ 2) = 1) :
    compress_den_inv P ^ 2 * (1 - compress_y_final P ^ 2) = 1 := by
  have h_curve : P.y ^ 2 - P.x ^ 2 = 1 + (↑d : ZMod p) * P.x ^ 2 * P.y ^ 2 := by
    have := P.on_curve
    simp only [Ed25519, neg_mul, one_mul] at this
    linear_combination this
  by_cases h_rot : compress_rotate P
  · have hD : compress_den_inv P = compress_invsqrt P * compress_u1 P * invsqrt_a_minus_d := by
      unfold compress_den_inv compress_den1
      rw [if_pos h_rot]
    have h_yprime : compress_y_prime P = P.x * sqrt_m1 := by
      unfold compress_y_prime
      rw [if_pos h_rot]
    have h_yf_sq : compress_y_final P ^ 2 = -(P.x ^ 2) := by
      unfold compress_y_final
      rw [h_yprime]
      split_ifs <;> (try rw [neg_sq]) <;>
        rw [show (P.x * sqrt_m1) ^ 2 = P.x ^ 2 * sqrt_m1 ^ 2 from by ring, sqrt_m1_sq] <;> ring
    have h_factor : compress_u1 P * (1 + P.x ^ 2) =
        compress_u2 P ^ 2 * (a_val - (↑d : ZMod p)) := by
      unfold compress_u1 compress_u2 a_val
      linear_combination -h_curve
    calc compress_den_inv P ^ 2 * (1 - compress_y_final P ^ 2)
        = (compress_invsqrt P * compress_u1 P * invsqrt_a_minus_d) ^ 2 * (1 + P.x ^ 2) := by
            rw [hD, h_yf_sq]
            ring
      _ = compress_invsqrt P ^ 2 * compress_u1 P *
          (compress_u1 P * (1 + P.x ^ 2)) * invsqrt_a_minus_d ^ 2 := by ring
      _ = compress_invsqrt P ^ 2 * compress_u1 P *
          (compress_u2 P ^ 2 * (a_val - ↑d)) * invsqrt_a_minus_d ^ 2 := by rw [h_factor]
      _ = (compress_invsqrt P ^ 2 * (compress_u1 P * compress_u2 P ^ 2)) *
          (invsqrt_a_minus_d ^ 2 * (a_val - ↑d)) := by ring
      _ = 1 := by
          rw [hI, iad_sq]
          simp
  · have h_rot_false : compress_rotate P = false := by
      revert h_rot
      cases compress_rotate P <;> simp
    have hD : compress_den_inv P = compress_invsqrt P * compress_u2 P := by
      unfold compress_den_inv compress_den2
      rw [h_rot_false, if_neg (by decide)]
    have h_yprime : compress_y_prime P = P.y := by
      unfold compress_y_prime
      rw [h_rot_false, if_neg (by decide)]
    have h_yf_sq : compress_y_final P ^ 2 = P.y ^ 2 := by
      unfold compress_y_final
      rw [h_yprime]
      split_ifs <;> ring
    have h_u1_eq : 1 - compress_y_final P ^ 2 = compress_u1 P := by
      rw [h_yf_sq]
      unfold compress_u1
      ring
    calc compress_den_inv P ^ 2 * (1 - compress_y_final P ^ 2)
        = (compress_invsqrt P * compress_u2 P) ^ 2 * compress_u1 P := by
            rw [hD, h_u1_eq]
      _ = compress_invsqrt P ^ 2 * (compress_u1 P * compress_u2 P ^ 2) := by ring
      _ = 1 := hI

lemma compress_x_prime_sq (P : Point Ed25519) :
    compress_x_prime P ^ 2 = if compress_rotate P then -(P.y ^ 2) else P.x ^ 2 := by
  unfold compress_x_prime
  split_ifs with h
  · rw [show (P.y * sqrt_m1) ^ 2 = P.y ^ 2 * sqrt_m1 ^ 2 from by ring, sqrt_m1_sq]
    ring
  · rfl

lemma compress_y_final_sq (P : Point Ed25519) :
    compress_y_final P ^ 2 = if compress_rotate P then -(P.x ^ 2) else P.y ^ 2 := by
  unfold compress_y_final compress_y_prime
  split_ifs <;> ring_nf <;> rw [sqrt_m1_sq] <;> ring

lemma compress_canonical_on_curve (P : Point Ed25519) :
    a_val * compress_x_prime P ^ 2 + compress_y_final P ^ 2 =
      1 + (↑d : ZMod p) * compress_x_prime P ^ 2 * compress_y_final P ^ 2 := by
  have h_curve : P.y ^ 2 - P.x ^ 2 = 1 + (↑d : ZMod p) * P.x ^ 2 * P.y ^ 2 := by
    have := P.on_curve
    simp only [Ed25519, neg_mul, one_mul] at this
    linear_combination this
  rw [compress_x_prime_sq, compress_y_final_sq]
  dsimp only [a_val]
  split_ifs <;> linear_combination h_curve

lemma compress_canonical_eq (P : Point Ed25519) :
    compress_x_prime P ^ 2 * (1 + (↑d : ZMod p) * compress_y_final P ^ 2) =
      compress_y_final P ^ 2 - 1 := by
  have h := compress_canonical_on_curve P
  dsimp only [a_val] at h
  linear_combination -h

end PureIsogeny

end curve25519_dalek.math



namespace curve25519_dalek.ristretto
open curve25519_dalek.edwards Edwards
open curve25519_dalek.math





















































































































































def IsEven (P : Point Ed25519) : Prop :=
  IsSquare (1 - P.y^2)


theorem IsEven_iff_in_doubling_image_right (P : Point Ed25519) :
    IsEven P → ∃ Q : Point Ed25519, P = Q + Q := by
  sorry


theorem IsEven_iff_in_doubling_image_left (P : Point Ed25519) :
    (∃ Q : Point Ed25519, P = Q + Q) → IsEven P := by
  intro ⟨Q, hP⟩
  rw [hP]
  unfold IsEven
  have h_double_y : (Q + Q).y = (Q.y * Q.y - Ed25519.a * Q.x * Q.x) / (1 - Ed25519.d * Q.x * Q.x * Q.y * Q.y) :=
    add_y Q Q
  have ha : Ed25519.a = -1 := rfl
  rw [ha] at h_double_y
  simp only [neg_mul, one_mul] at h_double_y
  have h_double_y' : (Q + Q).y = (Q.y^2 + Q.x^2) / (1 - Ed25519.d * Q.x * Q.x * Q.y * Q.y) := by
    convert h_double_y using 2
    ring
  rw [h_double_y']
  set x := Q.x
  set y := Q.y
  set lam := Ed25519.d * x * x * y * y with hlam
  have hcurve : Ed25519.a * x^2 + y^2 = 1 + Ed25519.d * x^2 * y^2 := Q.on_curve
  rw [ha] at hcurve
  simp only [neg_mul, one_mul] at hcurve
  have h_yx : y^2 - x^2 = 1 + lam := by linear_combination hcurve
  have h_denom_ne : 1 - lam ≠ 0 := by
    have := Ed25519.denomsNeZero Q Q
    convert this.2
  have : 1 - ((y^2 + x^2) / (1 - lam))^2 = ((1 - lam)^2 - (y^2 + x^2)^2) / (1 - lam)^2 := by
    field_simp [h_denom_ne]
  rw [this]
  have h_factor : (1 - lam)^2 - (y^2 + x^2)^2 = (1 - lam - y^2 - x^2) * (1 - lam + y^2 + x^2) := by
    ring
  have h_lam_eq : lam = y^2 - x^2 - 1 := by
    have h : y^2 - x^2 - 1 - lam = 0 := by linear_combination h_yx
    linear_combination -h
  have h1mlam : 1 - lam = 2 + x^2 - y^2 := by
    rw [h_lam_eq]
    ring
  have h_A : 1 - lam - y^2 - x^2 = 2 - 2*y^2 := by linear_combination h1mlam
  have h_B : 1 - lam + y^2 + x^2 = 2 + 2*x^2 := by linear_combination h1mlam
  rw [h_factor, h_A, h_B]
  have h_factor_simp : (2 - 2*y^2) * (2 + 2*x^2) = 4 * (1 - y^2) * (1 + x^2) := by ring
  rw [h_factor_simp]
  have h_1my : 1 - y^2 = -lam - x^2 := by linear_combination -h_yx
  rw [h_1my]
  have h_sign : 4 * (-lam - x^2) * (1 + x^2) = -4 * (lam + x^2) * (1 + x^2) := by ring
  rw [h_sign]
  have h_neg1_sq : IsSquare (-1 : CurveField) := neg_one_is_square
  have h_4_sq : IsSquare (4 : CurveField) := ⟨2, by ring⟩
  have h_neg4_sq : IsSquare (-4 : CurveField) := IsSquare.mul h_neg1_sq h_4_sq
  have h_lam_factor : lam + x^2 = x^2 * (Ed25519.d * y^2 + 1) := by
    rw [hlam]
    ring
  rw [h_lam_factor]
  have h_lam_x : lam + x^2 = y^2 - 1 := by linear_combination h_lam_eq
  have h_x2_dy : x^2 * (Ed25519.d * y^2 + 1) = y^2 - 1 := by
    calc x^2 * (Ed25519.d * y^2 + 1) = lam + x^2 := by rw [← h_lam_factor]
         _ = y^2 - 1 := h_lam_x
  rw [h_x2_dy]
  rw [h1mlam]
  have h_rw : (2 + x ^ 2 - y ^ 2) ^ 2 = (1 - lam) ^ 2 := by
    congr 1
    exact h1mlam.symm
  rw [h_rw]
  have h_num_sq : IsSquare (-4 * (y ^ 2 - 1) * (1 + x ^ 2)) := by
    rw [← h_lam_x]
    rw [h_lam_factor]
    have h_rearrange : -4 * (x ^ 2 * (Ed25519.d * y ^ 2 + 1)) * (1 + x ^ 2) =
                       -4 * (x ^ 2 * ((Ed25519.d * y ^ 2 + 1) * (1 + x ^ 2))) := by ring
    rw [h_rearrange]
    apply IsSquare.mul h_neg4_sq
    apply IsSquare.mul
    · exact ⟨x, pow_two x⟩
    · have h_expand : (Ed25519.d * y^2 + 1) * (1 + x^2) = y^2 * (1 + Ed25519.d) := by
        have h_dxy : Ed25519.d * x^2 * y^2 = y^2 - x^2 - 1 := by
          calc Ed25519.d * x^2 * y^2 = (1 + Ed25519.d * x^2 * y^2) - 1 := by ring
            _ = (-x^2 + y^2) - 1 := by rw [← hcurve]
            _ = y^2 - x^2 - 1 := by ring
        calc (Ed25519.d * y^2 + 1) * (1 + x^2)
            = Ed25519.d * y^2 + Ed25519.d * y^2 * x^2 + 1 + x^2 := by ring
          _ = Ed25519.d * y^2 + Ed25519.d * x^2 * y^2 + 1 + x^2 := by ring
          _ = Ed25519.d * y^2 + (y^2 - x^2 - 1) + 1 + x^2 := by rw [h_dxy]
          _ = Ed25519.d * y^2 + y^2 := by ring
          _ = y^2 * (Ed25519.d + 1) := by ring
          _ = y^2 * (1 + Ed25519.d) := by ring
      rw [h_expand]
      have h_one_add_d_sq : IsSquare (1 + Ed25519.d) := by
        change IsSquare ((1 + d : ℕ) : CurveField)
        have h_ne : ((1 + d : ℕ) : CurveField) ≠ 0 := by decide
        rw [← legendreSym.eq_one_iff' p h_ne]
        norm_num [d, p]
      apply IsSquare.mul
      · exact ⟨y, pow_two y⟩
      · exact h_one_add_d_sq
  obtain ⟨c, hc⟩ := h_num_sq
  use c / (1 - lam)
  field_simp [h_denom_ne, pow_ne_zero 2 h_denom_ne]
  convert hc using 1
  · ring
  · exact pow_two c


theorem IsEven_iff_in_doubling_image (P : Point Ed25519) :
    IsEven P ↔ ∃ Q : Point Ed25519, P = Q + Q := by
  constructor
  · exact IsEven_iff_in_doubling_image_right P
  · exact IsEven_iff_in_doubling_image_left P


theorem even_add_closure_Ed25519 (P Q : Point Ed25519) (hP : IsEven P) (hQ : IsEven Q) :
    IsEven (P + Q) := by
  rw [IsEven_iff_in_doubling_image] at *
  obtain ⟨P', rfl⟩ := hP
  obtain ⟨Q', rfl⟩ := hQ
  exact ⟨P' + Q', by abel⟩



theorem EdwardsPoint_IsSquare_iff_IsEven (e : EdwardsPoint) (h : e.IsValid) :
    IsSquare (e.Z.toField^2 - e.Y.toField^2) ↔ IsEven (e.toPoint) := by
  unfold IsEven
  obtain ⟨_, hy⟩ := EdwardsPoint.toPoint_of_isValid h
  rw [hy]
  have hz : e.Z.toField ≠ 0 := h.Z_ne_zero
  have hz2 : e.Z.toField^2 ≠ 0 := pow_ne_zero 2 hz
  have : 1 - (e.Y.toField / e.Z.toField)^2 = (e.Z.toField^2 - e.Y.toField^2) / e.Z.toField^2 := by
    field_simp [hz2]
  rw [this]
  constructor
  · intro ⟨w, hw⟩
    use w / e.Z.toField
    field_simp [hz2] at hw ⊢
    convert hw using 1
  · intro ⟨w, hw⟩
    use w * e.Z.toField
    field_simp [hz2] at hw ⊢
    convert hw using 1


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




lemma decompress_step2_1 (s : ZMod p) (pt : Point Ed25519)
    (h : decompress_step2 s = some pt) :
    let u1 := 1 + a_val * s ^ 2
    let u2 := 1 - a_val * s ^ 2
    let v := a_val * (d : CurveField) * u1 ^ 2 - u2 ^ 2
    let W := v * u2 ^ 2
    let I := (inv_sqrt_checked W).1
    IsSquare W ∧ W ≠ 0 ∧
    is_negative (abs_edwards (2 * s * (I * u2)) * (u1 * (I * (I * u2) * v))) = false ∧
    u1 * (I * (I * u2) * v) ≠ 0 ∧
    pt.x = abs_edwards (2 * s * (I * u2)) ∧
    pt.y = u1 * (I * (I * u2) * v) := by
  unfold decompress_step2 at h
  dsimp only at h
  split_ifs at h with h_invalid


  have h_pt := Option.some.inj h

  intro u1 u2 v W I

  replace h_invalid := Bool.eq_false_iff.mpr h_invalid
  rw [Bool.or_eq_false_iff, Bool.or_eq_false_iff] at h_invalid
  obtain ⟨⟨h_ws, h_neg⟩, h_y_eq⟩ := h_invalid
  simp only [Bool.not_eq_eq_eq_not, Bool.not_false] at h_ws

  have h_ws' : (inv_sqrt_checked W).2 = true := h_ws
  have h_neg' : is_negative (abs_edwards (2 * s * (I * u2)) *
    (u1 * (I * (I * u2) * v))) = false := h_neg
  have h_y_eq' : (u1 * (I * (I * u2) * v) == (0 : ZMod p)) = false := h_y_eq

  have h_W_ne : W ≠ 0 := by
    intro h_zero
    have : (inv_sqrt_checked W).2 = false := by
      rw [show W = (0 : ZMod p) from h_zero, inv_sqrt_checked_zero]
    rw [h_ws'] at this; exact absurd this (by decide)

  have h_sq_W : IsSquare W := by
    have h_sc : (sqrt_checked W).2 = true := by
      simpa only [← inv_sqrt_checked_snd W h_W_ne] using h_ws'
    exact (sqrt_checked_iff_isSquare W (Prod.mk.eta (p := sqrt_checked W)).symm).mp h_sc

  have h_y_ne : u1 * (I * (I * u2) * v) ≠ 0 := by
    exact beq_eq_false_iff_ne.mp h_y_eq'

  have hx : pt.x = abs_edwards (2 * s * (I * u2)) := by rw [← h_pt]
  have hy : pt.y = u1 * (I * (I * u2) * v) := by rw [← h_pt]
  exact ⟨h_sq_W, h_W_ne, h_neg', h_y_ne, hx, hy⟩






lemma decompress_step2_2 (s : ZMod p) (pt : Point Ed25519) (I : ZMod p)
    (hI : I ^ 2 * ((a_val * (d : CurveField) * (1 + a_val * s ^ 2) ^ 2 -
      (1 - a_val * s ^ 2) ^ 2) * (1 - a_val * s ^ 2) ^ 2) = 1)
    (h_neg : is_negative (pt.x * pt.y) = false)
    (h_y_ne : pt.y ≠ 0)
    (hx : pt.x = abs_edwards (2 * s * (I * (1 - a_val * s ^ 2))))
    (hy : pt.y = (1 + a_val * s ^ 2) *
      (I * (I * (1 - a_val * s ^ 2)) *
        (a_val * (d : CurveField) * (1 + a_val * s ^ 2) ^ 2 -
          (1 - a_val * s ^ 2) ^ 2))) :
    decompress_step2 s = some pt := by

  set W := (a_val * (d : CurveField) * (1 + a_val * s ^ 2) ^ 2 -
    (1 - a_val * s ^ 2) ^ 2) * (1 - a_val * s ^ 2) ^ 2

  have h_W_ne : W ≠ 0 := right_ne_zero_of_mul_eq_one hI
  have h_I_ne : I ≠ 0 := by intro h; simp only [h, ne_eq, OfNat.ofNat_ne_zero, not_false_eq_true,
    zero_pow, zero_mul, zero_ne_one] at hI
  have h_sq_W : IsSquare W := ⟨I⁻¹, by
    have : W = (I ^ 2)⁻¹ := by rw [eq_inv_of_mul_eq_one_left hI, inv_inv]
    rw [this, ← inv_pow, sq]⟩

  have h_ws : (inv_sqrt_checked W).2 = true := by
    rw [inv_sqrt_checked_snd W h_W_ne]
    exact (sqrt_checked_iff_isSquare W (Prod.mk.eta (p := sqrt_checked W)).symm).mpr h_sq_W

  have h_I'_sq : (inv_sqrt_checked W).1 ^ 2 * W = 1 :=
    inv_sqrt_checked_sq_mul W h_sq_W h_W_ne
  have h_sq_eq : I ^ 2 = (inv_sqrt_checked W).1 ^ 2 :=
    mul_right_cancel₀ h_W_ne (by rw [hI, h_I'_sq])

  have h_y_match : (1 + a_val * s ^ 2) *
      ((inv_sqrt_checked W).1 * ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2)) *
        (a_val * (d : CurveField) * (1 + a_val * s ^ 2) ^ 2 -
          (1 - a_val * s ^ 2) ^ 2)) = pt.y := by
    rw [hy]; congr 1
    have h1 : (inv_sqrt_checked W).1 * ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2)) *
      (a_val * ↑d * (1 + a_val * s ^ 2) ^ 2 - (1 - a_val * s ^ 2) ^ 2) =
      (inv_sqrt_checked W).1 ^ 2 * (1 - a_val * s ^ 2) *
      (a_val * ↑d * (1 + a_val * s ^ 2) ^ 2 - (1 - a_val * s ^ 2) ^ 2) := by ring
    have h2 : I * (I * (1 - a_val * s ^ 2)) *
      (a_val * ↑d * (1 + a_val * s ^ 2) ^ 2 - (1 - a_val * s ^ 2) ^ 2) =
      I ^ 2 * (1 - a_val * s ^ 2) *
      (a_val * ↑d * (1 + a_val * s ^ 2) ^ 2 - (1 - a_val * s ^ 2) ^ 2) := by ring
    rw [h1, h2, h_sq_eq]

  have h_x_match : abs_edwards (2 * s * ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2))) =
      pt.x := by
    rw [hx]
    have h_sq_x : (2 * s * ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2))) ^ 2 =
        (2 * s * (I * (1 - a_val * s ^ 2))) ^ 2 := by
      have h1 : (2 * s * ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2))) ^ 2 =
        4 * s ^ 2 * (inv_sqrt_checked W).1 ^ 2 * (1 - a_val * s ^ 2) ^ 2 := by ring
      have h2 : (2 * s * (I * (1 - a_val * s ^ 2))) ^ 2 =
        4 * s ^ 2 * I ^ 2 * (1 - a_val * s ^ 2) ^ 2 := by ring
      rw [h1, h2, h_sq_eq]
    rcases sq_eq_sq_iff_eq_or_eq_neg.mp h_sq_x with h_eq | h_neg_eq
    · rw [h_eq]
    · simpa only [h_neg_eq] using abs_edwards_neg (2 * s * (I * (1 - a_val * s ^ 2)))


  have h_neg_match : is_negative (abs_edwards (2 * s *
      ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2))) *
    ((1 + a_val * s ^ 2) * ((inv_sqrt_checked W).1 *
      ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2)) *
      (a_val * (d : CurveField) * (1 + a_val * s ^ 2) ^ 2 -
        (1 - a_val * s ^ 2) ^ 2)))) = false := by
    simpa only [h_x_match, h_y_match] using h_neg
  have h_y_ne_match : ((1 + a_val * s ^ 2) * ((inv_sqrt_checked W).1 *
      ((inv_sqrt_checked W).1 * (1 - a_val * s ^ 2)) *
      (a_val * (d : CurveField) * (1 + a_val * s ^ 2) ^ 2 -
        (1 - a_val * s ^ 2) ^ 2)) == (0 : ZMod p)) = false := by
    rw [h_y_match]
    exact beq_eq_false_iff_ne.mpr h_y_ne

  unfold decompress_step2; dsimp only
  split_ifs with h_cond
  ·

    simp_all only [ne_eq, mul_eq_zero, false_or, not_or, OfNat.ofNat_ne_zero, not_false_eq_true, pow_eq_zero_iff,
      or_self, mul_eq_mul_left_iff, mul_eq_mul_right_iff, or_false, beq_eq_false_iff_ne, Bool.not_true, Bool.or_self,
      Bool.false_or, beq_iff_eq, W]
  ·
    congr 1; ext
    · exact h_x_match
    · exact h_y_match


lemma decompress_step2_zero : ∃ pt, decompress_step2 0 = some pt := by
  have h_on_curve : Ed25519.a * (0 : ZMod p) ^ 2 + 1 ^ 2 =
      1 + Ed25519.d * 0 ^ 2 * 1 ^ 2 := by ring
  let pt : Point Ed25519 := ⟨0, 1, h_on_curve⟩
  have h_W_simp : (a_val * (↑d : CurveField) * (1 + a_val * (0 : ZMod p) ^ 2) ^ 2 -
      (1 - a_val * (0 : ZMod p) ^ 2) ^ 2) * (1 - a_val * (0 : ZMod p) ^ 2) ^ 2 =
      a_val - (↑d : ZMod p) := by
    unfold a_val
    ring
  have h_hy : pt.y = (1 + a_val * (0 : ZMod p) ^ 2) *
      (invsqrt_a_minus_d * (invsqrt_a_minus_d * (1 - a_val * (0 : ZMod p) ^ 2)) *
        (a_val * (↑d : CurveField) * (1 + a_val * (0 : ZMod p) ^ 2) ^ 2 -
          (1 - a_val * (0 : ZMod p) ^ 2) ^ 2)) := by
    change (1 : ZMod p) = _
    have h_ring : (1 + a_val * (0 : ZMod p) ^ 2) *
        (invsqrt_a_minus_d * (invsqrt_a_minus_d * (1 - a_val * (0 : ZMod p) ^ 2)) *
          (a_val * (↑d : CurveField) * (1 + a_val * (0 : ZMod p) ^ 2) ^ 2 -
            (1 - a_val * (0 : ZMod p) ^ 2) ^ 2)) =
        invsqrt_a_minus_d ^ 2 * (a_val - ↑d) := by
      unfold a_val
      ring
    rw [h_ring]
    exact iad_sq.symm
  exact ⟨pt, decompress_step2_2 0 pt invsqrt_a_minus_d
    (by rw [h_W_simp]; exact iad_sq)
    (by change is_negative (0 * 1 : ZMod p) = false; simp [is_negative])
    one_ne_zero
    (by
      change (0 : ZMod p) = abs_edwards (2 * 0 * (invsqrt_a_minus_d * (1 - a_val * 0 ^ 2)))
      simp [abs_edwards, is_negative])
    h_hy⟩

set_option maxHeartbeats 400000 in


lemma decompress_step2_compress_s (P : Point Ed25519) (heven : IsEven P) :
    ∃ pt, decompress_step2 (compress_s P) = some pt := by
  by_cases h_degen : compress_u1 P * compress_u2 P ^ 2 = 0
  ·
    have h_I_zero : compress_invsqrt P = 0 := by
      unfold compress_invsqrt; rw [h_degen, inv_sqrt_checked_zero]
    have h_den1_zero : compress_den1 P = 0 := by unfold compress_den1; rw [h_I_zero, zero_mul]
    have h_den2_zero : compress_den2 P = 0 := by unfold compress_den2; rw [h_I_zero, zero_mul]
    have h_zinv_zero : compress_z_inv P = 0 := by
      unfold compress_z_inv; rw [h_den1_zero, zero_mul, zero_mul]
    have h_no_rotate : compress_rotate P = false := by
      unfold compress_rotate; rw [h_zinv_zero, mul_zero]; rfl
    have h_deninv_zero : compress_den_inv P = 0 := by
      unfold compress_den_inv; rw [h_no_rotate, if_neg (by decide)]; exact h_den2_zero
    have h_s_zero : compress_s P = 0 := by
      unfold compress_s; rw [h_deninv_zero, zero_mul]
      unfold abs_edwards is_negative; simp
    rw [h_s_zero]
    exact decompress_step2_zero
  ·

    have h_u1_ne : compress_u1 P ≠ 0 := left_ne_zero_of_mul h_degen
    have h_u2_ne : compress_u2 P ≠ 0 := by
      intro h; exact h_degen (by rw [h, sq, mul_zero, mul_zero])

    have h_u1_sq : IsSquare (compress_u1 P) := by
      have : compress_u1 P = 1 - P.y ^ 2 := by unfold compress_u1; ring
      simpa only [this] using heven
    have h_arg_sq : IsSquare (compress_u1 P * compress_u2 P ^ 2) :=
      h_u1_sq.mul ⟨compress_u2 P, (sq _)⟩

    have h_I_sq : compress_invsqrt P ^ 2 * (compress_u1 P * compress_u2 P ^ 2) = 1 := by
      unfold compress_invsqrt; exact inv_sqrt_checked_sq_mul _ h_arg_sq h_degen

    have h_den_cancel : compress_den_inv P ^ 2 * (1 - compress_y_final P ^ 2) = 1 :=
      compress_den_inv_cancel P h_I_sq

    have h_sigma_sq := compress_s_sq P
    have h_mobius : compress_s P ^ 2 * (1 + compress_y_final P) = 1 - compress_y_final P := by
      rw [h_sigma_sq]
      have : compress_den_inv P ^ 2 * (1 - compress_y_final P) ^ 2 * (1 + compress_y_final P) =
          compress_den_inv P ^ 2 * (1 - compress_y_final P ^ 2) * (1 - compress_y_final P) := by ring
      rw [this, h_den_cancel]; ring

    set σ := compress_s P
    set y_f := compress_y_final P with hyf_def
    set x' := compress_x_prime P with hx'_def

    have h_1_sub_yf_sq_ne : (1 : ZMod p) - y_f ^ 2 ≠ 0 :=
      right_ne_zero_of_mul_eq_one h_den_cancel
    have h_1_sub_yf_sq_fact : (1 : ZMod p) - y_f ^ 2 = (1 - y_f) * (1 + y_f) := by
      ring
    have h_1_plus_yf_ne : (1 : ZMod p) + y_f ≠ 0 := by
      intro h; apply h_1_sub_yf_sq_ne
      rw [h_1_sub_yf_sq_fact, h, mul_zero]
    have h_1_sub_yf_ne : (1 : ZMod p) - y_f ≠ 0 := by
      intro h; apply h_1_sub_yf_sq_ne
      rw [h_1_sub_yf_sq_fact, h, zero_mul]
    have h_den_inv_ne : compress_den_inv P ≠ 0 := by
      intro h; rw [h, zero_pow (by omega : 2 ≠ 0), zero_mul] at h_den_cancel
      exact zero_ne_one h_den_cancel
    have h_sigma_ne : σ ≠ 0 := by
      intro h; rw [h, zero_pow (by omega : 2 ≠ 0)] at h_sigma_sq
      exact (mul_ne_zero (pow_ne_zero 2 h_den_inv_ne) (pow_ne_zero 2 h_1_sub_yf_ne))
        h_sigma_sq.symm
    have h_xy_ne : P.x * P.y ≠ 0 := by
      simpa only [compress_u2] using h_u2_ne
    have h_px_ne : P.x ≠ 0 := left_ne_zero_of_mul h_xy_ne
    have h_py_ne : P.y ≠ 0 := right_ne_zero_of_mul h_xy_ne
    have h_sqrt_m1_ne : (sqrt_m1 : ZMod p) ≠ 0 := by
      intro h; have hsm := sqrt_m1_sq; rw [h, zero_pow (by omega : 2 ≠ 0)] at hsm
      exact (neg_ne_zero.mpr one_ne_zero) hsm.symm
    have h_xprime_ne : x' ≠ 0 := by
      simp only [hx'_def]; unfold compress_x_prime
      split_ifs <;> [exact mul_ne_zero h_py_ne h_sqrt_m1_ne; exact h_px_ne]

    have h_z_inv_one : compress_z_inv P = 1 := compress_z_inv_eq_one P h_I_sq

    have h_can : x' ^ 2 * (1 + ↑d * y_f ^ 2) = y_f ^ 2 - 1 := by
      simpa only [hx'_def, hyf_def] using compress_canonical_eq P

    have h_yf_ne : y_f ≠ 0 := by
      simp only [hyf_def]; unfold compress_y_final compress_y_prime
      split_ifs <;>
        [exact neg_ne_zero.mpr (mul_ne_zero h_px_ne h_sqrt_m1_ne);
         exact neg_ne_zero.mpr h_py_ne;
         exact mul_ne_zero h_px_ne h_sqrt_m1_ne;
         exact h_py_ne]

    have h_yf_u2 : y_f * (1 - a_val * σ ^ 2) = 1 + a_val * σ ^ 2 := by
      unfold a_val; linear_combination h_mobius
    have h_u2_dec_scale : (1 - a_val * σ ^ 2) * (1 + y_f) = 2 := by
      unfold a_val
      linear_combination h_mobius


    have h_xsq_v : x' ^ 2 * (a_val * ↑d * (1 + a_val * σ ^ 2) ^ 2 -
        (1 - a_val * σ ^ 2) ^ 2) = 4 * σ ^ 2 := by
      apply mul_right_cancel₀ (pow_ne_zero 2 h_1_plus_yf_ne)
      have h1 : (1 + a_val * σ ^ 2) * (1 + y_f) = 2 * y_f := by
        unfold a_val; linear_combination -h_mobius
      have h_lhs : x' ^ 2 * (a_val * ↑d * (1 + a_val * σ ^ 2) ^ 2 -
          (1 - a_val * σ ^ 2) ^ 2) * (1 + y_f) ^ 2 =
          x' ^ 2 * (a_val * ↑d * ((1 + a_val * σ ^ 2) * (1 + y_f)) ^ 2 -
          ((1 - a_val * σ ^ 2) * (1 + y_f)) ^ 2) := by ring
      rw [h_lhs, h1, h_u2_dec_scale]
      have h_rhs : 4 * σ ^ 2 * (1 + y_f) ^ 2 = 4 * (1 - y_f) * (1 + y_f) := by
        linear_combination 4 * (1 + y_f) * h_mobius
      rw [h_rhs]; unfold a_val
      linear_combination -4 * h_can

    set v_dec := a_val * ↑d * (1 + a_val * σ ^ 2) ^ 2 - (1 - a_val * σ ^ 2) ^ 2
    set W_dec := v_dec * (1 - a_val * σ ^ 2) ^ 2
    have h2_ne : (2 : ZMod p) ≠ 0 :=
      haveI : Fact (Nat.Prime 2) := ⟨by decide⟩
      ZMod.prime_ne_zero p 2 (by unfold p; norm_num)
    have h_v_ne : v_dec ≠ 0 := by
      intro h; rw [h, mul_zero] at h_xsq_v
      have : (2 * σ) ^ 2 = 0 := by linear_combination -h_xsq_v
      exact mul_ne_zero h2_ne h_sigma_ne (sq_eq_zero_iff.mp this)
    have h_u2_dec_ne : (1 - a_val * σ ^ 2 : ZMod p) ≠ 0 := by
      intro h
      rw [h, zero_mul] at h_u2_dec_scale
      exact h2_ne h_u2_dec_scale.symm
    have h_W_ne : W_dec ≠ 0 :=
      mul_ne_zero h_v_ne (pow_ne_zero 2 h_u2_dec_ne)
    have h_xsq_W : x' ^ 2 * W_dec = (2 * σ * (1 - a_val * σ ^ 2)) ^ 2 := by
      have : x' ^ 2 * W_dec = (x' ^ 2 * v_dec) * (1 - a_val * σ ^ 2) ^ 2 := by ring
      rw [this, h_xsq_v]; ring
    have h_sq_W : IsSquare W_dec := ⟨2 * σ * (1 - a_val * σ ^ 2) * x'⁻¹, by
      have hx_inv_sq : x' ^ 2 * x'⁻¹ ^ 2 = 1 := by
        rw [← mul_pow, mul_inv_cancel₀ h_xprime_ne, one_pow]
      apply mul_left_cancel₀ (pow_ne_zero 2 h_xprime_ne)
      have : x' ^ 2 * (2 * σ * (1 - a_val * σ ^ 2) * x'⁻¹ *
          (2 * σ * (1 - a_val * σ ^ 2) * x'⁻¹)) =
          (2 * σ * (1 - a_val * σ ^ 2)) ^ 2 * (x' ^ 2 * x'⁻¹ ^ 2) := by ring
      rw [this, hx_inv_sq, mul_one, ← h_xsq_W]⟩

    set I_dec := x' * (2 * σ * (1 - a_val * σ ^ 2))⁻¹
    have h_denom_ne : (2 : ZMod p) * σ * (1 - a_val * σ ^ 2) ≠ 0 :=
      mul_ne_zero (mul_ne_zero h2_ne h_sigma_ne) h_u2_dec_ne
    have h_I_W : I_dec ^ 2 * W_dec = 1 := by
      have hden := show I_dec = x' * (2 * σ * (1 - a_val * σ ^ 2))⁻¹ from rfl
      have hden_inv_sq : (2 * σ * (1 - a_val * σ ^ 2))⁻¹ ^ 2 *
          (2 * σ * (1 - a_val * σ ^ 2)) ^ 2 = 1 := by
        rw [inv_pow, inv_mul_cancel₀ (pow_ne_zero 2 h_denom_ne)]
      rw [hden, mul_pow,
          show x' ^ 2 * (2 * σ * (1 - a_val * σ ^ 2))⁻¹ ^ 2 * W_dec =
          (2 * σ * (1 - a_val * σ ^ 2))⁻¹ ^ 2 * (x' ^ 2 * W_dec) from by ring]
      rw [h_xsq_W, hden_inv_sq]

    have hx_eq : abs_edwards x' =
        abs_edwards (2 * σ * (I_dec * (1 - a_val * σ ^ 2))) := by
      apply abs_edwards_eq_of_sq_eq
      apply mul_right_cancel₀ h_v_ne
      have : (2 * σ * (I_dec * (1 - a_val * σ ^ 2))) ^ 2 * v_dec =
          4 * σ ^ 2 * (I_dec ^ 2 * W_dec) := by ring
      rw [this, h_I_W, mul_one, h_xsq_v]

    have hy_eq : y_f = (1 + a_val * σ ^ 2) *
        (I_dec * (I_dec * (1 - a_val * σ ^ 2)) * v_dec) := by
      apply mul_right_cancel₀ h_u2_dec_ne
      rw [h_yf_u2]
      have : (1 + a_val * σ ^ 2) * (I_dec * (I_dec * (1 - a_val * σ ^ 2)) * v_dec) *
          (1 - a_val * σ ^ 2) =
          (1 + a_val * σ ^ 2) * (I_dec ^ 2 * W_dec) := by ring
      rw [this, h_I_W, mul_one]

    have h_neg_ok : is_negative (abs_edwards x' * y_f) = false := by
      have h_t_eq : abs_edwards x' * y_f = x' * compress_y_prime P := by
        simp only [hyf_def, hx'_def]; unfold compress_y_final abs_edwards
        simp only [h_z_inv_one, mul_one]; split_ifs <;> ring
      rw [h_t_eq]
      by_cases h_rot : compress_rotate P
      ·
        have h_t : x' * compress_y_prime P = -(P.x * P.y * compress_z_inv P) := by
          simp only [hx'_def]; unfold compress_x_prime compress_y_prime
          rw [if_pos h_rot, if_pos h_rot, h_z_inv_one]
          rw [show P.y * sqrt_m1 * (P.x * sqrt_m1) = P.x * P.y * sqrt_m1 ^ 2 from by ring,
              sqrt_m1_sq]; ring
        rw [h_t]
        have h_neg_pos : is_negative (P.x * P.y * compress_z_inv P) = true := by
          unfold compress_rotate at h_rot; exact h_rot
        have h_xy_ne : P.x * P.y * compress_z_inv P ≠ 0 := by
          rw [h_z_inv_one, mul_one]; exact mul_ne_zero h_px_ne h_py_ne
        unfold is_negative at h_neg_pos ⊢
        rw [ZMod.neg_val, if_neg h_xy_ne]
        have := ZMod.val_lt (P.x * P.y * compress_z_inv P)
        simp only [beq_iff_eq] at h_neg_pos ⊢; simp only [beq_eq_false_iff_ne, ne_eq,
          Nat.mod_two_not_eq_one]
        have hp_odd : p % 2 = 1 := by unfold p; norm_num
        omega
      ·
        have h_rot_false : compress_rotate P = false := by
          revert h_rot; cases compress_rotate P <;> simp
        have h_t : x' * compress_y_prime P = P.x * P.y * compress_z_inv P := by
          simp only [hx'_def]; unfold compress_x_prime compress_y_prime
          rw [if_neg (by rw [h_rot_false]; decide), if_neg (by rw [h_rot_false]; decide),
              h_z_inv_one, mul_one]
        rw [h_t]; unfold compress_rotate at h_rot
        revert h_rot; cases is_negative (P.x * P.y * compress_z_inv P) <;> simp

    have h_on_curve : Ed25519.a * (abs_edwards x') ^ 2 + y_f ^ 2 =
        1 + Ed25519.d * (abs_edwards x') ^ 2 * y_f ^ 2 := by
      rw [abs_edwards_sq]
      change a_val * x' ^ 2 + y_f ^ 2 = 1 + (↑d : ZMod p) * x' ^ 2 * y_f ^ 2
      simpa only [hx'_def, hyf_def] using compress_canonical_on_curve P
    let pt_can : Point Ed25519 := ⟨abs_edwards x', y_f, h_on_curve⟩
    exact ⟨pt_can, decompress_step2_2 σ pt_can I_dec h_I_W h_neg_ok h_yf_ne hx_eq hy_eq⟩

noncomputable def decompress_pure (c : CompressedRistretto) : Option (Point Ed25519) :=
  (decompress_step1 c).bind decompress_step2










def CompressedRistretto.IsValid (c : CompressedRistretto) : Prop :=
  ∃ (pt : Point Ed25519),
    decompress_pure c = some pt





noncomputable def CompressedRistretto.toPoint (c : CompressedRistretto) : Point Ed25519 :=
  match decompress_pure c with
  | some P => P
  | none   => 0

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


@[simp]
lemma elligator_pure_val_x (r0 : ZMod p) :
    (elligator_ristretto_flavor_pure r0).val.x =
      elligator_ristretto_flavor_x r0 := rfl


@[simp]
lemma elligator_pure_val_y (r0 : ZMod p) :
    (elligator_ristretto_flavor_pure r0).val.y =
      elligator_ristretto_flavor_y r0 := rfl

end ElligatorMap

end curve25519_dalek.math





namespace Edwards

open curve25519_dalek.math

































def IsCanonicalRistrettoRep (P : Point Ed25519) : Prop :=
  let x := P.x
  let y := P.y
  let t := x * y

  (is_negative x = false) ∧

  (is_negative t = false) ∧

  (y ≠ 0)

end Edwards
