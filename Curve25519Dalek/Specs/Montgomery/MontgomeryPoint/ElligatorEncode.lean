




import Curve25519Dalek.Funs
import Curve25519Dalek.FunsExternal
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi
import Curve25519Dalek.Specs.Field.FieldElement51.Invert
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square2
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Neg
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalSelect
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalAssign
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ZERO
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.MONTGOMERY_A
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.MONTGOMERY_A_NEG















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.backend.serial.u64.constants
open curve25519_dalek.field.FieldElement51
namespace curve25519_dalek.montgomery




























































private theorem ne_zero_iff_eq_one (p1 : subtle.Choice) (hp1 : ¬p1 = Choice.zero) :
    p1 = Choice.one := by
  obtain h | h := p1.valid
  · exfalso; apply hp1; cases p1; simpa [Choice.zero]
  · cases p1; simpa [Choice.one]

private theorem modEq_zero_iff (a n : ℕ) : a ≡ 0 [MOD n] ↔  a % n = 0 := by simp [Nat.ModEq]

private theorem modEq_one_iff (a : ℕ) : a ≡ 1 [MOD p] ↔  a % p = 1 := by
  simp only [Nat.ModEq]
  have :1 % p= 1:= by unfold p; decide
  rw[this]

private theorem mod_mul_mod (a b : ℕ) : (a % p) * (b % p) ≡ a * b [MOD p] := by
 exact ((Nat.mod_modEq a p).mul_right (b % p)).trans  ((Nat.mod_modEq b p).mul_left a)

lemma ne_zero_if_eq_one (p1 : subtle.Choice) (hp1 : ¬p1 = Choice.zero) : p1.val = 1#u8 := by
  sorry

lemma nat_486662_eq_A : (486662 : ℕ) = Curve25519.A := by
  sorry

lemma curveField_486662_eq_A : (486662 : CurveField) = Curve25519.A := by
  sorry

lemma A_ne_zero : (Curve25519.A : CurveField) ≠ 0 := by
  sorry

lemma SQRT_M1_val_ne_zero : (Field51_as_Nat SQRT_M1_val) ≠ (0 : CurveField) := by
  sorry


lemma fe1_inv_of_mod_mul (fe1_val d1_val : ℕ)
    (h_nonzero : d1_val % p ≠ 0)
    (h_mul : (fe1_val % p) * (d1_val % p) % p = 1) :
    (fe1_val : CurveField) = (d1_val : CurveField)⁻¹ := by
  sorry

lemma fe1_inv_of_mod_mul' (fe1_val d1_val : ℕ)
    (h_nonzero : ¬ d1_val ≡ 0 [MOD p])
    (h_fe1_non : d1_val % p ≠ 0 → (fe1_val % p) * (d1_val % p) % p = 1) :
    (fe1_val : CurveField) = (d1_val : CurveField)⁻¹ := by
  sorry

lemma d0_eq_d_of_inv (r0 : CurveField)
    (d0 : CurveField) (hd0 : d0 = -Curve25519.A * (1 + 2 * r0 ^ 2)⁻¹)
    (d_val fe1_val d1_val A_neg_val : ℕ)
    (change_A : (A_neg_val : CurveField) = -Curve25519.A)
    (change_d_1 : (d1_val : CurveField) = 1 + 2 * r0 ^ 2)
    (hd : d_val ≡ A_neg_val * fe1_val [MOD p])
    (hfe1_inv : (fe1_val : CurveField) = (d1_val : CurveField)⁻¹) :
    d0 = (d_val : CurveField) := by
  sorry


lemma two_mul_is_square : IsSquare ((2:CurveField) *(Field51_as_Nat SQRT_M1_val)):= by
  sorry
lemma two_did_is_square : IsSquare (-(2:CurveField) /(Field51_as_Nat SQRT_M1_val)):= by
  sorry



lemma eps_zero_of_d1_zero
    (d_1_val fe1_val A_neg_val d_val inner_val eps_val : ℕ)
    (hfe1_0 : d_1_val % p = 0 → fe1_val % p = 0)
    (hd : d_val ≡ A_neg_val * fe1_val [MOD p])
    (heps : eps_val ≡ d_val * inner_val [MOD p])
    (h : d_1_val ≡ 0 [MOD p]) :
    eps_val % p = 0 := by
  sorry



lemma nqr_condition_of_nonzero
    (eps_val one_val : ℕ)
    (one_eq : one_val = 1)
    (heps_ne : eps_val % p ≠ 0)
    (h_not_sq : ¬∃ x, x ^ 2 % p = eps_val % p) :
    (eps_val % p ≠ 0 ∧
     one_val % p ≠ 0 ∧
     ¬∃ x, x ^ 2 * (one_val % p) % p = eps_val % p) := by
  sorry

lemma qr_condition_of_square
    (eps_val one_val : ℕ)
    (one_eq : one_val = 1)
    (heps_ne : eps_val % p ≠ 0)
    (sq : IsSquare ((eps_val : CurveField))) :
    (eps_val % p ≠ 0 ∧
     one_val % p ≠ 0 ∧
     ∃ x, x ^ 2 * (one_val % p) % p = eps_val % p) := by
  sorry




private lemma elligator_qr_output_eq_d0
    (d0 r0 : CurveField)
    (hd0 : d0 = -Curve25519.A * (1 + 2 * r0 ^ 2)⁻¹)
    (a_val A_neg_val fe1_val d_1_val : ℕ)
    (ha_chain : a_val ≡ A_neg_val * fe1_val [MOD p])
    (change_A : (A_neg_val : CurveField) = -Curve25519.A)
    (change_d_1 : (d_1_val : CurveField) = 1 + 2 * r0 ^ 2)
    (hfe1_non : d_1_val % p ≠ 0 → (fe1_val % p) * (d_1_val % p) % p = 1)
    (hfe1_0 : d_1_val % p = 0 → fe1_val % p = 0) :
    (a_val : CurveField) = d0 := by
  rw[lift_mod_eq_iff] at ha_chain
  rw[hd0, ha_chain]
  simp only [Nat.cast_mul, change_A, neg_mul, ← change_d_1, neg_inj, mul_eq_mul_left_iff, A_ne_zero, or_false]
  by_cases h: (d_1_val) ≡ 0 [MOD p]
  · simp only [← modEq_zero_iff] at hfe1_0
    have := hfe1_0 h
    rw[lift_mod_eq_iff] at h
    simp only [h, Nat.cast_zero, inv_zero]
    rw[lift_mod_eq_iff] at this
    exact this
  · exact fe1_inv_of_mod_mul' fe1_val d_1_val h hfe1_non


private lemma elligator_nqr_neg_sum_eq
    (d0 r0 : CurveField)
    (hd0 : d0 = -Curve25519.A * (1 + 2 * r0 ^ 2)⁻¹)
    (d_val A1_val A_neg_val fe1_val d_1_val : ℕ)
    (hA : A1_val = 486662)
    (hd : d_val ≡ A_neg_val * fe1_val [MOD p])
    (change_A : (A_neg_val : CurveField) = -Curve25519.A)
    (change_d_1 : (d_1_val : CurveField) = 1 + 2 * r0 ^ 2)
    (hfe1_non : d_1_val % p ≠ 0 → (fe1_val % p) * (d_1_val % p) % p = 1)
    (hfe1_0 : d_1_val % p = 0 → fe1_val % p = 0) :
    -((d_val : CurveField) + (A1_val : CurveField)) = -d0 - Curve25519.A := by
  rw[hd0]
  have eq_dh := hd.add_right A1_val
  by_cases h: (d_1_val) ≡ 0 [MOD p]
  · simp only [← modEq_zero_iff] at hfe1_0
    have := hfe1_0 h
    have := hd.trans (this.mul_left A_neg_val)
    rw[lift_mod_eq_iff] at this
    simp only [this, mul_zero, Nat.cast_zero, zero_add, neg_mul, neg_neg]
    rw[← change_d_1]
    rw[lift_mod_eq_iff] at h
    simp only [h, Nat.cast_zero, inv_zero, mul_zero, zero_sub, neg_inj]
    unfold Curve25519.A
    simp[hA]
  · have hfe1_inv := fe1_inv_of_mod_mul' fe1_val d_1_val h hfe1_non
    have h_d_val : (d_val : CurveField) = -Curve25519.A * (d_1_val : CurveField)⁻¹ := by
      rw[lift_mod_eq_iff] at hd; rw[hd]; simp [change_A, hfe1_inv]
    have h_A1 : (A1_val : CurveField) = Curve25519.A := by
      unfold Curve25519.A; simp [hA]
    rw[h_d_val, h_A1, ← change_d_1]; ring



private lemma isSquare_eps_of_choice_one
    (choice_val : U8) (eps_val one_val : ℕ)
    (one_eq : one_val = 1)
    (hp_nqr_gives_zero :
      (eps_val % p ≠ 0 ∧ one_val % p ≠ 0 ∧
       ¬∃ x, x ^ 2 * (one_val % p) % p = eps_val % p) → choice_val = 0#u8)
    (h_one : choice_val = 1#u8) :
    IsSquare ((eps_val : CurveField)) := by
  by_cases h: eps_val % p = 0
  · rw[← modEq_zero_iff, lift_mod_eq_iff] at h
    rw[h]
    exact ⟨0, by simp⟩
  · by_cases ex_cases: ∃ x, x ^ 2 % p = eps_val % p
    · obtain ⟨ ex, hex⟩ := ex_cases
      rw[← Nat.ModEq] at hex
      rw[lift_mod_eq_iff] at hex
      rw[← hex]
      exact ⟨ex, by grind only⟩
    · have := hp_nqr_gives_zero (nqr_condition_of_nonzero eps_val one_val one_eq h ex_cases)
      simp [h_one] at this


private lemma choice_one_of_isSquare_eps
    (choice_val : U8) (eps_val d_val A1_val A_neg_val fe1_val d_1_val one_val : ℕ)
    (d0 r0 : CurveField) (hd0 : d0 = -Curve25519.A * (1 + 2 * r0 ^ 2)⁻¹)
    (one_eq : one_val = 1) (hA : A1_val = 486662)
    (change_heps : eps_val ≡ d_val * (d_val ^ 2 + A1_val * d_val + 1) [MOD p])
    (hd : d_val ≡ A_neg_val * fe1_val [MOD p])
    (change_A : (A_neg_val : CurveField) = -Curve25519.A)
    (change_d_1 : (d_1_val : CurveField) = 1 + 2 * r0 ^ 2)
    (hfe1_non : d_1_val % p ≠ 0 → (fe1_val % p) * (d_1_val % p) % p = 1)
    (hfe1_0 : d_1_val % p = 0 → fe1_val % p = 0)
    (hp_eps_zero_gives_one : eps_val % p = 0 → choice_val = 1#u8)
    (hp_qr_gives_one :
      (eps_val % p ≠ 0 ∧ one_val % p ≠ 0 ∧
       ∃ x, x ^ 2 * (one_val % p) % p = eps_val % p) → choice_val = 1#u8)
    (sq : IsSquare (d0 * (d0 ^ 2 + Curve25519.A * d0 + 1))) :
    choice_val = 1#u8 := by
  by_cases heps_zero: eps_val % p = 0
  · exact hp_eps_zero_gives_one heps_zero
  · by_cases hd_1_zero : d_1_val % p = 0
    · have := hfe1_0 hd_1_zero
      rw[← modEq_zero_iff] at this
      have := change_heps.trans ((hd.trans (this.mul_left A_neg_val)).mul_right (d_val ^ 2 + A1_val * d_val + 1))
      simp only [mul_zero, hA, zero_mul] at this
      rw[← modEq_zero_iff] at heps_zero
      simp only [this, not_true_eq_false] at heps_zero
    · have hfe1_inv := fe1_inv_of_mod_mul fe1_val d_1_val hd_1_zero (hfe1_non hd_1_zero)
      rw[← modEq_zero_iff] at hd_1_zero
      have hd0_eq : d0 = (d_val : CurveField) :=
        d0_eq_d_of_inv r0 d0 hd0 d_val fe1_val d_1_val A_neg_val change_A change_d_1 hd hfe1_inv
      rw[hd0_eq] at sq
      have change_heps' := change_heps
      simp only [hA, lift_mod_eq_iff, Nat.cast_mul, Nat.cast_add, Nat.cast_pow, Nat.cast_ofNat,
        Nat.cast_one] at change_heps'
      have : (486662 : CurveField) = Curve25519.A := curveField_486662_eq_A
      rw[this] at change_heps'
      rw[← change_heps'] at sq
      exact hp_qr_gives_one (qr_condition_of_square eps_val one_val one_eq heps_zero sq)



private lemma elligator_nqr_neg_rhs_identity
    (d0 r0 u : CurveField)
    (hd0 : d0 = -Curve25519.A * (1 + 2 * r0 ^ 2)⁻¹)
    (hu : u = -d0 - Curve25519.A)
    (h_nonzero : (1 + 2 * r0 ^ 2) ≠ (0 : CurveField)) :
    -(u * (u ^ 2 + Curve25519.A * u + 1)) =
      -2 * r0 ^ 2 * (d0 * (d0 ^ 2 + Curve25519.A * d0 + 1)) := by
  have eq1 : u = 2 * d0 * r0 ^ 2 := by
    rw[hu, hd0]
    field_simp[h_nonzero]
    simp only [sub_add_cancel_left, mul_neg, neg_inj]
    ring_nf
  have h_u_add_A : u + Curve25519.A = -d0 := by grind
  have eq2 : u ^ 2 + Curve25519.A * u + 1 = d0 ^ 2 + Curve25519.A * d0 + 1 := by grind
  rw[eq2, eq1]; ring



private lemma elligator_nqr_isSquare_witness
    (r0 : CurveField)
    (eps_val witness_val : ℕ)
    (h_witness : (witness_val : CurveField) ^ 2 =
      (Field51_as_Nat SQRT_M1_val : CurveField) * (eps_val : CurveField)) :
    IsSquare (-2 * r0 ^ 2 * (eps_val : CurveField)) := by
  obtain ⟨r1, hr1⟩ := two_did_is_square
  use (r1.val * r0.val * witness_val)
  simp only [neg_mul, ZMod.natCast_val, ZMod.cast_id', id_eq]
  field_simp
  field_simp at hr1
  rw[h_witness, ← hr1]
  field_simp [SQRT_M1_val_ne_zero]


private lemma elligator_nqr_twist
    (d0 r0 : CurveField) (hd0 : d0 = -Curve25519.A * (1 + 2 * r0 ^ 2)⁻¹)
    (a_val eps_val d_val A1_val A_neg_val fe1_val d_1_val one_val : ℕ)
    (choice_val : U8)
    (a_eq : (a_val : CurveField) = -d0 - Curve25519.A)
    (one_eq : one_val = 1) (hA : A1_val = 486662)
    (change_heps : eps_val ≡ d_val * (d_val ^ 2 + A1_val * d_val + 1) [MOD p])
    (hd : d_val ≡ A_neg_val * fe1_val [MOD p])
    (change_A : (A_neg_val : CurveField) = -Curve25519.A)
    (change_d_1 : (d_1_val : CurveField) = 1 + 2 * r0 ^ 2)
    (hfe1_non : d_1_val % p ≠ 0 → (fe1_val % p) * (d_1_val % p) % p = 1)
    (non_d_1 : (1 + 2 * r0 ^ 2) ≠ (0 : CurveField))

    (hp_case_2_left : eps_val % p = 0 → choice_val = 1#u8)
    (hp_case_4_left :
      (eps_val % p ≠ 0 ∧ one_val % p ≠ 0 ∧
       ∃ x, x ^ 2 * (one_val % p) % p = eps_val % p) → choice_val = 1#u8)
    (h_zero : choice_val = 0#u8)

    (witness_val : ℕ)
    (hp_case_5_right :
      (one_val % p = 1) →
      (witness_val ^ 2 * (one_val % p)) % p =
        ((Field51_as_Nat SQRT_M1_val % p) * (eps_val % p)) % p) :
    IsSquare (-((a_val : CurveField) *
      ((a_val : CurveField) ^ 2 + Curve25519.A * (a_val : CurveField) + 1))) := by

  have h_neg_rhs := elligator_nqr_neg_rhs_identity d0 r0 (a_val : CurveField) hd0 a_eq non_d_1
  rw[h_neg_rhs]

  have h_nqr_cond : (eps_val % p ≠ 0 ∧
      one_val % p ≠ 0 ∧
      ¬∃ x, x ^ 2 * (one_val % p) % p = eps_val % p) := by
    constructor
    · intro h; have := hp_case_2_left h; simp [this] at h_zero
    · constructor
      · rw[one_eq]; decide
      · intro h
        have : (eps_val % p ≠ 0 ∧
          one_val % p ≠ 0 ∧
          ∃ x, x ^ 2 * (one_val % p) % p = eps_val % p) := by
            constructor
            · intro h; have := hp_case_2_left h; simp [this] at h_zero
            · constructor
              · rw[one_eq]; decide
              · exact h
        have := hp_case_4_left this
        simp [this] at h_zero
  have one_mod : one_val % p = 1 := by rw[one_eq]; decide

  have h_witness_eq := hp_case_5_right one_mod
  simp only [one_mod, mul_one, Nat.mul_mod_mod, Nat.mod_mul_mod] at h_witness_eq
  rw[← Nat.ModEq, lift_mod_eq_iff] at h_witness_eq
  simp only [Nat.cast_pow, Nat.cast_mul] at h_witness_eq

  have hfe1_inv : ((fe1_val : CurveField)) = ((d_1_val : CurveField))⁻¹ := by
    have : (d_1_val : CurveField) ≠ 0 := by
      intro h1; apply non_d_1; rw[← change_d_1]; exact h1
    field_simp
    have : d_1_val % p ≠ 0 := by
      intro h1; apply non_d_1; rw[← change_d_1]
      simp only [← modEq_zero_iff, lift_mod_eq_iff] at h1; exact h1
    have := hfe1_non this
    have eq1 := mod_mul_mod fe1_val d_1_val
    rw[Nat.ModEq] at eq1
    rw[eq1] at this
    rw[← modEq_one_iff] at this
    simp only [lift_mod_eq_iff, Nat.cast_mul, Nat.cast_one] at this
    exact this
  have hd0_eq : d0 = (d_val : CurveField) :=
    d0_eq_d_of_inv r0 d0 hd0 d_val fe1_val d_1_val A_neg_val change_A change_d_1 hd hfe1_inv

  have change_heps' := change_heps
  rw[lift_mod_eq_iff] at change_heps'
  simp only [hA, Nat.cast_mul, ← hd0_eq, Nat.cast_add, Nat.cast_pow, Nat.cast_ofNat,
    Nat.cast_one] at change_heps'
  have : (486662 : CurveField) = Curve25519.A := curveField_486662_eq_A
  rw[this] at change_heps'
  rw[← change_heps']

  exact elligator_nqr_isSquare_witness r0 eps_val witness_val h_witness_eq




























@[progress]
theorem elligator_encode_spec
    (r_0 : backend.serial.u64.field.FieldElement51)
    (h_bounds : ∀ i, i < 5 → (r_0[i]!).val ≤ 2 ^ 52 - 1) :
    elligator_encode r_0 ⦃ res =>

    let r     : ZMod p := (Field51_as_Nat r_0 : ZMod p)
    let d_1   : ZMod p := 1 + 2 * r ^ 2
    let d     : ZMod p := -Curve25519.A * d_1⁻¹
    let eps   : ZMod p := d * (d ^ 2 + Curve25519.A * d + 1)
    let point  := res.1
    let eps_is_sq := res.2

    (eps_is_sq.val = 1#u8 ↔ IsSquare eps) ∧

    (eps_is_sq.val = 1#u8 →
      (U8x32_as_Nat point : ZMod p) = d) ∧
    (eps_is_sq.val = 0#u8 →
      (U8x32_as_Nat point : ZMod p) = -d - Curve25519.A) ∧

    (eps_is_sq.val = 1#u8 →
      let u : ZMod p := (U8x32_as_Nat point : ZMod p)
      u * (u ^ 2 + Curve25519.A * u + 1) = eps) ∧

    (eps_is_sq.val = 0#u8 →
      let u : ZMod p := (U8x32_as_Nat point : ZMod p)
      IsSquare (-(u * (u ^ 2 + Curve25519.A * u + 1)))) ⦄ := by
  sorry
end curve25519_dalek.montgomery
