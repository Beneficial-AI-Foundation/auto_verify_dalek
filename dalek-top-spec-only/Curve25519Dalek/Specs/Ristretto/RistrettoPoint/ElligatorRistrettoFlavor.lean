/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.FunsExternal
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Data.Nat.ModEq
import Mathlib.Tactic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.SQRT_AD_MINUS_ONE

open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.math
open Edwards curve25519_dalek.backend.serial.u64.constants
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.backend.serial.u64.field.FieldElement51
namespace curve25519_dalek.ristretto.RistrettoPoint

private structure ElligatorSqrtRatioPosts
    (N_s D : FieldElement51) (x : subtle.Choice × FieldElement51) : Prop where
  zero_case : Field51_as_Nat N_s % p = 0 → x.1.val = 1#u8 ∧ Field51_as_Nat x.2 % p = 0
  d_zero_case :
    Field51_as_Nat N_s % p ≠ 0 ∧ Field51_as_Nat D % p = 0 →
      x.1.val = 0#u8 ∧ Field51_as_Nat x.2 % p = 0
  square_case :
    (Field51_as_Nat N_s % p ≠ 0 ∧
        Field51_as_Nat D % p ≠ 0 ∧ ∃ x0, x0 ^ 2 * (Field51_as_Nat D % p) % p =
          Field51_as_Nat N_s % p) →
      x.1.val = 1#u8 ∧
        (Field51_as_Nat x.2 % p) ^ 2 * (Field51_as_Nat D % p) % p =
          Field51_as_Nat N_s % p
  nonsquare_case :
    (Field51_as_Nat N_s % p ≠ 0 ∧
        Field51_as_Nat D % p ≠ 0 ∧
        ¬∃ x0, x0 ^ 2 * (Field51_as_Nat D % p) % p = Field51_as_Nat N_s % p) →
      x.1.val = 0#u8 ∧
        (Field51_as_Nat x.2 % p) ^ 2 * (Field51_as_Nat D % p) % p =
            Field51_as_Nat field.FieldElement51.SQRT_M1_val % p *
            (Field51_as_Nat N_s % p) % p

private structure ElligatorSPrimePosts
    (s s_prime s_prime_neg s_prime1 : FieldElement51)
    (x : subtle.Choice × FieldElement51) (s_prime_is_pos : subtle.Choice) : Prop where
  mul_eq : Field51_as_Nat s_prime ≡ Field51_as_Nat x.2 * Field51_as_Nat s [MOD p]
  neg_eq : Field51_as_Nat s_prime + Field51_as_Nat s_prime_neg ≡ 0 [MOD p]
  select :
    ∀ i : Nat, i < 5 →
      s_prime1[i]! = if s_prime_is_pos.val = 1#u8 then s_prime_neg[i]! else s_prime[i]!

private structure ElligatorChoicePosts
    (c r c2 : FieldElement51)
    (x : subtle.Choice × FieldElement51) (not_sq : subtle.Choice) : Prop where
  not_sq_flag : x.1.val = 1#u8 ↔ not_sq = Choice.zero
  c2_select :
    ∀ i : Nat, i < 5 →
      c2[i]! = if not_sq.val = 1#u8 then r[i]! else c[i]!
  c_minus_one : Field51_as_Nat c = p - 1

private structure ElligatorS1Posts
    (s_prime1 s1 : FieldElement51)
    (x : subtle.Choice × FieldElement51) (not_sq : subtle.Choice) : Prop where
  select :
    ∀ i : Nat, i < 5 →
      s1[i]! = if not_sq.val = 1#u8 then s_prime1[i]! else x.2[i]!

private structure ElligatorSignPosts
    (s_prime : FieldElement51) (c1 s_prime_is_pos : subtle.Choice) : Prop where
  odd_flag : c1.val = 1#u8 ↔ Field51_as_Nat s_prime % p % 2 = 1
  pos_flag : c1.val = 1#u8 ↔ s_prime_is_pos = Choice.zero

private structure ElligatorCompletedPointPosts
    (one s_sq cp_X cp_Y cp_Z cp_T fe s_plus_s s1 D N_t : FieldElement51) : Prop where
  s_sq_eq : Field51_as_Nat s_sq ≡ Field51_as_Nat s1 ^ 2 [MOD p]
  s_plus_s_eq :
    ∀ i : Nat, i < 5 →
      ((s_plus_s[i]!) : Nat) = ((s1[i]!) : Nat) + ((s1[i]!) : Nat)
  cp_X_mul : Field51_as_Nat cp_X ≡ Field51_as_Nat s_plus_s * Field51_as_Nat D [MOD p]
  cp_X_bound : ∀ i : Nat, i < 5 → ((cp_X[i]!) : Nat) < 2 ^ 52
  cp_Z_mul : Field51_as_Nat cp_Z ≡ Field51_as_Nat N_t * Field51_as_Nat fe [MOD p]
  cp_Z_bound : ∀ i : Nat, i < 5 → ((cp_Z[i]!) : Nat) < 2 ^ 52
  cp_Y_bound : ∀ i : Nat, i < 5 → ((cp_Y[i]!) : Nat) < 2 ^ 52
  cp_Y_sub : (Field51_as_Nat cp_Y + Field51_as_Nat s_sq) % p = Field51_as_Nat one % p
  cp_T_bound : ∀ i : Nat, i < 5 → ((cp_T[i]!) : Nat) < 2 ^ 54
  fe_sq : ↑(Field51_as_Nat fe) ^ 2 % ↑p = (a * ↑_root_.d - 1) % ↑p
  one_eq : Field51_as_Nat one = 1

private structure ElligatorLiftPosts
    (cp_T one s_sq s1 r_plus_one r one_minus_d_sq N_s r_plus_d d
      c_minus_dr d_times_r c D r_minus_one c2 c_r_minus_one c_r_minus_one_d
      N_t d_minus_one_sq : FieldElement51) : Prop where
  cp_T_nat : Field51_as_Nat cp_T = Field51_as_Nat one + Field51_as_Nat s_sq
  s_sq_eq : Field51_as_Nat s_sq ≡ Field51_as_Nat s1 ^ 2 [MOD p]
  one_eq : Field51_as_Nat one = 1
  r_plus_one_nat : Field51_as_Nat r_plus_one = Field51_as_Nat r + Field51_as_Nat one
  one_minus_d_sq_eq : Field51_as_Nat one_minus_d_sq = (1 + p - _root_.d ^ 2 % p) % p
  N_s_mul :
    Field51_as_Nat N_s ≡ Field51_as_Nat r_plus_one * Field51_as_Nat one_minus_d_sq [MOD p]
  r_plus_d_nat : Field51_as_Nat r_plus_d = Field51_as_Nat r + Field51_as_Nat d
  d_eq : Field51_as_Nat d = _root_.d
  c_minus_dr_sub :
    (Field51_as_Nat c_minus_dr + Field51_as_Nat d_times_r) % p = Field51_as_Nat c % p
  d_times_r_mul : Field51_as_Nat d_times_r ≡ Field51_as_Nat d * Field51_as_Nat r [MOD p]
  c_minus_one : Field51_as_Nat c = p - 1
  D_mul : Field51_as_Nat D ≡ Field51_as_Nat c_minus_dr * Field51_as_Nat r_plus_d [MOD p]
  r_minus_one_sub : (Field51_as_Nat r_minus_one + Field51_as_Nat one) % p = Field51_as_Nat r % p
  c_r_minus_one_mul :
    Field51_as_Nat c_r_minus_one ≡ Field51_as_Nat c2 * Field51_as_Nat r_minus_one [MOD p]
  c_r_minus_one_d_mul :
    Field51_as_Nat c_r_minus_one_d ≡
      Field51_as_Nat c_r_minus_one * Field51_as_Nat d_minus_one_sq [MOD p]
  N_t_add : (Field51_as_Nat N_t + Field51_as_Nat D) % p = Field51_as_Nat c_r_minus_one_d % p
  d_minus_one_sq_eq : Field51_as_Nat d_minus_one_sq = (_root_.d - 1) ^ 2 % p

private structure ElligatorLiftFacts
    (cp_T r_plus_one one_minus_d_sq N_s r_plus_d c_minus_dr D r_minus_one c_r_minus_one
      c_r_minus_one_d N_t s1 r c2 d_minus_one_sq : FieldElement51) : Prop where
  cp_T_eq : cp_T.toField = 1 + s1.toField ^ 2
  r_plus_one_eq : r_plus_one.toField = r.toField + 1
  one_minus_d_sq_eq : one_minus_d_sq.toField = 1 - Ed25519.d ^ 2
  N_s_eq : N_s.toField = (r.toField + 1) * (1 - Ed25519.d ^ 2)
  r_plus_d_eq : r_plus_d.toField = r.toField + Ed25519.d
  c_minus_dr_eq : c_minus_dr.toField = -1 - Ed25519.d * r.toField
  D_eq : D.toField = (-1 - Ed25519.d * r.toField) * (r.toField + Ed25519.d)
  r_minus_one_eq : r_minus_one.toField = r.toField - 1
  c_r_minus_one_eq : c_r_minus_one.toField = c2.toField * r_minus_one.toField
  c_r_minus_one_d_eq : c_r_minus_one_d.toField = c_r_minus_one.toField * d_minus_one_sq.toField
  N_t_add_eq : N_t.toField + D.toField = c_r_minus_one_d.toField
  N_t_eq : N_t.toField = c2.toField * (r.toField - 1) * (Ed25519.d - 1) ^ 2 - D.toField

end curve25519_dalek.ristretto.RistrettoPoint
