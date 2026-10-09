/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MulInternal
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Sub
import Mathlib.Algebra.Polynomial.Eval.Algebra
import Mathlib.Algebra.Polynomial.Eval.Coeff
import Mathlib.Algebra.Polynomial.Eval.Defs
import Mathlib.Algebra.Polynomial.Eval.Degree
import Mathlib.Data.Nat.ModEq
import Mathlib.Data.Int.ModEq
import Mathlib.Data.ZMod.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.SquareInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.SquareMultiply

open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.backend.serial.u64.scalar curve25519_dalek.backend.serial.u64.scalar.Scalar52
open ZMod

namespace curve25519_dalek.scalar.Scalar52

section MontgomeryInvert_Helpers

def IsMont (R : ZMod L) (u_val : ZMod L) (x : ZMod L) (k : ℕ) : Prop :=
  x = u_val ^ k * R ^ (1 - (k : Int))

end MontgomeryInvert_Helpers

end curve25519_dalek.scalar.Scalar52

namespace curve25519_dalek.scalar.Scalar52

section MontgomeryInvert_Spec

/-- `v` is the Montgomery form (`R = 2^260`) of `A^e` when `a` is the Montgomery form of `A`:
`v * R^(e-1) ≡ a^e [MOD L]`. -/
def MontPow (a v e : ℕ) : Prop :=
  v * (2 ^ 260) ^ (e - 1) ≡ a ^ e [MOD _root_.L]

theorem MontPow.one (a : ℕ) : MontPow a a 1 := by
  simp [MontPow]; rfl

theorem MontPow.mul {a y x r e f : ℕ} (he : 1 ≤ e) (hf : 1 ≤ f)
    (hy : MontPow a y e) (hx : MontPow a x f)
    (hr : r * 2 ^ 260 ≡ y * x [MOD _root_.L]) : MontPow a r (e + f) := by
  unfold MontPow at *
  have hef : e + f - 1 = 1 + (e - 1) + (f - 1) := by omega
  calc r * (2 ^ 260) ^ (e + f - 1)
        = (r * 2 ^ 260) * ((2 ^ 260) ^ (e - 1) * (2 ^ 260) ^ (f - 1)) := by
          rw [hef, pow_add, pow_add, pow_one]; ring
    _ ≡ (y * x) * ((2 ^ 260) ^ (e - 1) * (2 ^ 260) ^ (f - 1)) [MOD _root_.L] :=
          Nat.ModEq.mul_right _ hr
    _ = (y * (2 ^ 260) ^ (e - 1)) * (x * (2 ^ 260) ^ (f - 1)) := by ring
    _ ≡ a ^ e * a ^ f [MOD _root_.L] := Nat.ModEq.mul hy hx
    _ = a ^ (e + f) := by rw [pow_add]

theorem MontPow.sq {a y r e : ℕ} (he : 1 ≤ e) (hy : MontPow a y e)
    (hr : r * 2 ^ 260 ≡ y * y [MOD _root_.L]) : MontPow a r (e + e) :=
  MontPow.mul he he hy hy hr

theorem MontPow.sqmul {a y x r e f k : ℕ} (he : 1 ≤ e) (hf : 1 ≤ f)
    (hy : MontPow a y e) (hx : MontPow a x f)
    (hr : r * (2 ^ 260) ^ (2 ^ k) ≡ y ^ (2 ^ k) * x [MOD _root_.L]) :
    MontPow a r (2 ^ k * e + f) := by
  unfold MontPow at *
  have h1 : 1 ≤ 2 ^ k := Nat.one_le_two_pow
  have hexp : 2 ^ k * e + f - 1 = 2 ^ k + (2 ^ k * (e - 1) + (f - 1)) := by
    have : 2 ^ k * e = 2 ^ k * (e - 1) + 2 ^ k := by
      rw [← Nat.mul_succ]; congr 1; omega
    omega
  generalize (2 : ℕ) ^ 260 = R at *
  calc r * R ^ (2 ^ k * e + f - 1)
        = (r * R ^ (2 ^ k)) * ((R ^ (e - 1)) ^ (2 ^ k) * R ^ (f - 1)) := by
          rw [hexp, pow_add, pow_add, ← pow_mul, mul_comm (e - 1)]; ring
    _ ≡ (y ^ (2 ^ k) * x) * ((R ^ (e - 1)) ^ (2 ^ k) * R ^ (f - 1))
          [MOD _root_.L] := Nat.ModEq.mul_right _ hr
    _ = (y * R ^ (e - 1)) ^ (2 ^ k) * (x * R ^ (f - 1)) := by ring
    _ ≡ (a ^ e) ^ (2 ^ k) * a ^ f [MOD _root_.L] := Nat.ModEq.mul (Nat.ModEq.pow _ hy) hx
    _ = a ^ (2 ^ k * e + f) := by rw [pow_add, ← pow_mul, mul_comm e]

end MontgomeryInvert_Spec

/-- Montgomery inversion: for an input `a` with 52-bit limbs and `a < L`, the result `r` has
52-bit limbs, is canonical (`< L`) and is the Montgomery form of the `(L-2)`-th power of the
value represented by `a` (with `R = 2^260`): `r * R^(L-3) ≡ a^(L-2) [MOD L]`.
By Fermat's little theorem (L prime, `a ≢ 0`), this gives `r * a ≡ R^2 [MOD L]`. -/
@[progress]
theorem montgomery_invert_spec (self : backend.serial.u64.scalar.Scalar52)
    (h : ∀ i, i < 5 → (self.val[i]!).val < 2 ^ 52)
    (hL : Scalar52_as_Nat self < _root_.L) :
    scalar.Scalar52.montgomery_invert self ⦃ r =>
      (∀ i, i < 5 → (r.val[i]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r < _root_.L ∧
      Scalar52_as_Nat r * (2 ^ 260) ^ (_root_.L - 3) ≡
        Scalar52_as_Nat self ^ (_root_.L - 2) [MOD _root_.L] ⦄ := by
  unfold scalar.Scalar52.montgomery_invert
  progress with backend.serial.u64.scalar.Scalar52.montgomery_square_spec_lt as ⟨_10, b10, m10, l10⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_square_spec_lt as ⟨_100, b100, m100, l100⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt as ⟨_11, b11, m11, l11⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt as ⟨_101, b101, m101, l101⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt as ⟨_111, b111, m111, l111⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt as ⟨_1001, b1001, m1001, l1001⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt as ⟨_1011, b1011, m1011, l1011⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt as ⟨_1111, b1111, m1111, l1111⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt as ⟨y0, by0, my0, ly0⟩
  progress as ⟨i, hi⟩
  progress as ⟨y1, b1, l1, m1⟩
  progress as ⟨i1, hi1⟩
  progress as ⟨y2, b2, l2, m2⟩
  progress as ⟨i2, hi2⟩
  progress as ⟨y3, b3, l3, m3⟩
  progress as ⟨y4, b4, l4, m4⟩
  progress as ⟨y5, b5, l5, m5⟩
  progress as ⟨y6, b6, l6, m6⟩
  progress as ⟨y7, b7, l7, m7⟩
  progress as ⟨i3, hi3⟩
  progress as ⟨y8, b8, l8, m8⟩
  progress as ⟨i4, hi4⟩
  progress as ⟨y9, b9, l9, m9⟩
  progress as ⟨y10, b10', l10', m10'⟩
  progress as ⟨y11, b11', l11', m11'⟩
  progress as ⟨i5, hi5⟩
  progress as ⟨y12, b12, l12, m12⟩
  progress as ⟨y13, b13, l13, m13⟩
  progress as ⟨y14, b14, l14, m14⟩
  progress as ⟨i6, hi6⟩
  progress as ⟨y15, b15, l15, m15⟩
  progress as ⟨i7, hi7⟩
  progress as ⟨y16, b16, l16, m16⟩
  progress as ⟨y17, b17, l17, m17⟩
  progress as ⟨i8, hi8⟩
  progress as ⟨y18, b18, l18, m18⟩
  progress as ⟨y19, b19, l19, m19⟩
  progress as ⟨y20, b20, l20, m20⟩
  progress as ⟨y21, b21, l21, m21⟩
  progress as ⟨y22, b22, l22, m22⟩
  progress as ⟨y23, b23, l23, m23⟩
  progress as ⟨y24, b24, l24, m24⟩
  progress as ⟨y25, b25, l25, m25⟩
  progress as ⟨y26, b26, l26, m26⟩
  progress as ⟨i9, hi9⟩
  progress as ⟨r, br, lr, mr⟩
  refine ⟨br, lr, ?_⟩
  simp only [hi, hi1, hi2, hi3, hi4, hi5, hi6, hi7, hi8, hi9] at *
  have e1 := MontPow.one (Scalar52_as_Nat self)
  have e10 := MontPow.sq (by norm_num) e1 m10
  have e100 := MontPow.sq (by norm_num) e10 m100
  have e11 := MontPow.mul (by norm_num) (by norm_num) e10 e1 m11
  have e101 := MontPow.mul (by norm_num) (by norm_num) e10 e11 m101
  have e111 := MontPow.mul (by norm_num) (by norm_num) e10 e101 m111
  have e1001 := MontPow.mul (by norm_num) (by norm_num) e10 e111 m1001
  have e1011 := MontPow.mul (by norm_num) (by norm_num) e10 e1001 m1011
  have e1111 := MontPow.mul (by norm_num) (by norm_num) e100 e1011 m1111
  have f0 := MontPow.mul (by norm_num) (by norm_num) e1111 e1 my0
  norm_num at e10 e100 e11 e101 e111 e1001 e1011 e1111 f0
  have f1 := MontPow.sqmul (by norm_num) (by norm_num) f0 e101 m1; norm_num at f1
  have f2 := MontPow.sqmul (by norm_num) (by norm_num) f1 e11 m2; norm_num at f2
  have f3 := MontPow.sqmul (by norm_num) (by norm_num) f2 e1111 m3; norm_num at f3
  have f4 := MontPow.sqmul (by norm_num) (by norm_num) f3 e1111 m4; norm_num at f4
  have f5 := MontPow.sqmul (by norm_num) (by norm_num) f4 e1001 m5; norm_num at f5
  have f6 := MontPow.sqmul (by norm_num) (by norm_num) f5 e11 m6; norm_num at f6
  have f7 := MontPow.sqmul (by norm_num) (by norm_num) f6 e1111 m7; norm_num at f7
  have f8 := MontPow.sqmul (by norm_num) (by norm_num) f7 e101 m8; norm_num at f8
  have f9 := MontPow.sqmul (by norm_num) (by norm_num) f8 e101 m9; norm_num at f9
  have f10 := MontPow.sqmul (by norm_num) (by norm_num) f9 e111 m10'; norm_num at f10
  have f11 := MontPow.sqmul (by norm_num) (by norm_num) f10 e1111 m11'; norm_num at f11
  have f12 := MontPow.sqmul (by norm_num) (by norm_num) f11 e111 m12; norm_num at f12
  have f13 := MontPow.sqmul (by norm_num) (by norm_num) f12 e11 m13; norm_num at f13
  have f14 := MontPow.sqmul (by norm_num) (by norm_num) f13 e1011 m14; norm_num at f14
  have f15 := MontPow.sqmul (by norm_num) (by norm_num) f14 e1011 m15; norm_num at f15
  have f16 := MontPow.sqmul (by norm_num) (by norm_num) f15 e1001 m16; norm_num at f16
  have f17 := MontPow.sqmul (by norm_num) (by norm_num) f16 e11 m17; norm_num at f17
  have f18 := MontPow.sqmul (by norm_num) (by norm_num) f17 e11 m18; norm_num at f18
  have f19 := MontPow.sqmul (by norm_num) (by norm_num) f18 e11 m19; norm_num at f19
  have f20 := MontPow.sqmul (by norm_num) (by norm_num) f19 e1001 m20; norm_num at f20
  have f21 := MontPow.sqmul (by norm_num) (by norm_num) f20 e111 m21; norm_num at f21
  have f22 := MontPow.sqmul (by norm_num) (by norm_num) f21 e1111 m22; norm_num at f22
  have f23 := MontPow.sqmul (by norm_num) (by norm_num) f22 e1011 m23; norm_num at f23
  have f24 := MontPow.sqmul (by norm_num) (by norm_num) f23 e101 m24; norm_num at f24
  have f25 := MontPow.sqmul (by norm_num) (by norm_num) f24 e1111 m25; norm_num at f25
  have f26 := MontPow.sqmul (by norm_num) (by norm_num) f25 e101 m26; norm_num at f26
  have fr := MontPow.sqmul (by norm_num) (by norm_num) f26 e11 mr; norm_num at fr
  have hfin : MontPow (Scalar52_as_Nat self) (Scalar52_as_Nat r) (_root_.L - 2) := by
    have hL2 : _root_.L - 2 =
        7237005577332262213973186563042994240857116359379907606001950938285454250987 := by
      unfold _root_.L; norm_num
    rw [hL2]; exact fr
  unfold MontPow at hfin
  rwa [show _root_.L - 2 - 1 = _root_.L - 3 by unfold _root_.L; norm_num] at hfin

end curve25519_dalek.scalar.Scalar52
