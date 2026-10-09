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
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryMul
import Curve25519Dalek.Specs.Scalar.Scalar52.MontgomeryInvert.SquareMultiplyLoop

open Aeneas Aeneas.Std Aeneas.Std.WP Result curve25519_dalek.backend.serial.u64.scalar curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.scalar.Scalar52

def pow2 (n : Nat) : Nat := 2^n

end curve25519_dalek.scalar.Scalar52

namespace curve25519_dalek.scalar.Scalar52.montgomery_invert

/-- Combining the closed form of `squarings` Montgomery squarings with one Montgomery
multiplication. -/
theorem square_multiply_modeq (y x y1 r R k n : Nat)
    (h1 : y1 * R ^ (2 ^ k - 1) ≡ y ^ (2 ^ k) [MOD n])
    (h2 : r * R ≡ y1 * x [MOD n]) :
    r * R ^ (2 ^ k) ≡ y ^ (2 ^ k) * x [MOD n] := by
  have hk : 2 ^ k = (2 ^ k - 1) + 1 := by
    have : 1 ≤ 2 ^ k := Nat.one_le_two_pow
    omega
  calc r * R ^ (2 ^ k) = (r * R) * R ^ (2 ^ k - 1) := by
        rw [hk, pow_succ, Nat.add_sub_cancel]; ring
    _ ≡ (y1 * x) * R ^ (2 ^ k - 1) [MOD n] := Nat.ModEq.mul_right _ h2
    _ = (y1 * R ^ (2 ^ k - 1)) * x := by ring
    _ ≡ y ^ (2 ^ k) * x [MOD n] := Nat.ModEq.mul_right _ h1

/-- `square_multiply y squarings x` computes, in Montgomery form, `y^(2^squarings) * x`:
with `R = 2^260`, the result `r` has 52-bit limbs, is canonical and satisfies
`r * R^(2^squarings) ≡ y^(2^squarings) * x [MOD L]`. -/
@[progress]
theorem square_multiply_spec (y : backend.serial.u64.scalar.Scalar52) (squarings : Usize)
    (x : backend.serial.u64.scalar.Scalar52)
    (hy : ∀ j, j < 5 → (y.val[j]!).val < 2 ^ 52)
    (hyL : Scalar52_as_Nat y < _root_.L)
    (hx : ∀ j, j < 5 → (x.val[j]!).val < 2 ^ 52)
    (hxL : Scalar52_as_Nat x < _root_.L) :
    scalar.Scalar52.montgomery_invert.square_multiply y squarings x ⦃ r =>
      (∀ j, j < 5 → (r.val[j]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r < _root_.L ∧
      Scalar52_as_Nat r * (2 ^ 260) ^ (2 ^ squarings.val) ≡
        Scalar52_as_Nat y ^ (2 ^ squarings.val) * Scalar52_as_Nat x [MOD _root_.L] ⦄ := by
  unfold scalar.Scalar52.montgomery_invert.square_multiply
  progress as ⟨y1, hy1, hy1L, hy1mod⟩
  progress with backend.serial.u64.scalar.Scalar52.montgomery_mul_spec_right_lt
    as ⟨r, hr, hrmod, hrL⟩
  refine ⟨hr, hrL, ?_⟩
  simp only [Nat.sub_zero] at hy1mod
  exact square_multiply_modeq _ _ _ _ _ _ _ hy1mod hrmod

end curve25519_dalek.scalar.Scalar52.montgomery_invert
