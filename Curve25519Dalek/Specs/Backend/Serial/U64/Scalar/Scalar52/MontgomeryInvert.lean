




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryMul
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomerySquare
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.SquareMultiply

import Mathlib.Data.Int.ModEq











open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.backend.serial.u64.scalar curve25519_dalek.backend.serial.u64.scalar.Scalar52
open ZMod

namespace curve25519_dalek.scalar.Scalar52

section MontgomeryInvert_Helpers



def IsMont (R : ZMod L) (u_val : ZMod L) (x : ZMod L) (k : ℕ) : Prop :=
  x = u_val ^ k * R ^ (1 - (k : Int))



lemma isMont_mul (R : ZMod L) (hR : R ≠ 0) {u_val x y res : ZMod L} {k j : ℕ}
    (hx : IsMont R u_val x k) (hy : IsMont R u_val y j)
    (h_eq : res = x * y * R⁻¹) :
    IsMont R u_val res (k + j) := by
  sorry

lemma isMont_sq (R : ZMod L) (hR : R ≠ 0) {u_val x res : ZMod L} {k : ℕ}
    (hx : IsMont R u_val x k)
    (h_eq : res = x * x * R⁻¹) :
    IsMont R u_val res (2 * k) := by
  sorry

lemma isMont_loop (R : ZMod L) (hR : R ≠ 0) {u_val y x res : ZMod L} {k j N : ℕ}
    (hy : IsMont R u_val y k) (hx : IsMont R u_val x j)
    (h_eq : res = y ^ N * x * (R ^ N)⁻¹) :
    IsMont R u_val res (k * N + j) := by
  sorry
lemma run_mul (RZ : ZMod L) (uZ : ZMod L) (h_RZ : (R : (ZMod L)) = RZ) (hRZ_ne_zero : RZ ≠ 0) (x y res : Scalar52) (k j : ℕ)
      (hx : IsMont RZ uZ (Scalar52_as_Nat x) k)
      (hy : IsMont RZ uZ (Scalar52_as_Nat y) j)
      (h_post : Scalar52_as_Nat x * Scalar52_as_Nat y ≡ Scalar52_as_Nat res * R [MOD L]) :
      IsMont RZ uZ (Scalar52_as_Nat res) (k + j) := by
  sorry
lemma run_sq (RZ : ZMod L) (uZ : ZMod L) (h_RZ : (R : (ZMod L)) = RZ) (hRZ_ne_zero : RZ ≠ 0)
 (x res : Scalar52) (k : ℕ)
    (hx : IsMont RZ uZ (Scalar52_as_Nat x) k)
    (h_post : Scalar52_as_Nat x * Scalar52_as_Nat x % L = Scalar52_as_Nat res * R % L) :
    IsMont RZ uZ (Scalar52_as_Nat res) (2 * k) := by
  sorry
lemma run_loop_nat (RZ : ZMod L) (uZ : ZMod L) (h_RZ : (R : (ZMod L)) = RZ) (hRZ_ne_zero : RZ ≠ 0) (y x res : Scalar52) (k j N : ℕ)
    (hy : IsMont RZ uZ (Scalar52_as_Nat y) k)
    (hx : IsMont RZ uZ (Scalar52_as_Nat x) j)
    (h_post : (Scalar52_as_Nat res * R ^ N) % L = (Scalar52_as_Nat y ^ N * Scalar52_as_Nat x) % L) :
    IsMont RZ uZ (Scalar52_as_Nat res) (k * N + j) := by
  sorry
end MontgomeryInvert_Helpers




















set_option maxHeartbeats 400000 in






@[progress]
theorem montgomery_invert_spec (u : Scalar52) (h : Scalar52_as_Nat u % L ≠ 0)
    (h_bounds : ∀ i < 5, u[i]!.val < 2 ^ 62) :
    montgomery_invert u ⦃ u' =>
    (Scalar52_as_Nat u * Scalar52_as_Nat u') % L = (R * R) % L ∧
    (∀ i < 5, u'[i]!.val < 2 ^ 62) ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar52
