import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomerySquare

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.scalar.Scalar52.montgomery_invert

open curve25519_dalek.backend.serial.u64.scalar

/-- One extra Montgomery squaring step in the closed form of `square_multiply_loop`. -/
theorem square_multiply_loop_modeq_step (y y1 r R n k : Nat)
    (h1 : y1 * R ≡ y * y [MOD n])
    (h2 : r * R ^ (2 ^ k - 1) ≡ y1 ^ (2 ^ k) [MOD n]) :
    r * R ^ (2 ^ (k + 1) - 1) ≡ y ^ (2 ^ (k + 1)) [MOD n] := by
  have hk : 2 ^ (k + 1) - 1 = (2 ^ k - 1) + 2 ^ k := by
    have : 1 ≤ 2 ^ k := Nat.one_le_two_pow
    rw [pow_succ]; omega
  rw [hk, pow_add, ← mul_assoc]
  calc r * R ^ (2 ^ k - 1) * R ^ (2 ^ k) ≡ y1 ^ (2 ^ k) * R ^ (2 ^ k) [MOD n] :=
        Nat.ModEq.mul_right _ h2
    _ = (y1 * R) ^ (2 ^ k) := by rw [mul_pow]
    _ ≡ (y * y) ^ (2 ^ k) [MOD n] := Nat.ModEq.pow _ h1
    _ = y ^ (2 ^ (k + 1)) := by rw [← sq, ← pow_mul, pow_succ, mul_comm 2]

/-- `square_multiply_loop y squarings i` performs `squarings - i` Montgomery squarings of `y`.
With `R = 2^260` and `k = squarings - i`, the result `r` is canonical with 52-bit limbs and
satisfies `r * R^(2^k - 1) ≡ y^(2^k) [MOD L]`. -/
@[progress]
theorem square_multiply_loop_spec (y : Scalar52) (squarings i : Usize)
    (hy : ∀ j, j < 5 → (y.val[j]!).val < 2 ^ 52)
    (hyL : Scalar52_as_Nat y < _root_.L) :
    scalar.Scalar52.montgomery_invert.square_multiply_loop y squarings i ⦃ r =>
      (∀ j, j < 5 → (r.val[j]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r < _root_.L ∧
      Scalar52_as_Nat r * (2 ^ 260) ^ (2 ^ (squarings.val - i.val) - 1) ≡
        Scalar52_as_Nat y ^ (2 ^ (squarings.val - i.val)) [MOD _root_.L] ⦄ := by
  unfold scalar.Scalar52.montgomery_invert.square_multiply_loop
  split
  · progress with Scalar52.montgomery_square_spec_lt as ⟨y1, hy1, hmod, hy1L⟩
    progress as ⟨i1, hi1⟩
    progress as ⟨r, hr, hrL, hrmod⟩
    refine ⟨hr, hrL, ?_⟩
    have hk : squarings.val - i.val = (squarings.val - i1.val) + 1 := by scalar_tac
    rw [hk]
    exact square_multiply_loop_modeq_step _ _ _ _ _ _ hmod hrmod
  · rw [spec_ok]
    have hk : squarings.val - i.val = 0 := by scalar_tac
    refine ⟨hy, hyL, ?_⟩
    rw [hk]; simp
    rfl
termination_by squarings.val - i.val
decreasing_by
  all_goals scalar_tac

end curve25519_dalek.scalar.Scalar52.montgomery_invert
