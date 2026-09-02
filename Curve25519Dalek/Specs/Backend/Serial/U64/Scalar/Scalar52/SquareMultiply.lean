




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryMul
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomerySquare












open Aeneas Aeneas.Std Aeneas.Std.WP Result curve25519_dalek.backend.serial.u64.scalar curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.scalar.Scalar52

























def pow2 (n : Nat) : Nat := 2^n








theorem square_multiply_loop_spec (y : Scalar52) (squarings i : Usize) (hi : i.val ≤ squarings.val)
    (h_y_bound : ∀ j < 5, y[j]!.val < 2 ^ 62) :
    montgomery_invert.square_multiply_loop y squarings i ⦃ res =>
    (Scalar52_as_Nat res * R ^ (pow2 (squarings.val - i.val) - 1)) % L =
    (Scalar52_as_Nat y) ^ (pow2 (squarings.val - i.val)) % L ∧
    (∀ j < 5, res[j]!.val < 2 ^ 62) ⦄ := by
  sorry






@[progress]
theorem square_multiply_spec (y : Scalar52) (squarings : Usize) (x : Scalar52)
    (hy : ∀ i < 5, y[i]!.val < 2 ^ 62) (hx : ∀ i < 5, x[i]!.val < 2 ^ 62) :
    montgomery_invert.square_multiply y squarings x ⦃ res =>
    (Scalar52_as_Nat res * R ^ (pow2 squarings.val)) % L =
    ((Scalar52_as_Nat y) ^ (pow2 squarings.val) * (Scalar52_as_Nat x)) % L ∧
    (∀ i < 5, res[i]!.val < 2 ^ 62) ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar52
