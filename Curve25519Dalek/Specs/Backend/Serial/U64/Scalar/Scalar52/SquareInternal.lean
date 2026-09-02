import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M


set_option exponentiation.threshold 416







open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

attribute [-simp] Int.reducePow Nat.reducePow


private theorem bounds_mul {x y : Nat} (hx : x < 2 ^ 62) (hy : y < 2 ^ 62) :
    x * y < 2^124 := by
  nlinarith [hx, hy]


private theorem bounds_sq {x : Nat} (hx : x < 2 ^ 62) : x * x < 2^124 := bounds_mul hx hx


private theorem bounds_mul2 {x y : Nat} (hx : x < 2 ^ 62) (hy : y < 2 ^ 62) :
    2 * x * y < 2^125 := by
  nlinarith [hx, hy]


private theorem bounds_add {a b : Nat} (ha : a < 2 ^ 126) (hb : b < 2 ^ 126) :
    a + b < 2^127 := by
  nlinarith [ha,hb]
















@[progress]
theorem square_internal_spec (a : Array U64 5#usize) (ha : ∀ i, i < 5 → (a[i]!).val < 2 ^ 62) :
    square_internal a ⦃ result =>
    Scalar52_wide_as_Nat result = Scalar52_as_Nat a * Scalar52_as_Nat a ∧
    (∀ i < 9, result[i]!.val < 2 ^ 127) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
