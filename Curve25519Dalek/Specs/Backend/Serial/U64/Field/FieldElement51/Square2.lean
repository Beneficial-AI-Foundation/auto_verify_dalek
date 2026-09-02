




import Curve25519Dalek.Aux
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Pow2K










open Aeneas Aeneas.Std Result Aeneas.Std.WP

set_option linter.hashCommand false
#setup_aeneas_simps

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51


















@[progress]
theorem square2_loop_spec (square : Array U64 5#usize) (i : Usize) (hi : i.val ≤ 5)
    (h_no_overflow : ∀ j < 5, i.val ≤ j → square[j]!.val * 2 ≤ U64.max) :
    square2_loop square i ⦃ (result : FieldElement51) =>
      (∀ j < 5, i.val ≤ j → result[j]!.val = square[j]!.val * 2) ∧
      (∀ j < 5, j < i.val → result[j]! = square[j]!) ⦄ := by
  sorry






@[progress]
theorem square2_spec (self : Array U64 5#usize) (h_bounds : ∀ i < 5, self[i]!.val < 2 ^ 54) :
    square2 self ⦃ (result : FieldElement51) =>
      Field51_as_Nat result ≡ (2 * (Field51_as_Nat self) ^ 2) [MOD p] ∧
      (∀ i < 5, result[i]!.val < 2 ^ 53) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
