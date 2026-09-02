




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic










open Aeneas Aeneas.Std.WP Aeneas.Std Result
namespace curve25519_dalek.backend.serial.u64.field.FieldElement51
















@[progress]
theorem ONE_spec :
    ONE ⦃ result =>
    Field51_as_Nat result = 1 ∧
    (∀ i < 5, result[i]!.val < 2^51) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
