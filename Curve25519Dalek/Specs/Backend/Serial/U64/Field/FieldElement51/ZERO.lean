




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromLimbs










open Aeneas Aeneas.Std.WP Aeneas.Std Result
namespace curve25519_dalek.backend.serial.u64.field.FieldElement51
















@[progress]
theorem ZERO_spec : ZERO ⦃ (result : FieldElement51) =>
    Field51_as_Nat result = 0 ∧
    (∀ i< 5, (result[i]!.val) < 2^51 )⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
