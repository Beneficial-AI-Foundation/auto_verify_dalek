




import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromLimbs













open Aeneas Aeneas.Std Result
open curve25519_dalek.backend.serial.u64.field

namespace curve25519_dalek.backend.serial.u64.constants



















@[progress]
theorem APLUS2_OVER_FOUR_spec :
  APLUS2_OVER_FOUR ⦃ result =>
    Field51_as_Nat result = 121666 ∧
    ∀ i < 5, result[i]!.val < 2 ^ 54 ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
