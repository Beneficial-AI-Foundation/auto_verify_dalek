




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic









open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants


















@[progress]
theorem EDWARDS_D2_spec :
    EDWARDS_D2 ⦃ (result : field.FieldElement51) =>
      Field51_as_Nat result = (2 * d) % p ∧
      ∀ i < 5, result[i]!.val < 2 ^ 52 ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
