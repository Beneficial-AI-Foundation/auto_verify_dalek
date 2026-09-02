




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic









open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants


















@[progress]
theorem EDWARDS_D_MINUS_ONE_SQUARED_spec :
    EDWARDS_D_MINUS_ONE_SQUARED ⦃ result =>
    Field51_as_Nat result = (d - 1) ^ 2 % p ∧
    (∀ i < 5, result[i]!.val < 2^51) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
