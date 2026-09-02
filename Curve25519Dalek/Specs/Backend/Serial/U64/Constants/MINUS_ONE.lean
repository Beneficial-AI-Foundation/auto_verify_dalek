




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants

















@[progress]
theorem MINUS_ONE_spec :
    MINUS_ONE ⦃ result =>
    Field51_as_Nat result = p - 1 ∧
    (∀ i < 5, result[i]!.val < 2^51) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
