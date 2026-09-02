




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic









open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants

















@[progress]
theorem EDWARDS_D_spec :
    EDWARDS_D ⦃ result =>
    Field51_as_Nat result = d ∧
    (∀ i < 5, result[i]!.val < 2^51) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
