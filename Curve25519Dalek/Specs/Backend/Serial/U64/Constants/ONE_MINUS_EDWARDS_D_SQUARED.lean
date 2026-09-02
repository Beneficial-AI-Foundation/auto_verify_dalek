




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic









open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants
























@[progress]
theorem ONE_MINUS_EDWARDS_D_SQUARED_spec :
    ONE_MINUS_EDWARDS_D_SQUARED ⦃ result =>
    Field51_as_Nat result = (1 + p - (d^2 % p)) % p ∧
    (∀ i < 5, result[i]!.val < 2^51) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
