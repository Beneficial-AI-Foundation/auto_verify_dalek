




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants


















@[progress]
theorem MONTGOMERY_A_spec :
    MONTGOMERY_A ⦃ result => Field51_as_Nat result = 486662 ∧
    (∀ i < 5, (result[i]!).val < 2 ^51)⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
