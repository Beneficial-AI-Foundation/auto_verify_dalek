




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic










open Aeneas.Std Result
namespace curve25519_dalek.backend.serial.u64.constants


















theorem LFACTOR_spec :
    (_root_.L * LFACTOR + 1) % (2^52) = 0 ∧
    0 ≤ LFACTOR.val ∧
    LFACTOR.val < 2^52 := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
