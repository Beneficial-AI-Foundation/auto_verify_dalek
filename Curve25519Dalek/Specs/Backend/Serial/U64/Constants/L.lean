




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic










open Aeneas.Std Result
namespace curve25519_dalek.backend.serial.u64.constants















@[simp]
theorem L_spec : Scalar52_as_Nat L = _root_.L := by
  sorry
lemma L_limbs_spec (i : Usize) (h : i.val < 5) :
    (constants.L[i.val]!).val < 2 ^ 52 := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
