import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

@[progress]
theorem from_limbs_spec (limbs : Array Std.U64 5#usize) :
    spec (from_limbs limbs) (fun fe => fe = limbs) := by
  simp [from_limbs]

end curve25519_dalek.backend.serial.u64.field.FieldElement51
