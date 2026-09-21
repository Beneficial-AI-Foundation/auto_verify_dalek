import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromLimbs

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

@[progress]
theorem ONE_spec :
    spec ONE (fun fe => Field51_as_Nat fe = 1) := by
  simp only [ONE, from_limbs, spec_ok, Field51_as_Nat, Finset.sum_range_succ,
    Finset.sum_range_zero]
  decide

end curve25519_dalek.backend.serial.u64.field.FieldElement51
