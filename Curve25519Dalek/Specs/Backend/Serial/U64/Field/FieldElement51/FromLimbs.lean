




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic












open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.field.FieldElement51





















@[progress]
theorem from_limbs_spec (a : Array U64 5#usize) :
    from_limbs a ⦃ r =>
    r = a ∧ Field51_as_Nat r = Field51_as_Nat a ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
