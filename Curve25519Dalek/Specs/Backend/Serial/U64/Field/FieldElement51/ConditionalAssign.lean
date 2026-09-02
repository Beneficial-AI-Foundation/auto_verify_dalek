




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalSelect
import Mathlib.Tactic














open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.SubtleConditionallySelectable











@[progress]
theorem conditional_assign_spec (self other : backend.serial.u64.field.FieldElement51)
    (choice : subtle.Choice) :
    conditional_assign self other choice ⦃ (res : FieldElement51) =>
      (∀ i < 5, res[i]! = (if choice.val = 1#u8 then other[i]! else self[i]!)) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.SubtleConditionallySelectable
