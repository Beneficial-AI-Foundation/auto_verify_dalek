




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalSelect













open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable













@[progress]
theorem conditional_select_spec
    (a b : montgomery.ProjectivePoint)
    (choice : subtle.Choice) :
    conditional_select a b choice ⦃ res =>
      (∀ i < 5, res.U[i]! = (if choice.val = 1#u8 then b.U[i]! else a.U[i]!)) ∧
      (∀ i < 5, res.W[i]! = (if choice.val = 1#u8 then b.W[i]! else a.W[i]!)) ⦄ := by
  sorry
end curve25519_dalek.montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable
