




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalSelect













open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable




















@[progress]
theorem conditional_select_spec
    (a b : edwards.affine.AffinePoint)
    (choice : subtle.Choice) :
    conditional_select a b choice ⦃ (result : edwards.affine.AffinePoint) =>
      result = if choice.val = 1#u8 then b else a ⦄ := by
  sorry
end curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable
