




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalSelect

















open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable













theorem conditional_select_spec
    (a b : backend.serial.curve_models.AffineNielsPoint)
    (choice : subtle.Choice) :
    conditional_select a b choice ⦃ result =>
    (∀ i < 5, result.y_plus_x[i]!.val =
      if choice.val = 1#u8 then b.y_plus_x[i]!.val else a.y_plus_x[i]!.val) ∧
    (∀ i < 5, result.y_minus_x[i]!.val =
      if choice.val = 1#u8 then b.y_minus_x[i]!.val else a.y_minus_x[i]!.val) ∧
    (∀ i < 5, result.xy2d[i]!.val =
      if choice.val = 1#u8 then b.xy2d[i]!.val else a.xy2d[i]!.val) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable
