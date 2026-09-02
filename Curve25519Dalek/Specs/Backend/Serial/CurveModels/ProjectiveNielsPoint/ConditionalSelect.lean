




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalSelect

















open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable













theorem conditional_select_spec
    (a b : backend.serial.curve_models.ProjectiveNielsPoint)
    (choice : subtle.Choice) :
    conditional_select a b choice ⦃ result =>
    (∀ i < 5, result.Y_plus_X[i]!.val =
      if choice.val = 1#u8 then b.Y_plus_X[i]!.val else a.Y_plus_X[i]!.val) ∧
    (∀ i < 5, result.Y_minus_X[i]!.val =
      if choice.val = 1#u8 then b.Y_minus_X[i]!.val else a.Y_minus_X[i]!.val) ∧
    (∀ i < 5, result.Z[i]!.val =
      if choice.val = 1#u8 then b.Z[i]!.val else a.Z[i]!.val) ∧
    (∀ i < 5, result.T2d[i]!.val =
      if choice.val = 1#u8 then b.T2d[i]!.val else a.T2d[i]!.val) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable
