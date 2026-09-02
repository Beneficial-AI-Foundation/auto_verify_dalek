




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalAssign




















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.curve_models
namespace curve25519_dalek.backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable






























theorem conditional_assign_spec
    (self other : backend.serial.curve_models.ProjectiveNielsPoint)
    (choice : subtle.Choice) :
    conditional_assign self other choice ⦃ result =>
    (∀ i < 5, result.Y_plus_X[i]!.val =
      if choice.val = 1#u8 then other.Y_plus_X[i]!.val else self.Y_plus_X[i]!.val) ∧
    (∀ i < 5, result.Y_minus_X[i]!.val =
      if choice.val = 1#u8 then other.Y_minus_X[i]!.val else self.Y_minus_X[i]!.val) ∧
    (∀ i < 5, result.Z[i]!.val =
      if choice.val = 1#u8 then other.Z[i]!.val else self.Z[i]!.val) ∧
    (∀ i < 5, result.T2d[i]!.val =
      if choice.val = 1#u8 then other.T2d[i]!.val else self.T2d[i]!.val) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable
