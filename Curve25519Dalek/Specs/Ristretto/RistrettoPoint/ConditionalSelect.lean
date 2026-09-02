




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.ConditionalSelect














open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable




















@[progress]
theorem conditional_select_spec
    (a b : RistrettoPoint)
    (choice : subtle.Choice) :
    conditional_select a b choice ⦃ (result : RistrettoPoint) =>
      result = if choice.val = 1#u8 then b else a ⦄ := by
  sorry
end curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable
