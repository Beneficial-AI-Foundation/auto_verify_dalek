




import Curve25519Dalek.Funs













open Aeneas Aeneas.Std Result
namespace curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable












@[progress]
theorem conditional_select_spec
    (a b : montgomery.MontgomeryPoint)
    (choice : subtle.Choice) :
    conditional_select a b choice ⦃ res =>
      ∀ i < 32,
        res[i]! = (if choice.val = 1#u8 then b[i]! else a[i]!) ⦄ := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable
