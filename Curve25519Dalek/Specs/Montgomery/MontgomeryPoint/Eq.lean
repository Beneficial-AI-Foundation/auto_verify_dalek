




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Montgomery.MontgomeryPoint.CtEq













open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCmpPartialEqMontgomeryPoint





















@[progress]
theorem eq_spec (u v : MontgomeryPoint) :
    eq u v ⦃ b =>
    (b = true ↔
      (U8x32_as_Nat u % 2 ^ 255) ≡ (U8x32_as_Nat v % 2 ^ 255) [MOD p]) ⦄ := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCmpPartialEqMontgomeryPoint
