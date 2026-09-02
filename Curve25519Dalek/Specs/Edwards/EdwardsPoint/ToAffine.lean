




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Field.FieldElement51.Invert
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul














open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.EdwardsPoint





























@[progress]
theorem to_affine_spec (e : EdwardsPoint)
    (hX : ∀ i < 5, e.X[i]!.val < 2 ^ 54)
    (hY : ∀ i < 5, e.Y[i]!.val < 2 ^ 54)
    (hZ : ∀ i < 5, e.Z[i]!.val < 2 ^ 54) :
    to_affine e ⦃ ap =>
      let X := Field51_as_Nat e.X
      let Y := Field51_as_Nat e.Y
      let Z := Field51_as_Nat e.Z
      let x := Field51_as_Nat ap.x
      let y := Field51_as_Nat ap.y
      (if Z % p = 0 then
        x % p = 0 ∧ y % p = 0
      else
        (x * Z) % p = X % p ∧
        (y * Z) % p = Y % p) ∧
        (∀ i < 5, ap.x[i]!.val < 2 ^ 52) ∧
        (∀ i < 5, ap.y[i]!.val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
