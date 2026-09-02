




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Field.FieldElement51.Invert
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Math.Montgomery.Representation











open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery
namespace curve25519_dalek.edwards.EdwardsPoint






























@[externally_verified, progress]
theorem to_montgomery_spec (e : EdwardsPoint)
    (h_Y_bounds : ∀ i < 5, e.Y[i]!.val < 2 ^ 53) (h_Z_bounds : ∀ i < 5, e.Z[i]!.val < 2 ^ 53) :
    to_montgomery e ⦃ mp =>
    (let Y := Field51_as_Nat e.Y
    let Z := Field51_as_Nat e.Z
    let u := U8x32_as_Nat mp
    if Z % p = Y % p then
      u % p = 0
    else
      (u * Z) % p = (u * Y + (Z + Y)) % p) ∧
    (∀ n : ℕ, fromEdwards (n • e.toPoint) = n • (MontgomeryPoint.mkPoint mp)) ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
