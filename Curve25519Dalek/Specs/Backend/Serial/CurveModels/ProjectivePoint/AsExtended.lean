




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square












open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.curve_models.ProjectivePoint


































@[progress]
theorem as_extended_spec (q : ProjectivePoint)
  (h_qX_bounds : ∀ i, i < 5 → (q.X[i]!).val < 2 ^ 54)
  (h_qY_bounds : ∀ i, i < 5 → (q.Y[i]!).val < 2 ^ 54)
  (h_qZ_bounds : ∀ i, i < 5 → (q.Z[i]!).val < 2 ^ 54) :
as_extended q ⦃ e =>
let X := Field51_as_Nat q.X
let Y := Field51_as_Nat q.Y
let Z := Field51_as_Nat q.Z
let X' := Field51_as_Nat e.X
let Y' := Field51_as_Nat e.Y
let Z' := Field51_as_Nat e.Z
let T' := Field51_as_Nat e.T
X' % p = (X * Z) % p ∧
Y' % p = (Y * Z) % p ∧
Z' % p = (Z^2) % p ∧
T' % p = (X * Y) % p ⦄
:= by
  sorry
end curve25519_dalek.backend.serial.curve_models.ProjectivePoint
