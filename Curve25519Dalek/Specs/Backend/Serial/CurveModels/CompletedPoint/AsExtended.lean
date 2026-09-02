




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul













open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field

namespace curve25519_dalek.backend.serial.curve_models.CompletedPoint
































@[progress]
theorem as_extended_spec (q : CompletedPoint)
  (h_q_Valid : q.IsValid) :
  as_extended q ⦃ (e : edwards.EdwardsPoint) =>
    let X := Field51_as_Nat q.X
    let Y := Field51_as_Nat q.Y
    let Z := Field51_as_Nat q.Z
    let T := Field51_as_Nat q.T
    let X' := Field51_as_Nat e.X
    let Y' := Field51_as_Nat e.Y
    let Z' := Field51_as_Nat e.Z
    let T' := Field51_as_Nat e.T
    X' % p = (X * T) % p ∧
    Y' % p = (Y * Z) % p ∧
    Z' % p = (Z * T) % p ∧
    T' % p = (X * Y) % p ∧
    (∀ i < 5, e.X[i]!.val < 2 ^ 52) ∧
    (∀ i < 5, e.Y[i]!.val < 2 ^ 52) ∧
    (∀ i < 5, e.Z[i]!.val < 2 ^ 52) ∧
    (∀ i < 5, e.T[i]!.val < 2 ^ 52) ∧
    e.IsValid ∧
    e.toPoint = q.toPoint ⦄ := by
  sorry
end curve25519_dalek.backend.serial.curve_models.CompletedPoint
