




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Basepoint
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromLimbs

set_option linter.style.nativeDecide false










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants


















@[progress]
theorem ED25519_BASEPOINT_POINT_spec :
    ED25519_BASEPOINT_POINT ⦃ (result : edwards.EdwardsPoint) =>
      result.IsValid ∧
      _root_.L • result.toPoint = 0 ∧
      result.toPoint ≠ 0 ∧
      4 • result.toPoint ≠ 0 ∧
      result.Z.toField ^ 2 - result.Y.toField ^ 2 =
        34737626771194858627071295502606372355980995399692169211837275202373938891970 ^ 2 ∧
      result.toPoint = _root_.Edwards.basepoint ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
