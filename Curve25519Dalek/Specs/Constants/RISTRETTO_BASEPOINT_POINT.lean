




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.ED25519_BASEPOINT_POINT










open Aeneas Aeneas.Std Result Edwards
open curve25519_dalek.backend.serial.u64.field (FieldElement51.toField)
open curve25519_dalek.ristretto
namespace curve25519_dalek.constants
































@[progress]
theorem RISTRETTO_BASEPOINT_POINT_spec :
    RISTRETTO_BASEPOINT_POINT ⦃ (result : RistrettoPoint) =>
      result.IsValid ∧ _root_.L • result.toPoint = 0 ∧
      result.toPoint ≠ 0 ∧ 4 • result.toPoint ≠ 0 ∧
      result.toPoint = _root_.Edwards.basepoint ⦄ := by
  sorry
end curve25519_dalek.constants
