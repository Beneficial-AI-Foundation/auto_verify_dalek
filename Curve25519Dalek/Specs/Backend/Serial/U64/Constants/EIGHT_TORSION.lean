




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.EightTorsion
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromLimbs


















open Aeneas Aeneas.Std Result Edwards
namespace curve25519_dalek.backend.serial.u64.constants
























@[progress]
theorem EIGHT_TORSION_spec :
    EIGHT_TORSION ⦃ result =>
      let P := result.val[1]
      P.IsValid ∧ 4 • P.toPoint ≠ 0 ∧ 8 • P.toPoint = 0 ∧
      (∀ (i : Fin 8), result.val[i].IsValid) ∧
      (∀ (i : Fin 8), result.val[i].toPoint = (i : ℕ) • P.toPoint) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
