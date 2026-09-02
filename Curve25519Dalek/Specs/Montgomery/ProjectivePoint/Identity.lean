




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ZERO
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromLimbs











open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek
open backend.serial.u64.field.FieldElement51
namespace curve25519_dalek.IdentityMontgomeryProjectivePoint























@[progress]
theorem identity_spec :
    identity ⦃ (q : montgomery.ProjectivePoint) =>
      Field51_as_Nat q.U = 1 ∧
      Field51_as_Nat q.W = 0 ⦄ := by
  sorry
end curve25519_dalek.IdentityMontgomeryProjectivePoint
