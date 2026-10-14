import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.AddAssign

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51

/-- `a + b` adds the limbs pointwise (no reduction); limbs must be small enough
not to overflow. -/
@[progress]
theorem add_spec (self _rhs : backend.serial.u64.field.FieldElement51)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 63)
    (hb : ∀ i < 5, _rhs[i]!.val < 2 ^ 63) :
    add self _rhs ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val = self[i]!.val + _rhs[i]!.val) ∧
      Field51_as_Nat result = Field51_as_Nat self + Field51_as_Nat _rhs ⦄ := by
  unfold add
  progress with
    backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51.add_assign_spec
    as ⟨r, h1, h2⟩
  exact ⟨h1, h2⟩

end curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51
