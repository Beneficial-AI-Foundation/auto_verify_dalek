




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.field.FieldElement51














@[progress]
theorem negate_spec (self : FieldElement51) (h : ∀ i < 5, self[i]!.val < 2 ^ 54) :
    negate self ⦃ (neg : FieldElement51) =>
      Field51_as_Nat self + Field51_as_Nat neg ≡ 0 [MOD p] ∧
      ∀ i < 5, neg[i]!.val < 2 ^ 52 ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
