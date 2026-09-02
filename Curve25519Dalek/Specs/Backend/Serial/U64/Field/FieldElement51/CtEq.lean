




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.SubtleConstantTimeEq






















@[progress]
theorem ct_eq_spec (a b : backend.serial.u64.field.FieldElement51) :
    ct_eq a b ⦃ c =>
    (c = Choice.one ↔ a.to_bytes = b.to_bytes ) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.SubtleConstantTimeEq
