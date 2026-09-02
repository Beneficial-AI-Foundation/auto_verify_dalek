




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
















open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.field.FieldElement51

















theorem first_bit (bytes : Aeneas.Std.Array U8 32#usize) :
    U8x32_as_Nat bytes  % 2 = (bytes.val[0]).val %2 := by
  sorry
@[progress]
theorem is_negative_spec (r : backend.serial.u64.field.FieldElement51) :
    is_negative r ⦃ c =>
    (c.val = 1#u8 ↔ (Field51_as_Nat r % p) % 2 = 1) ⦄ := by
  sorry
end curve25519_dalek.field.FieldElement51
