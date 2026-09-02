




import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes


















open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51






@[progress]
theorem as_bytes_spec (self : backend.serial.u64.field.FieldElement51) :
    as_bytes self ⦃ result =>
    U8x32_as_Nat result ≡ Field51_as_Nat self [MOD p] ∧
    U8x32_as_Nat result < p ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
