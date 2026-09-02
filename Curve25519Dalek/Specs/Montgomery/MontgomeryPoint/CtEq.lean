




import Curve25519Dalek.Aux
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.CtEq
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes

import Mathlib.Data.Nat.ModEq













open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field.FieldElement51
namespace curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConstantTimeEq





















@[progress]
theorem ct_eq_spec (u v : MontgomeryPoint) :
    ct_eq u v ⦃ c =>
    (c = Choice.one ↔
      (U8x32_as_Nat u % 2 ^ 255) ≡ (U8x32_as_Nat v % 2 ^ 255) [MOD p]) ⦄ := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConstantTimeEq
