




import Curve25519Dalek.Aux
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.CtEq
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes

import Mathlib.Data.Nat.ModEq













open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field.FieldElement51

namespace curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConstantTimeEq

























@[progress]
theorem ct_eq_spec (self other : AffinePoint) :
  ct_eq self other ⦃ c =>
  (c = Choice.one ↔
    (Field51_as_Nat self.x) ≡ (Field51_as_Nat other.x) [MOD p] ∧
    (Field51_as_Nat self.y) ≡ (Field51_as_Nat other.y) [MOD p]) ∧
  (self.IsValid → other.IsValid → (c = Choice.one ↔ self.toPoint = other.toPoint)) ⦄ := by
  sorry
end curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConstantTimeEq
