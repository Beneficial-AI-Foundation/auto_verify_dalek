




import Curve25519Dalek.Aux
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.CtEq
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Field.FieldElement51.IsZero

import Mathlib.Data.Nat.ModEq










open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field.FieldElement51

namespace curve25519_dalek.edwards.EdwardsPoint.Insts.SubtleConstantTimeEq






















@[progress]
theorem ct_eq_spec (e1 e2 : EdwardsPoint)

  (h_e1_X : ∀ i, i < 5 → e1.X.val[i]!.val ≤ 2 ^ 53)
  (h_e1_Y : ∀ i, i < 5 → e1.Y.val[i]!.val ≤ 2 ^ 53)
  (h_e1_Z : ∀ i, i < 5 → e1.Z.val[i]!.val ≤ 2 ^ 53)
  (h_e2_X : ∀ i, i < 5 → e2.X.val[i]!.val ≤ 2 ^ 53)
  (h_e2_Y : ∀ i, i < 5 → e2.Y.val[i]!.val ≤ 2 ^ 53)
  (h_e2_Z : ∀ i, i < 5 → e2.Z.val[i]!.val ≤ 2 ^ 53) :
  ct_eq e1 e2 ⦃ c =>
  (c = Choice.one ↔
    (Field51_as_Nat e1.X * Field51_as_Nat e2.Z) ≡ (Field51_as_Nat e2.X * Field51_as_Nat e1.Z) [MOD p] ∧
    (Field51_as_Nat e1.Y * Field51_as_Nat e2.Z) ≡ (Field51_as_Nat e2.Y * Field51_as_Nat e1.Z) [MOD p]) ∧
  (e1.IsValid → e2.IsValid → (c = Choice.one ↔ e1.toPoint = e2.toPoint)) ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint.Insts.SubtleConstantTimeEq
