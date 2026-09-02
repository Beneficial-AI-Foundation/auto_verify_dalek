




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.CtEq
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Mathlib.Data.Nat.ModEq

















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field.FieldElement51

namespace curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConstantTimeEq

































@[progress]
theorem ct_eq_spec
    (self other : RistrettoPoint)
    (h_self_valid : self.IsValid)
    (h_other_valid : other.IsValid) :
    ct_eq self other ⦃ (result : subtle.Choice) =>
      result = Choice.one ↔
        (Field51_as_Nat self.X * Field51_as_Nat other.Y) ≡ (Field51_as_Nat self.Y * Field51_as_Nat other.X) [MOD p] ∨
        (Field51_as_Nat self.X * Field51_as_Nat other.X) ≡ (Field51_as_Nat self.Y * Field51_as_Nat other.Y) [MOD p] ⦄ := by
  sorry
end curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConstantTimeEq
