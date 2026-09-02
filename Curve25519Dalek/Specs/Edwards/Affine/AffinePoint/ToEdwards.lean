




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE












open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.edwards.affine.AffinePoint
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.backend.serial.u64.field.FieldElement51





















@[progress]
private lemma ONE_bounds_spec :
    ONE ⦃ result => Field51_as_Nat result = 1 ∧ ∀ i < 5, result[i]!.val < 2 ^ 53 ⦄ := by
  unfold ONE from_limbs
  simp only [spec_ok]
  decide








@[progress]
theorem to_edwards_spec (self : AffinePoint) (hself : self.IsValid)
  (hx53 : ∀ i < 5, self.x[i]!.val < 2 ^ 53)
  (hy53 : ∀ i < 5, self.y[i]!.val < 2 ^ 53) :
    to_edwards self ⦃ result =>
      result.X = self.x ∧ result.Y = self.y ∧
      Field51_as_Nat result.Z = 1 ∧
      Field51_as_Nat result.T % p = (Field51_as_Nat self.x * Field51_as_Nat self.y) % p ∧
      (∀ i < 5, result.T[i]!.val < 2 ^ 52) ∧
      (∀ i < 5, result.Z[i]!.val < 2 ^ 53) ∧
      result.IsValid ⦄ := by
  sorry
end curve25519_dalek.edwards.affine.AffinePoint
