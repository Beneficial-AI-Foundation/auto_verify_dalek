




import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Pow2K









open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.field.FieldElement51




















@[progress]
theorem square_spec (a : Array U64 5#usize) (ha : ∀ i < 5, a[i]!.val < 2 ^ 54) :
    square a ⦃ r =>
    Field51_as_Nat r ≡ (Field51_as_Nat a)^2 [MOD p] ∧ (∀ i < 5, r[i]!.val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51
