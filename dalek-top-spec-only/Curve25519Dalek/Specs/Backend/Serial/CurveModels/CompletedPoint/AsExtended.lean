import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.curve_models.CompletedPoint

/-- Converting a completed point `((X:Z),(Y:T))` to extended coordinates:
`X' = X·T`, `Y' = Y·Z`, `Z' = Z·T`, `T' = X·Y` (mod p), with output limbs `< 2^52`. -/
@[progress]
theorem as_extended_spec (q : CompletedPoint)
    (h_qX_bounds : ∀ i < 5, (q.X[i]!).val < 2 ^ 54)
    (h_qY_bounds : ∀ i < 5, (q.Y[i]!).val < 2 ^ 54)
    (h_qZ_bounds : ∀ i < 5, (q.Z[i]!).val < 2 ^ 54)
    (h_qT_bounds : ∀ i < 5, (q.T[i]!).val < 2 ^ 54) :
    as_extended q ⦃ e =>
      (∀ i < 5, (e.X[i]!).val < 2 ^ 52) ∧
      (∀ i < 5, (e.Y[i]!).val < 2 ^ 52) ∧
      (∀ i < 5, (e.Z[i]!).val < 2 ^ 52) ∧
      (∀ i < 5, (e.T[i]!).val < 2 ^ 52) ∧
      Field51_as_Nat e.X % p = (Field51_as_Nat q.X * Field51_as_Nat q.T) % p ∧
      Field51_as_Nat e.Y % p = (Field51_as_Nat q.Y * Field51_as_Nat q.Z) % p ∧
      Field51_as_Nat e.Z % p = (Field51_as_Nat q.Z * Field51_as_Nat q.T) % p ∧
      Field51_as_Nat e.T % p = (Field51_as_Nat q.X * Field51_as_Nat q.Y) % p ⦄ := by
  unfold as_extended
  progress as ⟨fe, hfe_b, hfe⟩
  progress as ⟨fe1, hfe1_b, hfe1⟩
  progress as ⟨fe2, hfe2_b, hfe2⟩
  progress as ⟨fe3, hfe3_b, hfe3⟩
  exact ⟨hfe_b, hfe1_b, hfe2_b, hfe3_b, hfe, hfe1, hfe2, hfe3⟩

end curve25519_dalek.backend.serial.curve_models.CompletedPoint
