import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Pow2K

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

/-- `square self` computes `self ^ 2` modulo `p`, with output limbs bounded by `2 ^ 52`. -/
@[progress]
theorem square_spec (self : backend.serial.u64.field.FieldElement51)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 54) :
    square self ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val < 2 ^ 52) ∧
      Field51_as_Nat result % p = Field51_as_Nat self ^ 2 % p ⦄ := by
  unfold square
  progress with pow2k_spec self 1#u32 (by decide) ha as ⟨r, hr1, hr2⟩
  exact ⟨hr1, by simpa using hr2⟩

end curve25519_dalek.backend.serial.u64.field.FieldElement51
