




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Ristretto.Representation

import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Field.FieldElement51.IsNegative
import Curve25519Dalek.Specs.Ristretto.CompressedRistretto.AsBytes













open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.ristretto.decompress


















































@[progress]
theorem step_1_spec (c : CompressedRistretto) :
    step_1 c ⦃ (s_encoding_is_canonical, s_is_negative, s) =>
    (∀ i < 5, s[i]!.val < 2^51) ∧
    s.IsValid ∧
    (s.toField = ((U8x32_as_Nat c % 2^255 : ℕ) : ZMod p)) ∧
    (s_encoding_is_canonical.val = 1#u8 ↔ U8x32_as_Nat c < p) ∧
    (s_is_negative.val = 1#u8 ↔ math.is_negative s.toField) ∧
    (ristretto.decompress_step1 c = some s.toField ↔
      (s_encoding_is_canonical.val = 1#u8 ∧ s_is_negative.val = 0#u8)) ⦄ := by
  sorry
end curve25519_dalek.ristretto.decompress
