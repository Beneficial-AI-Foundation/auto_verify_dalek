




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Specs.Field.FieldElement51.Invert
import Curve25519Dalek.Specs.Edwards.CompressedEdwardsY.Decompress
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.MINUS_ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.CtEq
import Curve25519Dalek.Math.Montgomery.Representation













open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.montgomery.MontgomeryPoint
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.backend.serial.u64.field.FieldElement51





















@[progress]
private lemma ONE_bounds_spec : ONE ⦃ result => Field51_as_Nat result = 1 ∧ ∀ i < 5, result[i]!.val < 2 ^ 53 ⦄ := by
  unfold ONE from_limbs
  simp only [spec_ok]
  decide

@[progress]
theorem to_edwards_spec (mp : MontgomeryPoint) (sign : U8) :
      to_edwards mp sign ⦃ result =>
        (∀ ep, result = some ep →
          ∃ Z_inv,
            field.FieldElement51.invert ep.Z = ok Z_inv ∧
            let u := U8x32_as_Nat mp % 2^255
            let y := Field51_as_Nat ep.Y * Field51_as_Nat Z_inv % p
            (y * ((u + 1) % p)) % p = ((u + p - 1) % p) % p ∧ ep.IsValid )
      ⦄ := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint
