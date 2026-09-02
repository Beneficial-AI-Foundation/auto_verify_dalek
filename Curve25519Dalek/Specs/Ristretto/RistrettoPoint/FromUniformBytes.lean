




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Specs.Ristretto.RistrettoPoint.ElligatorRistrettoFlavor
import Curve25519Dalek.Specs.Ristretto.RistrettoPoint.Add












open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.math
namespace curve25519_dalek.ristretto.RistrettoPoint




























@[reducible]
def bytes_lower (bytes : Array U8 64#usize) : Array U8 32#usize :=
  ⟨(List.range 32).map (fun i => bytes[i]!), by simp⟩


@[reducible]
def bytes_upper (bytes : Array U8 64#usize) : Array U8 32#usize :=
  ⟨(List.range 32).map (fun i => bytes[32 + i]!), by simp⟩


@[reducible]
def field_from_bytes (b : Array U8 32#usize) : ZMod p :=
  ((U8x32_as_Nat b % 2^255 : ℕ) : ZMod p)






@[progress]
theorem from_uniform_bytes_spec (bytes : Array U8 64#usize) :
    from_uniform_bytes bytes ⦃ (result : RistrettoPoint) =>
      result.IsValid ∧
      result.toPoint =
        (elligator_ristretto_flavor_pure (field_from_bytes (bytes_lower bytes))).val +
        (elligator_ristretto_flavor_pure (field_from_bytes (bytes_upper bytes))).val
      ⦄ := by
  sorry
end curve25519_dalek.ristretto.RistrettoPoint
