




import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Field.FieldElement51.Invert
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open Montgomery

namespace curve25519_dalek.montgomery.ProjectivePoint
















lemma Field51_modP_ne_zero_of_toField_ne_zero
    (W : backend.serial.u64.field.FieldElement51)
    (hW : W.toField ≠ 0) :
    Field51_as_Nat W % p ≠ 0 := by
  sorry

lemma zmod_div_eq_mul_of_mod_inv (U W x_inv : Nat) (hW_ne : W % p ≠ 0) (h_inv : x_inv * W ≡ 1 [MOD p]) :
    (U : ZMod p) / (W : ZMod p) = (U : ZMod p) * (x_inv : ZMod p) := by
  sorry





@[progress]
theorem as_affine_spec (self : montgomery.ProjectivePoint)
    (hU : self.U.IsValid)
    (hW : self.W.IsValid)
    (h_valid : self.W.toField ≠ 0) :
    as_affine self ⦃ res => (U8x32_as_Field res = self.U.toField  / self.W.toField) ∧
    (U8x32_as_Nat res < 2 ^255)  ⦄ := by
  sorry
end curve25519_dalek.montgomery.ProjectivePoint
