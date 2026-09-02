




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes

set_option linter.style.longLine false
set_option linter.style.setOption false











open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.field.FieldElement51
















lemma array_eq_of_to_slice_eq {α : Type} {n : Usize} {h1 h2 : Array α n}
    (h : h1.to_slice = h2.to_slice) :
    h1 = h2 := by
  sorry















private def Hold (P : Prop) : Prop := P

@[progress]
theorem is_zero_spec (r : backend.serial.u64.field.FieldElement51) :
    is_zero r ⦃ c =>
    (c.val = 1#u8 ↔ Field51_as_Nat r % p = 0) ⦄ := by
  sorry

end curve25519_dalek.field.FieldElement51
