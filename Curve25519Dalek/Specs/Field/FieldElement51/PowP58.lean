




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Field.FieldElement51.Pow22501
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Pow2K
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul










open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51
  (mul_spec)
namespace curve25519_dalek.field.FieldElement51


















@[progress]
theorem pow_p58_spec (r : backend.serial.u64.field.FieldElement51)
    (h_bounds : ∀ i, i < 5 → (r[i]!).val ≤ 2 ^ 52 - 1) :
    pow_p58 r ⦃ r' =>
      Field51_as_Nat r' % p = (Field51_as_Nat r ^ (2 ^ 252 - 3)) % p ∧
      (∀ i < 5, r'[i]!.val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.field.FieldElement51
