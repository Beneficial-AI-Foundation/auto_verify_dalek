




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Edwards.CompressedEdwardsY.AsBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Neg
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ConditionalAssign


















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithNegFieldElement51
open curve25519_dalek.backend.serial.u64.field

namespace curve25519_dalek.edwards.CompressedEdwardsY





























@[progress]
theorem step_2_spec
    (repr : edwards.CompressedEdwardsY)
    (X : backend.serial.u64.field.FieldElement51)
    (Y : backend.serial.u64.field.FieldElement51)
    (Z : backend.serial.u64.field.FieldElement51)
    (bytes : Aeneas.Std.Array U8 32#usize)
    (sign_bit : Bool)
    (h_repr : repr.as_bytes = ok bytes)
    (h_byter : sign_bit = (bytes[31]!.val.testBit 7))
    (hX : ∀ i < 5, X[i]!.val ≤ 2 ^ 53 - 1)
    (hY : ∀ i < 5, Y[i]!.val < 2 ^ 51) :
    edwards.decompress.step_2 repr X Y Z ⦃ result =>
      result.Y = Y ∧
      result.Z = Z ∧
      (if sign_bit then
        result.X.toField = -X.toField
      else
        result.X = X) ∧
      (∀ i < 5, result.X[i]!.val ≤ 2 ^ 53 - 1) ∧
      result.T.toField = result.X.toField * Y.toField ∧
      (∀ i < 5, result.T[i]!.val < 2 ^ 52) ⦄ := by
  sorry

end curve25519_dalek.edwards.CompressedEdwardsY
