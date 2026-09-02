




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.Specs.Edwards.CompressedEdwardsY.AsBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.EDWARDS_D
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi























open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.constants
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51
open curve25519_dalek.backend.serial.u64.field
open curve25519_dalek.field.FieldElement51
open Edwards

namespace curve25519_dalek.edwards.CompressedEdwardsY

































@[progress]
theorem step_1_spec (cey : edwards.CompressedEdwardsY)
    (bytes : Aeneas.Std.Array U8 32#usize)
    (h_byter : cey.as_bytes = ok bytes) :
    edwards.decompress.step_1 cey ⦃ result =>
      let (is_valid_y_coord, X, Y, Z) := result
      let x := X.toField
      let y := Y.toField

      Field51_as_Nat Y ≡ (U8x32_as_Nat bytes % 2 ^ 255) [MOD p] ∧
      (∀ i < 5, Y[i]!.val < 2 ^ 51) ∧

      Field51_as_Nat Z = 1 ∧
      (∀ i < 5, Z[i]!.val < 2 ^ 51) ∧

      (∀ i < 5, X[i]!.val ≤ 2 ^ 53 - 1) ∧
      (Field51_as_Nat X % p) % 2 = 0 ∧


      (is_valid_y_coord.val = 1#u8 ↔
        ∃ x' : CurveField, Ed25519.a * x' ^ 2 + y ^ 2 = 1 + Ed25519.d * x' ^ 2 * y ^ 2) ∧

      (is_valid_y_coord.val = 1#u8 →
        Ed25519.a * x ^ 2 + y ^ 2 = 1 + Ed25519.d * x ^ 2 * y ^ 2) ⦄ := by
  sorry

end curve25519_dalek.edwards.CompressedEdwardsY
