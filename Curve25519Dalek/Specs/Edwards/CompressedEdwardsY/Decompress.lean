




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Edwards.Curve
import Curve25519Dalek.ExternallyVerified



















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field
open Edwards

namespace curve25519_dalek.edwards.CompressedEdwardsY































@[progress, externally_verified]
theorem decompress_spec (cey : edwards.CompressedEdwardsY) :
    edwards.CompressedEdwardsY.decompress cey ⦃ result =>
      let y : CurveField := (U8x32_as_Nat cey % 2 ^ 255 : CurveField)
      let x_sign_bit := cey[31]!.val.testBit 7

      (result.isSome ↔ ∃ pt : Point Ed25519, pt.y = y) ∧

      (∀ ep, result = some ep →

        ep.IsValid ∧

        ep.Y.toField = y ∧
        Field51_as_Nat ep.Y ≡ (U8x32_as_Nat cey % 2 ^ 255) [MOD p] ∧

        ep.Z.toField = 1 ∧
        Field51_as_Nat ep.Z % p = 1 ∧
        ep.T.toField = ep.X.toField * ep.Y.toField ∧


        (y ^ 2 ≠ 1 →
          (x_sign_bit ↔ (Field51_as_Nat ep.X % p) % 2 = 1))) ⦄ := by
  sorry

end curve25519_dalek.edwards.CompressedEdwardsY
