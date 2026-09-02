




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytes










open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.scalar.Scalar52
open curve25519_dalek.backend.serial.u64.scalar
namespace curve25519_dalek.scalar.Scalar


















@[progress]
theorem unpack_spec (self : Scalar) :
    unpack self ⦃ (u : Scalar52 ) =>
        Scalar52_as_Nat u = U8x32_as_Nat self.bytes ∧
        ∀ i < 5, u[i]!.val < 2 ^ 62 ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
