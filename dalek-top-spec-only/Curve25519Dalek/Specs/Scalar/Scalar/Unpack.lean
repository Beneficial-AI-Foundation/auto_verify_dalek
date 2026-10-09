import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytes

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.scalar.Scalar

end curve25519_dalek.scalar.Scalar

namespace curve25519_dalek.scalar.Scalar

/-- `unpack` converts the 32 little-endian bytes of a `Scalar` into five 52-bit limbs
representing the same natural number (no reduction modulo `L`). -/
@[progress]
theorem unpack_spec (self : Scalar) :
    unpack self ⦃ s =>
      Scalar52_as_Nat s = U8x32_as_Nat self.bytes ∧ (∀ i < 5, s[i]!.val < 2 ^ 52) ⦄ := by
  unfold unpack
  exact backend.serial.u64.scalar.Scalar52.from_bytes_spec self.bytes

end curve25519_dalek.scalar.Scalar
