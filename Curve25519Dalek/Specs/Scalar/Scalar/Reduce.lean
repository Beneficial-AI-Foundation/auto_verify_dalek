




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Scalar.Scalar.Unpack
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MulInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.R
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Invert









set_option linter.style.whitespace false
set_option exponentiation.threshold 260

open Aeneas Aeneas.Std Aeneas.Std.WP Result
open curve25519_dalek.backend.serial.u64
open curve25519_dalek.scalar.Scalar52
namespace curve25519_dalek.scalar.Scalar



















@[progress]
theorem reduce_spec (s : Scalar) :
    reduce s ⦃ (s' : Scalar) =>
      U8x32_as_Nat s'.bytes ≡ U8x32_as_Nat s.bytes [MOD L] ∧
      U8x32_as_Nat s'.bytes < L ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar
