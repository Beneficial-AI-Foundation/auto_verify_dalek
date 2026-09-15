import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Tactics
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.M

set_option exponentiation.threshold 416

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

attribute [-simp] Int.reducePow Nat.reducePow

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
