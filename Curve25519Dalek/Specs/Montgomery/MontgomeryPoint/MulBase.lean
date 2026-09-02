




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.MulBase
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.ToMontgomery
import Curve25519Dalek.Math.Edwards.Basepoint
import Curve25519Dalek.ExternallyVerified















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64
open Montgomery
namespace curve25519_dalek.montgomery.MontgomeryPoint






















@[externally_verified, progress]
theorem mul_base_spec (scalar : scalar.Scalar) :
    mul_base scalar ⦃ result =>
    Montgomery.MontgomeryPoint.mkPoint result = (U8x32_as_Nat scalar.bytes) • (fromEdwards _root_.Edwards.basepoint) ⦄
     := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint
