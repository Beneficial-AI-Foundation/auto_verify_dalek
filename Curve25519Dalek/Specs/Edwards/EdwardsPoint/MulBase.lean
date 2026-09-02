




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Edwards.Basepoint
import Curve25519Dalek.ExternallyVerified















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.montgomery
open curve25519_dalek.backend.serial.u64
namespace curve25519_dalek.edwards.EdwardsPoint




















@[externally_verified, progress]
theorem mul_base_spec (scalar : scalar.Scalar) :
    mul_base scalar ⦃ res =>
    EdwardsPoint.IsValid res ∧
    res.toPoint = (U8x32_as_Nat scalar.bytes) • _root_.Edwards.basepoint ⦄ := by
    sorry

end curve25519_dalek.edwards.EdwardsPoint
