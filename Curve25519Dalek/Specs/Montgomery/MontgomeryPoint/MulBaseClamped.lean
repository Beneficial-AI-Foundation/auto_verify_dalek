




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Representation
import Curve25519Dalek.Specs.Montgomery.MontgomeryPoint.MulBase
import Curve25519Dalek.Specs.Scalar.ClampInteger











open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64
open Montgomery
namespace curve25519_dalek.montgomery.MontgomeryPoint






















@[progress]
theorem mul_base_clamped_spec (bytes : Array U8 32#usize) :
    mul_base_clamped bytes ⦃ result =>
    (∃ clamped_scalar_nat,
    h ∣ clamped_scalar_nat ∧
    clamped_scalar_nat < 2 ^ 255 ∧
    2 ^ 254 ≤ clamped_scalar_nat ∧
     MontgomeryPoint.mkPoint result = clamped_scalar_nat • (fromEdwards _root_.Edwards.basepoint)) ⦄    := by
  sorry
end curve25519_dalek.montgomery.MontgomeryPoint
