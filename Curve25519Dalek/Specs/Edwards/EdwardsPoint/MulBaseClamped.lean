




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Math.Edwards.Basepoint
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.MulBase
import Curve25519Dalek.Specs.Scalar.ClampInteger















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.edwards
open curve25519_dalek.backend.serial.u64

namespace curve25519_dalek.edwards.EdwardsPoint





















@[progress]
theorem mul_base_clamped_spec (bytes : Array U8 32#usize) :
    mul_base_clamped bytes ⦃ (result : EdwardsPoint) =>
      EdwardsPoint.IsValid result ∧
      (∃ clamped_scalar,
      h ∣ U8x32_as_Nat clamped_scalar ∧
      U8x32_as_Nat clamped_scalar < 2 ^ 255 ∧
      2 ^ 254 ≤ U8x32_as_Nat clamped_scalar ∧
      result.toPoint = ((U8x32_as_Nat clamped_scalar) • _root_.Edwards.basepoint)) ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
