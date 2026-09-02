




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.Mul
import Curve25519Dalek.Specs.Scalar.ClampInteger






















open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.edwards
open curve25519_dalek.backend.serial.u64



namespace curve25519_dalek.edwards.EdwardsPoint

























@[progress]
theorem mul_clamped_spec (self : EdwardsPoint) (bytes : Array U8 32#usize)
    (h_self_valid : self.IsValid) :
    mul_clamped self bytes ⦃ (result : EdwardsPoint) =>
      EdwardsPoint.IsValid result ∧
      (∃ clamped_scalar,
      h ∣ U8x32_as_Nat clamped_scalar ∧
      U8x32_as_Nat clamped_scalar < 2 ^ 255 ∧
      2 ^ 254 ≤ U8x32_as_Nat clamped_scalar ∧
      result.toPoint = (((U8x32_as_Nat clamped_scalar)) • self.toPoint)) ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
