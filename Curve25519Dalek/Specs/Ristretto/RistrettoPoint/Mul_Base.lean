




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Math.Edwards.Basepoint
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Ristretto.RistrettoPoint.Mul
import Curve25519Dalek.Specs.Constants.RISTRETTO_BASEPOINT_POINT














open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.ristretto.RistrettoPoint






















@[progress]
theorem mul_base_spec (s : scalar.Scalar) (h_s_canonical : U8x32_as_Nat s.bytes < 2 ^ 255) :
    mul_base s ⦃ (result : RistrettoPoint) =>
      result.IsValid ∧
      result.toPoint = (U8x32_as_Nat s.bytes) • _root_.Edwards.basepoint ⦄ := by
  sorry
end curve25519_dalek.ristretto.RistrettoPoint
