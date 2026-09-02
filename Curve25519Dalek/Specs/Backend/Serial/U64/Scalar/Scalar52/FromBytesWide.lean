




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified











open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52














@[externally_verified, progress]
theorem from_bytes_wide_spec (b : Array U8 64#usize) :
    from_bytes_wide b ⦃ (u : Scalar52) =>
        Scalar52_as_Nat u = U8x64_as_Nat b % L ∧
        ∀ i < 5, u[i]!.val < 2 ^ 52 ⦄ := by
  sorry

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
