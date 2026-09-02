




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.Add










open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.ristretto
namespace curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithAddSharedARistrettoPointRistrettoPoint





















@[progress]
theorem add_spec (self other : RistrettoPoint) (h_self_valid : self.IsValid) (h_other_valid : other.IsValid) :
    add self other ⦃ (result : RistrettoPoint) =>
      result.IsValid ∧
      result.toPoint = self.toPoint + other.toPoint ⦄ := by
  sorry
































end curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithAddSharedARistrettoPointRistrettoPoint
