




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.MulByCofactor
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.Identity
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.CtEq










open Aeneas Aeneas.Std Result Aeneas.Std.WP Edwards
open curve25519_dalek.backend.serial.u64.field.FieldElement51
namespace curve25519_dalek.edwards.EdwardsPoint



















@[progress]
theorem is_small_order_spec (self : EdwardsPoint) (hself : self.IsValid) :
    is_small_order self ⦃ result =>
    (result ↔ h • self.toPoint = 0) ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
