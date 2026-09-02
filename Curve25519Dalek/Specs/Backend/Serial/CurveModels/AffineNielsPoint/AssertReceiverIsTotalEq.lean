




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic












open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpEq


















@[progress]
theorem assert_receiver_is_total_eq_spec
    (self : backend.serial.curve_models.AffineNielsPoint) :
    assert_receiver_is_total_eq self ⦃ result => result = () ⦄ := by
  simp [assert_receiver_is_total_eq]
end curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpEq
