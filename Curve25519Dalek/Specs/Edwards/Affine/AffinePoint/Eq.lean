




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Edwards.Affine.AffinePoint.CtEq












open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field
namespace curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint




@[simp]
theorem Choice.eq_one (c : subtle.Choice) : c.val = 1#u8 → c = Choice.one := by
  sorry

@[simp]
theorem Choice.eq_zero (c : subtle.Choice) : c.val = 0#u8 → c = Choice.zero := by
  sorry


















@[progress]
theorem eq_spec (self other : AffinePoint) (h_self_valid : self.IsValid) (h_other_valid : other.IsValid) :
    eq self other ⦃ result =>
    result = true ↔ self.toPoint = other.toPoint ⦄ := by
  sorry
end curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint
