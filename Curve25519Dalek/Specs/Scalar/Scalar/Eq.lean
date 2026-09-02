




import Curve25519Dalek.Funs
import Curve25519Dalek.Specs.Scalar.Scalar.CtEq












open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar.Insts.CoreCmpPartialEqScalar



















@[progress]
theorem eq_spec (self other : scalar.Scalar) :
    eq self other ⦃ result =>
    result = true ↔ self.bytes = other.bytes ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreCmpPartialEqScalar
