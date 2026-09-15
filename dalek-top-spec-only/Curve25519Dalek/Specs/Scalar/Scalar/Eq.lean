/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar.Insts.CoreCmpPartialEqScalar

@[progress]
theorem eq_spec (self other : scalar.Scalar) :
    eq self other ⦃ result =>
    result = true ↔ self.bytes = other.bytes ⦄ := by
  sorry

end curve25519_dalek.scalar.Scalar.Insts.CoreCmpPartialEqScalar
