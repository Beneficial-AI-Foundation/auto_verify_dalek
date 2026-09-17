/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar

@[progress]
theorem to_bytes_spec (s : Scalar) :
    to_bytes s ⦃ a =>
    a = s.bytes ∧ mk a = s ⦄ := by
  sorry

end curve25519_dalek.scalar.Scalar
