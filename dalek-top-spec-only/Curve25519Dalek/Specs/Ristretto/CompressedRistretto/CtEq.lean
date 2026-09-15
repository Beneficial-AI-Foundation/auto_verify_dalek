/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.ristretto.CompressedRistretto.Insts.SubtleConstantTimeEq

@[progress]
theorem ct_eq_spec
    (self other : CompressedRistretto) :
    ct_eq self other ⦃ (result : subtle.Choice) =>
      result = Choice.one ↔ self = other ⦄ := by
  sorry

end curve25519_dalek.ristretto.CompressedRistretto.Insts.SubtleConstantTimeEq
