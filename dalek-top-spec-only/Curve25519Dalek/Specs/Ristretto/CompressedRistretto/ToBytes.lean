/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.ristretto.CompressedRistretto

@[progress]
theorem to_bytes_spec (cr : CompressedRistretto) :
    to_bytes cr ⦃ b =>
    b = cr ⦄ := by
  sorry

end curve25519_dalek.ristretto.CompressedRistretto
