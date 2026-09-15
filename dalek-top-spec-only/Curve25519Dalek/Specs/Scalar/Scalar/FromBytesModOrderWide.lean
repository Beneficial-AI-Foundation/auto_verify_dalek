/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ToBytes

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.scalar.Scalar

@[progress]
theorem from_bytes_mod_order_wide_spec (input : Array U8 64#usize) :
    from_bytes_mod_order_wide input ⦃ (result : Scalar) =>
      U8x32_as_Nat result.bytes ≡ U8x64_as_Nat input [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  sorry

end curve25519_dalek.scalar.Scalar
