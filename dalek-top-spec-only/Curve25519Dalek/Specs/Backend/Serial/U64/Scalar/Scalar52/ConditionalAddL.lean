/-
Copyright 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux

attribute [-simp] Int.reducePow Nat.reducePow
set_option exponentiation.threshold 260

namespace curve25519_dalek
open Aeneas Aeneas.Std Aeneas.Std.WP Result

attribute [-progress] U64.Insts.SubtleConditionallySelectable.conditional_select_spec
end curve25519_dalek

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
