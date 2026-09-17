/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants

def SQRT_AD_MINUS_ONE_raw : backend.serial.u64.field.FieldElement51 :=
  Array.make 5#usize [2241493124984347#u64, 425987919032274#u64, 2207028919301688#u64,
    1220490630685848#u64, 974799131293748#u64]

end curve25519_dalek.backend.serial.u64.constants
