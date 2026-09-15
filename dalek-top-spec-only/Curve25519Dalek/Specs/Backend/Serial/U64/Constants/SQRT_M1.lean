/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants

def SQRT_M1_raw : backend.serial.u64.field.FieldElement51 :=
  Array.make 5#usize [1718705420411056#u64, 234908883556509#u64, 2233514472574048#u64,
    2117202627021982#u64, 765476049583133#u64]

end curve25519_dalek.backend.serial.u64.constants
