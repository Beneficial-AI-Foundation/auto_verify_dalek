/-
Copyright (c) 2025 Oliver Butterley. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aeneas
import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ConditionalAddL

set_option exponentiation.threshold 260

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

attribute [-simp] Int.reducePow Nat.reducePow

def Scalar52_partial_as_Nat (limbs : Array U64 5#usize) (n : Nat) : Nat :=
  ∑ j ∈ Finset.range n, 2 ^ (52 * j) * (limbs[j]!).val

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
