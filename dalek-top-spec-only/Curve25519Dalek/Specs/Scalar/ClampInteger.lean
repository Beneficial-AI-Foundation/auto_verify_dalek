/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Funs
import Mathlib.Tactic.IntervalCases
import Mathlib.Tactic.GCongr
import Mathlib.Algebra.BigOperators.Ring.Finset

set_option linter.style.setOption false
set_option grind.warning false

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek
open scalar

attribute [-simp] Int.reducePow Nat.reducePow

attribute [bvify_simps] Nat.dvd_iff_mod_eq_zero

namespace curve25519_dalek.scalar

end curve25519_dalek.scalar
