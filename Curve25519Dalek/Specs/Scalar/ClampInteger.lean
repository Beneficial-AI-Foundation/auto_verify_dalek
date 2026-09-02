




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







@[progress]
theorem clamp_integer_spec (bytes : Array U8 32#usize) :
    clamp_integer bytes ⦃ result =>
    h ∣ U8x32_as_Nat result ∧
    U8x32_as_Nat result < 2^255 ∧
    2^254 ≤ U8x32_as_Nat result ⦄ := by
  sorry
end curve25519_dalek.scalar
