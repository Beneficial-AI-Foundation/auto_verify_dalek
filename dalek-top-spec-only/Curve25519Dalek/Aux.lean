import Aeneas
import Curve25519Dalek.Math.Basic
import Mathlib.Data.Nat.Digits.Lemmas
import Mathlib.Algebra.Order.BigOperators.Group.Finset

set_option linter.style.longLine false

set_option linter.hashCommand false
#setup_aeneas_simps

open Aeneas.Std Result

attribute [-simp] Int.reducePow Nat.reducePow

