




import Curve25519Dalek.Aux
import Curve25519Dalek.ExternallyVerified
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.L
import Mathlib.Data.Nat.ModEq











set_option exponentiation.threshold 280

attribute [-simp] Int.reducePow Nat.reducePow

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52












set_option maxHeartbeats 300000 in






@[progress]
theorem add_loop_spec (a b sum : Scalar52) (mask carry : U64) (i : Usize)
    (ha : ∀ j < 5, a[j]!.val < 2 ^ 52) (hb : ∀ j < 5, b[j]!.val < 2 ^ 52)
    (ha' : Scalar52_as_Nat a < 2 ^ 259) (hb' : Scalar52_as_Nat b < 2 ^ 259)
    (hmask : mask.val = 2 ^ 52 - 1) (hi : i.val ≤ 5)
    (hcarry : i.val = 5 → carry.val < 2 ^ 52)
    (hcarry' : ∀ i < 5, carry.val < 2 ^ 53)
    (hsum : ∀ j < 5, sum[j]!.val < 2 ^ 52)
    (hsum' : ∀ j < 5, i.val ≤ j → sum[j]!.val = 0) :
    add_loop a b sum mask carry i ⦃ (sum' : Scalar52) =>
      (∀ j < 5, sum'[j]!.val < 2 ^ 52) ∧
      (∀ j < i.val, sum'[j]!.val = sum[j]!.val) ∧
      ∑ j ∈ Finset.Ico i.val 5, 2 ^ (52 * j) * sum'[j]!.val =
        ∑ j ∈ Finset.Ico i.val 5, 2 ^ (52 * j) * (a[j]!.val + b[j]!.val) +
        2 ^ (52 * i.val) * (carry.val / 2 ^ 52) ⦄ := by
  sorry




@[progress]
theorem add_spec (a b : Scalar52)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 52) (hb : ∀ i < 5, b[i]!.val < 2 ^ 52)
    (ha' : Scalar52_as_Nat a < L) (hb' : Scalar52_as_Nat b ≤ L) :
    add a b ⦃ (v : Scalar52) =>
      Scalar52_as_Nat v ≡ Scalar52_as_Nat a + Scalar52_as_Nat b [MOD L] ∧
      Scalar52_as_Nat v < L ∧ ∀ i < 5, v[i]!.val < 2 ^ 52 ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
