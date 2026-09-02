




import Aeneas
import Curve25519Dalek.Funs
import Curve25519Dalek.Aux
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ConditionalAddL
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Zero

set_option exponentiation.threshold 260



































open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52


attribute [-simp] Int.reducePow Nat.reducePow




def Scalar52_partial_as_Nat (limbs : Array U64 5#usize) (n : Nat) : Nat :=
  ∑ j ∈ Finset.range n, 2 ^ (52 * j) * (limbs[j]!).val

set_option maxHeartbeats 300000 in












@[progress]
theorem sub_loop_spec (a b difference : Scalar52) (mask borrow : U64) (i : Usize)
    (ha : ∀ j < 5, a[j]!.val < 2 ^ 52)
    (hb : ∀ j < 5, b[j]!.val < 2 ^ 52)
    (hdiff : ∀ j < i.val, difference[j]!.val < 2 ^ 52)
    (hdiff_rest : ∀ j, i.val ≤ j → j < 5 → difference[j]!.val = 0)
    (hmask : mask.val = 2 ^ 52 - 1)
    (hi : i.val ≤ 5)
    (hborrow : borrow.val / 2 ^ 63 ≤ 1)
    (hinv : Scalar52_partial_as_Nat a i.val + borrow.val / 2 ^ 63 * 2 ^ (52 * i.val) =
            Scalar52_partial_as_Nat b i.val + Scalar52_partial_as_Nat difference i.val) :
    sub_loop a b difference mask borrow i ⦃ result =>
    (∀ j < 5, result.1[j]!.val < 2 ^ 52) ∧
    (Scalar52_as_Nat a + result.2.val / 2 ^ 63 * 2 ^ 260 =
     Scalar52_as_Nat b + Scalar52_as_Nat result.1) ⦄ := by
  sorry





@[progress]
theorem sub_spec (a b : Array U64 5#usize)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 52)
    (hb : ∀ i < 5, b[i]!.val < 2 ^ 52)
    (ha' : Scalar52_as_Nat a < Scalar52_as_Nat b + L)
    (hb' : Scalar52_as_Nat b ≤ L) :
    sub a b ⦃ result =>
    Scalar52_as_Nat result + Scalar52_as_Nat b ≡ Scalar52_as_Nat a [MOD L] ∧
    Scalar52_as_Nat result < L ∧
    (∀ i < 5, result[i]!.val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
