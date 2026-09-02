




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.L









attribute [-simp] Int.reducePow Nat.reducePow
set_option exponentiation.threshold 260











































































namespace curve25519_dalek
open Aeneas Aeneas.Std Aeneas.Std.WP Result





attribute [-progress] U64.Insts.SubtleConditionallySelectable.conditional_select_spec

@[progress]
theorem U64.Insts.SubtleConditionallySelectable.conditional_select_spec' (a b : U64) (choice : subtle.Choice) :
    U64.Insts.SubtleConditionallySelectable.conditional_select a b choice ⦃ (res : U64) =>
      (choice = Choice.one → res = b) ∧
      (choice = Choice.zero → res = a) ⦄ := by
  sorry
end curve25519_dalek

open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

@[progress]
theorem conditional_add_l_loop_spec (self : Scalar52) (condition : subtle.Choice)
    (carry : U64) (mask : U64) (i : Usize) (hself : ∀ j < 5, self[j]!.val < 2 ^ 52)
    (hmask : mask.val = 2 ^ 52 - 1) (hi : i.val ≤ 5) (hcarry : carry.val < 2 ^ 53) :
    conditional_add_l_loop self condition carry mask i ⦃ (result : U64 × Scalar52) =>
      (∀ j < 5, result.2[j]!.val < 2 ^ 52) ∧
      (Scalar52_as_Nat result.2 + 2 ^ 260 * (result.1.val / 2 ^ 52) =
        Scalar52_as_Nat self + (if condition = Choice.one then Scalar52_as_Nat constants.L else 0) +
        2 ^ (52 * i.val) * (carry.val / 2 ^ 52) -
        (if condition = Choice.one then ∑ j ∈ Finset.Ico 0 i.val, 2 ^ (52 * j) * constants.L[j]!.val
          else 0)) ⦄ := by
  sorry






@[progress]
theorem conditional_add_l_spec (self : Scalar52) (condition : subtle.Choice)
    (hself : ∀ i < 5, self[i]!.val < 2 ^ 52)
    (hself' : condition = Choice.one → 2 ^ 260 ≤ Scalar52_as_Nat self + L)
    (hself'' : condition = Choice.one → Scalar52_as_Nat self < 2 ^ 260)
    (hself''' : condition = Choice.zero → Scalar52_as_Nat self < L) :
    conditional_add_l self condition ⦃ (result : U64 × Scalar52) =>
      (∀ i < 5, result.2[i]!.val < 2 ^ 52) ∧
      (Scalar52_as_Nat result.2 < L) ∧
      (condition = Choice.one → Scalar52_as_Nat result.2 + 2 ^ 260 = Scalar52_as_Nat self + L) ∧
      (condition = Choice.zero → Scalar52_as_Nat result.2 = Scalar52_as_Nat self) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
