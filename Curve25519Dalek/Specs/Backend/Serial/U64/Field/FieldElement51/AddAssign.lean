




import Curve25519Dalek.Aux
import Curve25519Dalek.Funs










open Aeneas Aeneas.Std Result Aeneas.Std.WP

set_option linter.hashCommand false
#setup_aeneas_simps



namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51




@[progress]
theorem add_assign_loop_spec (self _rhs : Array U64 5#usize) (i : Usize) (hi : i.val ≤ 5)
    (hab : ∀ j < 5, i.val ≤ j → self[j]!.val + _rhs[j]!.val ≤ U64.max) :
    add_assign_loop self _rhs i ⦃ (result : FieldElement51) =>
      (∀ j < 5, i.val ≤ j → result[j]!.val = self[j]!.val + _rhs[j]!.val) ∧
      (∀ j < 5, j < i.val → result[j]! = self[j]!) ⦄ := by
  sorry







@[progress]
theorem add_assign_spec (self _rhs : Array U64 5#usize)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 53) (hb : ∀ i < 5, _rhs[i]!.val < 2 ^ 53) :
    add_assign self _rhs ⦃ (result : FieldElement51) =>
      (∀ i < 5, (result[i]!).val = (self[i]!).val + (_rhs[i]!).val) ∧
      (∀ i < 5, result[i]!.val < 2 ^ 54) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51
