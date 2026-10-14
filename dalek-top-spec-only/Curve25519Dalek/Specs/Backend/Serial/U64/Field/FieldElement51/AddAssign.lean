import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51

/-- Loop invariant spec: starting at index `i`, the loop adds `_rhs[j]` to `self[j]` for every
`i ≤ j < 5`, leaving limbs `j < i` unchanged. -/
@[progress]
theorem add_assign_loop_spec (self _rhs : backend.serial.u64.field.FieldElement51) (i : Std.Usize)
    (hi : i.val ≤ 5)
    (hno : ∀ j < 5, i.val ≤ j → self[j]!.val + _rhs[j]!.val ≤ U64.max) :
    add_assign_loop self _rhs i ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ j < 5, i.val ≤ j → result[j]!.val = self[j]!.val + _rhs[j]!.val) ∧
      (∀ j < 5, j < i.val → result[j]! = self[j]!) ⦄ := by
  unfold add_assign_loop
  split
  · have hlen : i.val < 5 := by scalar_tac
    have hno_i := hno i.val hlen (le_refl _)
    simp only [Array.getElem!_Nat_eq] at hno_i
    progress as ⟨i1, hi1⟩
    progress as ⟨i2, hi2⟩
    progress as ⟨i3, hi3⟩
    progress as ⟨a, ha⟩
    progress as ⟨i4, hi4⟩
    have hget : ∀ j < 5, a[j]! = if j = i.val then i3 else self[j]! := by
      intro j hj
      rw [ha, Array.getElem!_Nat_eq, Array.getElem!_Nat_eq, Array.set_val_eq]
      split
      · subst_vars
        have hlen' : self.val.length = 5 := by simp
        simp_lists
      · simp_lists
    progress with add_assign_loop_spec as ⟨r, hr1, hr2⟩
    refine ⟨?_, ?_⟩
    · intro j hj hij
      by_cases hji : j = i.val
      · subst hji
        rw [hr2 _ hj (by scalar_tac), hget _ hj, if_pos rfl, hi3, hi1, hi2]
        simp only [Array.getElem!_Nat_eq]
      · rw [hr1 j hj (by scalar_tac), hget j hj, if_neg hji]
    · intro j hj hji
      rw [hr2 j hj (by scalar_tac), hget j hj, if_neg (by omega)]
  · refine ⟨?_, ?_⟩
    · intro j hj hij
      scalar_tac
    · intro j _ _
      rfl
termination_by 5 - i.val
decreasing_by scalar_tac

/-- Limb-wise addition lifts to addition of the `Field51_as_Nat` values. -/
theorem Field51_as_Nat_of_pointwise_add (a b c : backend.serial.u64.field.FieldElement51)
    (h : ∀ i < 5, c[i]!.val = a[i]!.val + b[i]!.val) :
    Field51_as_Nat c = Field51_as_Nat a + Field51_as_Nat b := by
  unfold Field51_as_Nat
  rw [← Finset.sum_add_distrib]
  refine Finset.sum_congr rfl ?_
  intro i hi
  rw [h i (Finset.mem_range.mp hi), mul_add]

/-- `add_assign` adds the limbs pointwise (no reduction); limbs must be small enough
not to overflow. -/
@[progress]
theorem add_assign_spec (self _rhs : backend.serial.u64.field.FieldElement51)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 63)
    (hb : ∀ i < 5, _rhs[i]!.val < 2 ^ 63) :
    add_assign self _rhs ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val = self[i]!.val + _rhs[i]!.val) ∧
      Field51_as_Nat result = Field51_as_Nat self + Field51_as_Nat _rhs ⦄ := by
  unfold add_assign
  have hno : ∀ j < 5, (0#usize).val ≤ j → self[j]!.val + _rhs[j]!.val ≤ U64.max := by
    intro j hj _
    have := ha j hj
    have := hb j hj
    scalar_tac
  progress with add_assign_loop_spec as ⟨r, hr1, _⟩
  have hpt : ∀ i < 5, r[i]!.val = self[i]!.val + _rhs[i]!.val :=
    fun i hi => hr1 i hi (by simp)
  exact ⟨hpt, Field51_as_Nat_of_pointwise_add _ _ _ hpt⟩

end curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51
