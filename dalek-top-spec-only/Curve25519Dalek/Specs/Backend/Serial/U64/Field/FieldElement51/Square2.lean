import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Pow2K

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

/-- Loop invariant spec: starting at index `i`, the loop doubles `square[j]` for every
`i ≤ j < 5`, leaving limbs `j < i` unchanged. -/
@[progress]
theorem square2_loop_spec (square : backend.serial.u64.field.FieldElement51) (i : Std.Usize)
    (hi : i.val ≤ 5)
    (hno : ∀ j < 5, i.val ≤ j → square[j]!.val * 2 ≤ U64.max) :
    square2_loop square i ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ j < 5, i.val ≤ j → result[j]!.val = 2 * square[j]!.val) ∧
      (∀ j < 5, j < i.val → result[j]! = square[j]!) ⦄ := by
  unfold square2_loop
  split
  · have hlen : i.val < 5 := by scalar_tac
    have hno_i := hno i.val hlen (le_refl _)
    simp only [Array.getElem!_Nat_eq] at hno_i
    progress as ⟨i1, hi1⟩
    progress as ⟨i2, hi2⟩
    progress as ⟨a, ha⟩
    progress as ⟨i3, hi3⟩
    have hget : ∀ j < 5, a[j]! = if j = i.val then i2 else square[j]! := by
      intro j hj
      rw [ha, Array.getElem!_Nat_eq, Array.getElem!_Nat_eq, Array.set_val_eq]
      split
      · subst_vars
        have hlen' : square.val.length = 5 := by simp
        simp_lists
      · simp_lists
    progress with square2_loop_spec as ⟨r, hr1, hr2⟩
    refine ⟨?_, ?_⟩
    · intro j hj hij
      by_cases hji : j = i.val
      · subst hji
        rw [hr2 _ hj (by scalar_tac), hget _ hj, if_pos rfl, hi2, hi1]
        simp only [Array.getElem!_Nat_eq]
        ring
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

/-- Full-loop form (starting at index 0): every limb is doubled, so the value doubles. -/
@[progress]
theorem square2_loop_zero_spec (square : backend.serial.u64.field.FieldElement51)
    (hno : ∀ j < 5, square[j]!.val < 2 ^ 63) :
    square2_loop square 0#usize ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ j < 5, result[j]!.val = 2 * square[j]!.val) ∧
      Field51_as_Nat result = 2 * Field51_as_Nat square ⦄ := by
  have hno' : ∀ j < 5, (0#usize).val ≤ j → square[j]!.val * 2 ≤ U64.max := by
    intro j hj _
    have := hno j hj
    scalar_tac
  progress with square2_loop_spec as ⟨r, hr1, _⟩
  have hpt : ∀ j < 5, r[j]!.val = 2 * square[j]!.val := fun j hj => hr1 j hj (by simp)
  refine ⟨hpt, ?_⟩
  unfold Field51_as_Nat
  rw [Finset.mul_sum]
  refine Finset.sum_congr rfl ?_
  intro j hj
  rw [hpt j (Finset.mem_range.mp hj)]
  ring

/-- `square2 self` computes `2 * self ^ 2` modulo `p`, with output limbs bounded by `2 ^ 53`. -/
@[progress]
theorem square2_spec (self : backend.serial.u64.field.FieldElement51)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 54) :
    square2 self ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val < 2 ^ 53) ∧
      Field51_as_Nat result % p = (2 * Field51_as_Nat self ^ 2) % p ⦄ := by
  unfold square2
  progress with pow2k_spec self 1#u32 (by decide) ha as ⟨sq, hsq1, hsq2⟩
  have hno : ∀ j < 5, sq[j]!.val < 2 ^ 63 := by
    intro j hj
    have := hsq1 j hj
    omega
  progress with square2_loop_zero_spec sq hno as ⟨r, hr1, hr2⟩
  refine ⟨?_, ?_⟩
  · intro i hi
    rw [hr1 i hi]
    have := hsq1 i hi
    omega
  · simp only [Nat.pow_one] at hsq2
    rw [hr2, Nat.mul_mod, hsq2, ← Nat.mul_mod]

end curve25519_dalek.backend.serial.u64.field.FieldElement51
