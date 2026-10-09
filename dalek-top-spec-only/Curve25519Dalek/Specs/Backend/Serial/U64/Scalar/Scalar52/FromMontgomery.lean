import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Index
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- `from_montgomery_loop self limbs i` copies (widened to `u128`) the limbs `i..4` of `self`
into `limbs`, leaving every other entry unchanged. -/
@[progress]
theorem from_montgomery_loop_spec (self : Scalar52) (limbs : Array U128 9#usize) (i : Usize)
    (hi : i.val ≤ 5) :
    from_montgomery_loop self limbs i ⦃ r =>
      ∀ j, j < 9 → (r.val[j]!).val =
        if i.val ≤ j ∧ j < 5 then (self.val[j]!).val else (limbs.val[j]!).val ⦄ := by
  unfold from_montgomery_loop
  split
  · have hilt : i.val < 5 := by scalar_tac
    progress as ⟨x, hx, hx'⟩
    progress as ⟨y, hy⟩
    progress as ⟨a, ha⟩
    progress as ⟨i3, hi3⟩
    progress as ⟨r, hr⟩
    rename_i j hj
    rw [hr j hj, ha]
    by_cases hji : j = i.val
    · subst hji
      have : (limbs.set i y).val[i.val]! = y := by
        simp only [Array.set_val_eq]; exact List.getElem!_set _ _ _ (by simp; omega)
      rw [this, if_neg (by omega), if_pos ⟨le_refl _, hilt⟩, hy, ← hx']
      simp
    · have : (limbs.set i y).val[j]! = limbs.val[j]! := by
        simp only [Array.set_val_eq]; simp_lists
      rw [this]
      by_cases h1 : i3.val ≤ j ∧ j < 5
      · rw [if_pos h1, if_pos (by omega)]
      · rw [if_neg h1, if_neg (by omega)]
  · rw [spec_ok]
    intro j hj
    rw [if_neg (by scalar_tac)]
termination_by 5 - i.val
decreasing_by
  all_goals scalar_tac

/-- Starting from the all-zero array at index `0`, `from_montgomery_loop` produces a
9-limb array with the same value as `self`, whose limbs are below `2^64`. -/
theorem from_montgomery_loop_zero_spec (self : Scalar52) :
    from_montgomery_loop self (Array.repeat 9#usize 0#u128) 0#usize ⦃ r =>
      (∀ j, j < 9 → (r.val[j]!).val < 2 ^ 64) ∧
      (∀ j, j < 9 → (r.val[j]!).val = if j < 5 then (self.val[j]!).val else 0) ∧
      U128x9_as_Nat r = Scalar52_as_Nat self ⦄ := by
  apply spec_mono (from_montgomery_loop_spec self _ 0#usize (by simp))
  intro r hr
  have hz : ∀ j, j < 9 → ((Array.repeat 9#usize 0#u128).val[j]!).val = 0 := by
    intro j hj
    interval_cases j <;> first | rfl | decide | simp [Array.repeat, List.replicate]
  have hr' : ∀ j, j < 9 → (r.val[j]!).val = if j < 5 then (self.val[j]!).val else 0 := by
    intro j hj
    rw [hr j hj, hz j hj]
    simp
  refine ⟨?_, hr', ?_⟩
  · intro j hj
    rw [hr' j hj]
    split
    · exact (self.val[j]!).hBounds
    · norm_num
  · rw [U128x9_as_Nat_expand]
    unfold Scalar52_as_Nat
    simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq]
    rw [hr' 0 (by omega), hr' 1 (by omega), hr' 2 (by omega), hr' 3 (by omega),
      hr' 4 (by omega), hr' 5 (by omega), hr' 6 (by omega), hr' 7 (by omega),
      hr' 8 (by omega)]
    simp

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Any `Scalar52` (with arbitrary `u64` limbs) has value below `2 ^ 273`. -/
theorem from_montgomery_as_Nat_lt (a : Scalar52) : Scalar52_as_Nat a < 2 ^ 273 := by
  have h0 := (a.val[0]!).hBounds
  have h1 := (a.val[1]!).hBounds
  have h2 := (a.val[2]!).hBounds
  have h3 := (a.val[3]!).hBounds
  have h4 := (a.val[4]!).hBounds
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq]
  norm_num at h0 h1 h2 h3 h4 ⊢
  omega

/-- `from_montgomery self` computes `self * R⁻¹ mod L` (with `R = 2 ^ 260`), returning a
canonical (`< L`) scalar with 52-bit limbs. -/
@[progress]
theorem from_montgomery_spec (self : Scalar52) :
    from_montgomery self ⦃ r =>
      (∀ i, i < 5 → (r.val[i]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r * 2 ^ 260 ≡ Scalar52_as_Nat self [MOD _root_.L] ∧
      Scalar52_as_Nat r < _root_.L ⦄ := by
  unfold from_montgomery
  apply spec_bind (from_montgomery_loop_zero_spec self)
  rintro limbs ⟨hb, -, hv⟩
  have hb' : ∀ i, i < 9 → (limbs.val[i]!).val < 2 ^ 126 := fun i hi =>
    lt_of_lt_of_le (hb i hi) (by norm_num)
  have hT : U128x9_as_Nat limbs < 2 ^ 260 * _root_.L := by
    rw [hv]
    have := from_montgomery_as_Nat_lt self
    have hL : 2 ^ 13 ≤ _root_.L := by unfold _root_.L; norm_num
    calc Scalar52_as_Nat self < 2 ^ 273 := this
      _ = 2 ^ 260 * 2 ^ 13 := by rw [← pow_add]
      _ ≤ 2 ^ 260 * _root_.L := Nat.mul_le_mul_left _ hL
  apply spec_mono (montgomery_reduce_spec limbs hb' hT)
  rintro r ⟨h1, h2, h3⟩
  exact ⟨h1, hv ▸ h2, h3⟩

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
