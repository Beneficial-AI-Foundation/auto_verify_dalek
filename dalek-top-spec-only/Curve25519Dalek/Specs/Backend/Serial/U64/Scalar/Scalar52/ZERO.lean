import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- The underlying list of `ZERO` is five zero limbs. -/
theorem ZERO_val : ZERO.val = List.replicate 5 0#u64 := by
  unfold ZERO
  simp [Array.repeat]

/-- Every limb of `ZERO` is zero (list indexing form). -/
theorem ZERO_val_getElem! (i : Nat) : ZERO.val[i]! = 0#u64 := by
  rw [ZERO_val]
  by_cases hi : i < 5
  · interval_cases i <;> rfl
  · rw [getElem!_neg _ _ (by simpa using hi)]; rfl

/-- Every limb of `ZERO` is zero (array indexing form). -/
@[simp]
theorem ZERO_getElem! (i : Nat) : ZERO[i]! = 0#u64 := by
  rw [Array.getElem!_Nat_eq, ZERO_val_getElem!]

/-- Every limb of `ZERO` has value `0`. -/
theorem ZERO_index_val (i : Nat) : (ZERO[i]!).val = 0 := by
  rw [ZERO_getElem!]; rfl

/-- All limbs of `ZERO` are bounded by `2^52`. -/
theorem ZERO_bounds : ∀ i < 5, ZERO[i]!.val < 2 ^ 52 := by
  intro i _; rw [ZERO_index_val]; norm_num

/-- `ZERO` represents the natural number `0`. -/
@[simp]
theorem ZERO_spec : Scalar52_as_Nat ZERO = 0 := by
  unfold Scalar52_as_Nat
  simp only [ZERO_index_val, mul_zero, Finset.sum_const_zero]

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
