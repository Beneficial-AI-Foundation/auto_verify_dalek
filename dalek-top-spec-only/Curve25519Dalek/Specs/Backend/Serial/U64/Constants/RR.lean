import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.constants

/-- The underlying list of limbs of `RR`. -/
theorem RR_val : RR.val = [2764609938444603#u64, 3768881411696287#u64, 1616719297148420#u64,
    1087343033131391#u64, 10175238647962#u64] := by
  unfold RR
  rfl

/-- The limbs of `RR` as natural numbers. -/
theorem RR_limbs :
    RR[0]!.val = 2764609938444603 ∧ RR[1]!.val = 3768881411696287 ∧
    RR[2]!.val = 1616719297148420 ∧ RR[3]!.val = 1087343033131391 ∧
    RR[4]!.val = 10175238647962 := by
  simp only [Array.getElem!_Nat_eq, RR_val]
  decide

/-- All limbs of `RR` are bounded by `2^52`. -/
theorem RR_bounds : ∀ i < 5, RR[i]!.val < 2 ^ 52 := by
  obtain ⟨h0, h1, h2, h3, h4⟩ := RR_limbs
  intro i hi
  interval_cases i <;> simp only [h0, h1, h2, h3, h4] <;> norm_num

/-- `RR` represents the natural number `R^2 mod L` where `R = 2^260`. -/
@[simp]
theorem RR_spec : Scalar52_as_Nat RR = (2 ^ 260) ^ 2 % _root_.L := by
  obtain ⟨h0, h1, h2, h3, h4⟩ := RR_limbs
  unfold Scalar52_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, h0, h1, h2, h3, h4]
  unfold _root_.L
  rfl

/-- `RR` is congruent to `R^2` modulo `L`, with `R = 2^260`. -/
theorem RR_mod : Scalar52_as_Nat RR ≡ (2 ^ 260) ^ 2 [MOD _root_.L] := by
  rw [RR_spec]
  exact Nat.mod_modEq _ _

/-- `RR` is reduced modulo `L`. -/
theorem RR_lt_L : Scalar52_as_Nat RR < _root_.L := by
  rw [RR_spec]
  exact Nat.mod_lt _ (by unfold _root_.L; norm_num)

end curve25519_dalek.backend.serial.u64.constants
