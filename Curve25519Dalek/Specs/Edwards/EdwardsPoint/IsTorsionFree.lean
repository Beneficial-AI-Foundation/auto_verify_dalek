




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.Mul
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.Identity
import Curve25519Dalek.Specs.Edwards.EdwardsPoint.CtEq
import Curve25519Dalek.Specs.Edwards.CompressedEdwardsY.Identity
import Curve25519Dalek.Specs.Constants.BASEPOINT_ORDER_PRIVATE











open Aeneas Aeneas.Std Result Aeneas.Std.WP Edwards
open curve25519_dalek.backend.serial.u64.field.FieldElement51
namespace curve25519_dalek.edwards.EdwardsPoint


















private lemma field51_limb_le_of_sum_eq_zero {f : backend.serial.u64.field.FieldElement51}
    (h : Field51_as_Nat f = 0) : ∀ i < 5, (↑f)[i]!.val ≤ 2 ^ 53 := by
  simp only [Field51_as_Nat, Array.getElem!_Nat_eq, List.getElem!_eq_getElem?_getD,
    Finset.sum_range_succ, Finset.range_one, Finset.sum_singleton] at h
  intro i hi; interval_cases i <;> simp_all

private lemma field51_limb_le_of_sum_eq_one {f : backend.serial.u64.field.FieldElement51}
    (h : Field51_as_Nat f = 1) : ∀ i < 5, (↑f)[i]!.val ≤ 2 ^ 53 := by
  simp only [Field51_as_Nat, Array.getElem!_Nat_eq, List.getElem!_eq_getElem?_getD,
    Finset.sum_range_succ, Finset.range_one, Finset.sum_singleton] at h
  intro i hi; interval_cases i <;> simp_all <;> omega





@[progress, externally_verified]
theorem is_torsion_free_spec (self : EdwardsPoint) (hself : self.IsValid) :
    is_torsion_free self ⦃ result =>
    (result ↔ L • self.toPoint = 0) ⦄ := by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
